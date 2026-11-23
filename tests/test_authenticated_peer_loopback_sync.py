"""End-to-end authenticated peer sync over the node's HTTP API."""

import json
import os
import shutil
import threading
from dataclasses import replace
from unittest.mock import patch
from pathlib import Path
from urllib.error import HTTPError

from qr_blockchain.api import BoundedThreadingHTTPServer, NodeRequestHandler
from qr_blockchain.service import NodeService
from qr_blockchain.migration_consensus import PROFILE_SCHEMA, PROFILE_VERSION, migration_consensus_profile_hash
from qr_blockchain.snapshot import MigrationSnapshotBundle, MigrationSnapshotEntry
from tests.node_service_test_support import NodeServiceTestSupport


class AuthenticatedPeerLoopbackSyncTests(NodeServiceTestSupport):
    def _profile(self, *, amount: int = 500) -> dict[str, object]:
        bundle = MigrationSnapshotBundle(
            source_network="legacy-a",
            snapshot_ref="snapshot-a",
            generated_at=100.0,
            entries=(
                MigrationSnapshotEntry(
                    classical_address="source-a",
                    provider_id="provider-a",
                    amount=amount,
                    source_address="source-a",
                    source_address_format="hex",
                ),
            ),
        ).to_dict()
        return {
            "profile_schema": PROFILE_SCHEMA,
            "profile_version": PROFILE_VERSION,
            "chain_id": "qr-chain-devnet",
            "activation_height": 1,
            "policy": {
                "allowed_classical_providers": ["provider-a"],
                "allowed_signature_providers": ["native_test_pq_v1"],
                "claim_start_height": 1,
                "claim_end_height": 1000,
                "conversion_denominator": 2,
                "conversion_numerator": 1,
                "conversion_policy": "ratio",
                "dispute_window_blocks": 20,
                "dual_control_start_height": 0,
                "dual_control_end_height": 0,
                "epoch_length_blocks": 100,
                "epoch_mint_cap": 5000,
                "escrow_blocks": 30,
                "migration_pool_cap": 100000,
                "per_address_cap": 2000,
            },
            "snapshots": [{
                **bundle,
                "status": "active",
                "status_reason": "",
                "reviewed_at": 0.0,
            }],
        }

    def _profiled_config(self, config, profile: dict[str, object], profile_path: Path):
        profile_path.write_text(json.dumps(profile), encoding="utf-8")
        return replace(
            config,
            default_signature_provider="native_test_pq_v1",
            preferred_signature_providers=("native_test_pq_v1",),
            allowed_signature_providers=("native_test_pq_v1",),
            migration_allowed_classical_providers=("provider-a",),
            migration_claim_start_height=1,
            migration_claim_end_height=1000,
            migration_conversion_policy="ratio",
            migration_conversion_ratio_numerator=1,
            migration_conversion_ratio_denominator=2,
            migration_dispute_window_blocks=20,
            migration_dual_control_start_height=0,
            migration_dual_control_end_height=0,
            migration_epoch_length_blocks=100,
            migration_epoch_mint_cap=5000,
            migration_escrow_blocks=30,
            migration_pool_cap=100000,
            migration_claim_per_address_cap=2000,
            migration_consensus_profile_path=profile_path,
            migration_consensus_profile_hash=migration_consensus_profile_hash(profile),
        )

    def _start_node(self, root: Path, name: str, *, chain_id: str = "qr-chain-devnet", profile: dict[str, object] | None = None):
        server = BoundedThreadingHTTPServer(("127.0.0.1", 0), NodeRequestHandler)
        url = f"http://127.0.0.1:{server.server_port}"
        node_root = root / name
        node_root.mkdir(parents=True)
        config = self.make_config(
            node_root / "chain.db",
            chain_id=chain_id,
            node_id=f"loopback-{name}",
            advertised_url=url,
        )
        if profile is None:
            config = replace(config, default_signature_provider="native_test_pq_v1")
        else:
            config = self._profiled_config(config, profile, node_root / "migration-profile.json")
        service = NodeService(config)
        handler = type(f"Handler_{name}", (NodeRequestHandler,), {"service": service})
        server.RequestHandlerClass = handler

        thread = threading.Thread(target=server.serve_forever, name=f"qbc-http-{name}", daemon=True)
        self.addCleanup(thread.join, 5)
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        thread.start()
        return service, url

    def _new_root(self) -> Path:
        native_test_mode = patch.dict(os.environ, {"QR_CHAIN_NATIVE_SIGNER_MODE": "deterministic-test"})
        native_test_mode.start()
        self.addCleanup(native_test_mode.stop)
        root = Path("test_runtime") / self._testMethodName
        if root.exists():
            shutil.rmtree(root)
        root.mkdir(parents=True)
        self.addCleanup(lambda: shutil.rmtree(root, ignore_errors=True))
        return root

    def test_authenticated_http_sync_converges_over_ten_blocks(self) -> None:
        root = self._new_root()
        source, source_url = self._start_node(root, "source")
        target, _ = self._start_node(root, "target")
        allocations = {"shared-bootstrap": 1_000}

        source.create_genesis_block(allocations)
        target.create_genesis_block(allocations)
        self.assertEqual(source.chain_summary()["best_head_hash"], target.chain_summary()["best_head_hash"])

        for height in range(1, 11):
            source.mine_pending_transactions("loopback-miner")

            imported = target.sync_with_peer(source_url)

            self.assertEqual(imported, 1)
            self.assertEqual(target.chain_summary()["height"], height + 1)
            self.assertEqual(target.chain_summary()["best_head_hash"], source.chain_summary()["best_head_hash"])
            source_block = source.get_block(height)
            target_block = target.get_block(height)
            self.assertIsNotNone(source_block)
            self.assertIsNotNone(target_block)
            self.assertEqual(target_block.block_hash, source_block.block_hash)
            self.assertEqual(target_block.state_root, source_block.state_root)
            self.assertEqual(target.balance_for_address("loopback-miner"), source.balance_for_address("loopback-miner"))

    def test_profiled_loopback_nodes_sync_only_with_matching_profile_digest(self) -> None:
        root = self._new_root()
        profile = self._profile()
        source, source_url = self._start_node(root, "profile-source", profile=profile)
        target, _ = self._start_node(root, "profile-target", profile=profile)
        allocations = {"shared-bootstrap": 1_000}
        source.create_genesis_block(allocations)
        target.create_genesis_block(allocations)
        self.assertEqual(
            source.protocol_manifest()["migration"]["consensus_profile"]["hash"],
            target.protocol_manifest()["migration"]["consensus_profile"]["hash"],
        )

        source.mine_pending_transactions("loopback-miner")
        imported = target.sync_with_peer(source_url)
        self.assertEqual(imported, 1)
        self.assertEqual(target.chain_summary()["best_head_hash"], source.chain_summary()["best_head_hash"])
        self.assertEqual(target.get_block(1).state_root, source.get_block(1).state_root)

    def test_profiled_loopback_nodes_reject_a_mismatched_profile_before_import(self) -> None:
        root = self._new_root()
        source, source_url = self._start_node(root, "profile-source", profile=self._profile(amount=500))
        target, _ = self._start_node(root, "profile-target", profile=self._profile(amount=501))
        allocations = {"shared-bootstrap": 1_000}
        source.create_genesis_block(allocations)
        target.create_genesis_block(allocations)
        self.assertNotEqual(
            source.protocol_manifest()["migration"]["consensus_profile"]["hash"],
            target.protocol_manifest()["migration"]["consensus_profile"]["hash"],
        )
        source.mine_pending_transactions("loopback-miner")

        with self.assertRaises(HTTPError) as raised:
            target.sync_with_peer(source_url)

        self.assertEqual(raised.exception.code, 400)
        self.assertEqual(target.chain_summary()["height"], 1)
        self.assertNotIn(source_url, target.list_peers())

    def test_http_peer_sync_rejects_a_different_chain_id(self) -> None:
        root = self._new_root()
        source, source_url = self._start_node(root, "foreign", chain_id="qbc-unrelated-chain")
        target, _ = self._start_node(root, "local", chain_id="qr-chain-devnet")
        source.create_genesis_block({"foreign-bootstrap": 1})
        target.create_genesis_block({"local-bootstrap": 1})

        with self.assertRaises(HTTPError) as raised:
            target.sync_with_peer(source_url)

        self.assertEqual(raised.exception.code, 400)
        self.assertEqual(target.chain_summary()["height"], 1)
        self.assertNotIn(source_url, target.list_peers())


if __name__ == "__main__":
    import unittest

    unittest.main()
