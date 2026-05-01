from __future__ import annotations

from pathlib import Path
import shutil
import unittest
from unittest.mock import patch

from qr_blockchain import NodeConfig, NodeService, Wallet
from qr_blockchain.migration import (
    build_demo_classical_claim_address,
    build_demo_classical_claim_proof,
    build_demo_classical_claim_public_key,
    classical_claim_message_bytes,
)
from qr_blockchain.models import Transaction, TxOutput


class MigrationLoadAndChaosTests(unittest.TestCase):
    def make_service(self, name: str) -> NodeService:
        root = Path("test_runtime") / f"{self._testMethodName}_{name}"
        if root.exists():
            shutil.rmtree(root)
        root.mkdir(parents=True, exist_ok=True)
        self.addCleanup(lambda: shutil.rmtree(root, ignore_errors=True))
        return NodeService(
            NodeConfig(
                db_path=root / "chain.db",
                wallet_state_db_path=root / "wallet_state.db",
                difficulty=1,
                mining_reward=10,
                node_id=f"node-{name}",
                advertised_url=f"http://{name}:8080",
                migration_dual_control_start_height=0,
                migration_dual_control_end_height=0,
            )
        )

    @staticmethod
    def _build_demo_claim(
        service: NodeService,
        wallet: Wallet,
        *,
        seed: str,
        amount: int,
        source_network: str,
        snapshot_ref: str,
    ) -> tuple[str, Transaction]:
        classical_public_key = build_demo_classical_claim_public_key(seed)
        classical_address = build_demo_classical_claim_address(classical_public_key)
        service.seed_migration_source(
            classical_address=classical_address,
            provider_id="classical_claim_demo_v1",
            source_network=source_network,
            amount=amount,
            snapshot_ref=snapshot_ref,
        )
        preview = service.build_migration_claim_draft(
            destination_address=wallet.create_address(),
            classical_address=classical_address,
            classical_provider_id="classical_claim_demo_v1",
            source_network=source_network,
            snapshot_ref=snapshot_ref,
            classical_public_key=classical_public_key,
        )
        signature = build_demo_classical_claim_proof(
            classical_public_key,
            classical_claim_message_bytes(preview.migration_claim_payload()),
        )
        claim = wallet.create_migration_claim(
            service,
            classical_address=classical_address,
            classical_provider_id="classical_claim_demo_v1",
            classical_public_key=classical_public_key,
            classical_signature=signature,
            source_network=source_network,
            snapshot_ref=snapshot_ref,
            destination_address=preview.outputs[0].recipient,
            timestamp=preview.timestamp,
        )
        return classical_address, claim

    def test_bulk_migration_claims_roundtrip_through_blocks(self) -> None:
        service = self.make_service("source")
        wallet = Wallet("PQWallet")
        miner = Wallet("Miner")

        service.create_genesis_block({miner.create_address(): 10})
        destinations: list[str] = []
        for index in range(12):
            _, claim = self._build_demo_claim(
                service,
                wallet,
                seed=f"bulk-user-{index}",
                amount=5 + index,
                source_network="legacy-bulk-ledger",
                snapshot_ref="bulk-snapshot",
            )
            destinations.append(claim.outputs[0].recipient)
            service.submit_transaction(claim)

        service.mine_pending_transactions(miner.create_address())

        for index, destination in enumerate(destinations):
            self.assertEqual(service.balance_for_address(destination), 5 + index)
        self.assertEqual(len([item for item in service.list_migration_sources() if item["claimed"]]), 12)

    def test_bulk_migration_claims_sync_to_peer(self) -> None:
        source = self.make_service("source")
        target = self.make_service("target")
        wallet = Wallet("PQWallet")
        miner = Wallet("Miner")

        genesis_address = miner.create_address()
        source.create_genesis_block({genesis_address: 10})
        target.create_genesis_block({genesis_address: 10})
        for index in range(8):
            classical_address, claim = self._build_demo_claim(
                source,
                wallet,
                seed=f"sync-user-{index}",
                amount=20,
                source_network="legacy-sync-ledger",
                snapshot_ref="sync-snapshot",
            )
            target.seed_migration_source(
                classical_address=classical_address,
                provider_id="classical_claim_demo_v1",
                source_network="legacy-sync-ledger",
                amount=20,
                snapshot_ref="sync-snapshot",
            )
            source.submit_transaction(claim)
        source.mine_pending_transactions(miner.create_address())

        def fake_fetch_json(url: str, *, method: str = "GET", payload: dict[str, object] | None = None, timeout: float = 10.0) -> dict[str, object]:
            if url.endswith("/peer/handshake"):
                return source.accept_peer_handshake(payload["auth"])
            if url.endswith("/peer/summary"):
                return source.authenticated_chain_summary(payload["auth"])
            if url.endswith("/peer/blocks"):
                frame_payload = payload["payload"]
                return source.authenticated_blocks(payload["auth"], int(frame_payload["start_height"]))
            raise AssertionError(f"Unexpected URL {url}")

        with patch("qr_blockchain.service.fetch_json", side_effect=fake_fetch_json):
            imported = target.sync_with_peer(source.config.advertised_url)

        self.assertEqual(imported, 1)
        self.assertEqual(len([item for item in target.list_migration_sources() if item["claimed"]]), 8)

    def test_reorg_switches_canonical_migration_claims(self) -> None:
        branch_a = self.make_service("branch_a")
        branch_b = self.make_service("branch_b")
        target = self.make_service("target")
        wallet_a = Wallet("WalletA")
        wallet_b = Wallet("WalletB")
        miner = Wallet("Miner")

        genesis_address = miner.create_address()
        branch_a.create_genesis_block({genesis_address: 10})
        branch_b.create_genesis_block({genesis_address: 10})
        target.create_genesis_block({genesis_address: 10})

        classical_public_key = build_demo_classical_claim_public_key("reorg-user")
        classical_address = build_demo_classical_claim_address(classical_public_key)
        for service in (branch_a, branch_b, target):
            service.seed_migration_source(
                classical_address=classical_address,
                provider_id="classical_claim_demo_v1",
                source_network="legacy-reorg-ledger",
                amount=30,
                snapshot_ref="reorg-snapshot",
            )

        preview_a = branch_a.build_migration_claim_draft(
            destination_address=wallet_a.create_address(),
            classical_address=classical_address,
            classical_provider_id="classical_claim_demo_v1",
            source_network="legacy-reorg-ledger",
            snapshot_ref="reorg-snapshot",
            classical_public_key=classical_public_key,
        )
        signature_a = build_demo_classical_claim_proof(
            classical_public_key,
            classical_claim_message_bytes(preview_a.migration_claim_payload()),
        )
        claim_a = wallet_a.create_migration_claim(
            branch_a,
            classical_address=classical_address,
            classical_provider_id="classical_claim_demo_v1",
            classical_public_key=classical_public_key,
            classical_signature=signature_a,
            source_network="legacy-reorg-ledger",
            snapshot_ref="reorg-snapshot",
            destination_address=preview_a.outputs[0].recipient,
            timestamp=preview_a.timestamp,
        )
        branch_a.submit_transaction(claim_a)
        block_a = branch_a.mine_pending_transactions(miner.create_address())

        preview_b = branch_b.build_migration_claim_draft(
            destination_address=wallet_b.create_address(),
            classical_address=classical_address,
            classical_provider_id="classical_claim_demo_v1",
            source_network="legacy-reorg-ledger",
            snapshot_ref="reorg-snapshot",
            classical_public_key=classical_public_key,
        )
        signature_b = build_demo_classical_claim_proof(
            classical_public_key,
            classical_claim_message_bytes(preview_b.migration_claim_payload()),
        )
        claim_b = wallet_b.create_migration_claim(
            branch_b,
            classical_address=classical_address,
            classical_provider_id="classical_claim_demo_v1",
            classical_public_key=classical_public_key,
            classical_signature=signature_b,
            source_network="legacy-reorg-ledger",
            snapshot_ref="reorg-snapshot",
            destination_address=preview_b.outputs[0].recipient,
            timestamp=preview_b.timestamp,
        )
        branch_b.submit_transaction(claim_b)
        block_b1 = branch_b.mine_pending_transactions(miner.create_address())
        block_b2 = branch_b.mine_pending_transactions(miner.create_address())

        target.import_block(block_a)
        self.assertEqual(target.store.migration_claim(classical_address)["destination_address"], preview_a.outputs[0].recipient)

        target.import_block(block_b1)
        target.import_block(block_b2)
        self.assertEqual(target.store.migration_claim(classical_address)["destination_address"], preview_b.outputs[0].recipient)


if __name__ == "__main__":
    unittest.main()
