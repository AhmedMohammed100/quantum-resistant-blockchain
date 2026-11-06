"""End-to-end authenticated peer sync over the node's HTTP API."""

import os
import shutil
import threading
from dataclasses import replace
from unittest.mock import patch
from pathlib import Path

from qr_blockchain.api import BoundedThreadingHTTPServer, NodeRequestHandler
from qr_blockchain.service import NodeService
from tests.node_service_test_support import NodeServiceTestSupport


class AuthenticatedPeerLoopbackSyncTests(NodeServiceTestSupport):
    def _start_node(self, root: Path, name: str, *, chain_id: str = "qr-chain-devnet"):
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
        config = replace(config, default_signature_provider="native_test_pq_v1")
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

    def test_http_peer_sync_rejects_a_different_chain_id(self) -> None:
        root = self._new_root()
        source, source_url = self._start_node(root, "foreign", chain_id="qbc-unrelated-chain")
        target, _ = self._start_node(root, "local", chain_id="qr-chain-devnet")
        source.create_genesis_block({"foreign-bootstrap": 1})
        target.create_genesis_block({"local-bootstrap": 1})

        with self.assertRaises(ValueError):
            target.sync_with_peer(source_url)

        self.assertEqual(target.chain_summary()["height"], 1)
        self.assertNotIn(source_url, target.list_peers())


if __name__ == "__main__":
    import unittest

    unittest.main()
