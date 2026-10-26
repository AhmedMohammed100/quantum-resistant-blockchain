"""Adversarial v2 handshake downgrade and mixed-version isolation tests."""

import copy
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from qr_blockchain.portable_encoding import canonical_json_v1, hash_canonical_v1
from qr_blockchain.protocol_v2 import V2SchemaError
from tests.test_protocol_v2_node_consensus import (
    HTTPPeer, PeerServer, block_after, build_network, create_node,
)


class ScriptedHTTPPeer:
    """Loopback peer that exposes an attacker-selected handshake and block list."""

    def __init__(self, handshake, blocks):
        self.handshake_payload = handshake
        self.blocks_payload = blocks
        self.block_requests = 0
        self.handshake_requests = 0
        peer = self

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                if self.path == "/handshake":
                    peer.handshake_requests += 1
                    payload = peer.handshake_payload
                elif self.path == "/blocks":
                    peer.block_requests += 1
                    payload = peer.blocks_payload
                else:
                    self.send_error(404)
                    return
                encoded = canonical_json_v1(payload)
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(encoded)))
                self.end_headers()
                self.wfile.write(encoded)

            def log_message(self, *_):
                pass

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.base_url = f"http://127.0.0.1:{self.server.server_port}"
        self.peer = HTTPPeer(self.base_url)

    def handshake(self):
        return self.peer.handshake()

    def canonical_blocks(self):
        return self.peer.canonical_blocks()

    def close(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)


class ProtocolV2DowngradeIsolationTests(unittest.TestCase):
    def test_mixed_versions_and_handshake_mutations_are_rejected_before_block_fetch(self):
        manifest, genesis = build_network()
        expected = {
            "protocol_version": 2,
            "chain_id": manifest["chain_id"],
            "manifest_digest": manifest["manifest_digest"],
            "genesis_hash": manifest["genesis_hash"],
        }
        variants = [
            ("legacy v0.1", {"protocol_version": 1}),
            ("unversioned peer", {key: value for key, value in expected.items() if key != "protocol_version"}),
            ("boolean protocol version", {**expected, "protocol_version": True}),
            ("future protocol version", {**expected, "protocol_version": 3}),
            ("wrong chain ID", {**expected, "chain_id": "qbc-v2-foreign"}),
            ("wrong manifest digest", {**expected, "manifest_digest": "f" * 64}),
            ("wrong genesis hash", {**expected, "genesis_hash": "e" * 64}),
            ("unknown handshake field", {**expected, "legacy_fallback": True}),
        ]

        with tempfile.TemporaryDirectory(prefix="qbc-v2-downgrade-") as directory:
            database = Path(directory) / "node.sqlite3"
            node = create_node(manifest, genesis, database)
            original_tip = node.tip_hash
            original_state = node.canonical_state()
            original_blocks = node.canonical_blocks()

            for label, handshake in variants:
                with self.subTest(peer=label):
                    attacker = ScriptedHTTPPeer(handshake, [genesis])
                    try:
                        with self.assertRaisesRegex(V2SchemaError, "handshake"):
                            node.sync_from(attacker)
                        self.assertEqual(attacker.handshake_requests, 1)
                        self.assertEqual(attacker.block_requests, 0)
                    finally:
                        attacker.close()
                    self.assertEqual(node.tip_hash, original_tip)
                    self.assertEqual(node.canonical_state(), original_state)
                    self.assertEqual(node.canonical_blocks(), original_blocks)

            restarted = create_node(manifest, genesis, database)
            self.assertEqual(restarted.tip_hash, original_tip)
            self.assertEqual(restarted.canonical_state(), original_state)
            self.assertEqual(restarted.canonical_blocks(), original_blocks)

            source = create_node(manifest, genesis)
            source.accept_block(block_after(source, genesis))
            server = PeerServer(source)
            try:
                restarted.sync_from(HTTPPeer(server.base_url))
            finally:
                server.close()
            self.assertEqual(restarted.tip_hash, source.tip_hash)
            self.assertEqual(restarted.canonical_state(), source.canonical_state())

    def test_matching_handshake_cannot_smuggle_a_different_genesis(self):
        manifest, genesis = build_network()
        wrong_genesis = copy.deepcopy(genesis)
        wrong_genesis["timestamp_us"] += 1
        preimage = {key: value for key, value in wrong_genesis.items() if key != "block_hash"}
        wrong_genesis["block_hash"] = hash_canonical_v1("block-v2", preimage)

        node = create_node(manifest, genesis)
        before = (node.tip_hash, node.canonical_state(), node.canonical_blocks())
        peer = ScriptedHTTPPeer(node.handshake(), [wrong_genesis])
        try:
            with self.assertRaisesRegex(V2SchemaError, "different genesis"):
                node.sync_from(peer)
            self.assertEqual(peer.handshake_requests, 1)
            self.assertEqual(peer.block_requests, 1)
        finally:
            peer.close()
        self.assertEqual((node.tip_hash, node.canonical_state(), node.canonical_blocks()), before)


if __name__ == "__main__":
    unittest.main()
