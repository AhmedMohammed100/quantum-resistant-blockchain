"""Exercise the same v2 chain and reject cases in Python and independent Go."""

import copy
import shutil
import subprocess
import unittest
from pathlib import Path

from qr_blockchain.portable_encoding import canonical_json_v1, hash_canonical_v1
from qr_blockchain.protocol_v2 import V2SchemaError, parse_canonical_v2, validate_state_utxos_v2
from qr_blockchain.protocol_v2_manifest import v2_network_manifest_digest
from tests.test_protocol_v2_node_consensus import (
    DIFFICULTY_BITS, block_after, build_network, create_node, is_address,
    signed_transfer,
)


REPO = Path(__file__).resolve().parents[1]
GO_DIR = REPO / "conformance" / "go"


@unittest.skipUnless(shutil.which("go"), "Go is required for cross-runtime consensus checks")
class ProtocolV2CrossRuntimeConsensusTests(unittest.TestCase):
    def run_go(self, manifest, genesis, blocks):
        envelope = {"manifest": manifest, "genesis_block": genesis, "blocks": blocks}
        result = subprocess.run(
            ["go", "run", "./cmd/consensuscheck"], cwd=GO_DIR,
            input=canonical_json_v1(envelope), capture_output=True, check=False,
        )
        if result.returncode:
            return False, result.stderr.decode("utf-8", "replace")
        return True, parse_canonical_v2(result.stdout.strip(), maximum=1 << 20)

    def test_both_runtimes_accept_same_signed_chain_state_and_work(self):
        manifest, genesis = build_network()
        python_node = create_node(manifest, genesis)
        coin = python_node.canonical_state()[0]
        tx = signed_transfer(prev_tx_id=coin["tx_id"], amount=990, fee=10)
        block = block_after(python_node, genesis, [tx])
        python_node.accept_block(block)

        ok, result = self.run_go(manifest, genesis, [block])
        self.assertTrue(ok, result)
        state = python_node.canonical_state()
        state_root = validate_state_utxos_v2(state, address_validator=is_address)
        self.assertEqual(result["tip_hash"], python_node.tip_hash)
        self.assertEqual(result["work"], str(1 << DIFFICULTY_BITS))
        self.assertEqual(result["state_root"], state_root)
        self.assertEqual(result["utxos"], state)

    def test_both_runtimes_match_fork_tie_break_and_reorganization(self):
        manifest, genesis = build_network()
        python_node = create_node(manifest, genesis)
        peer_node = create_node(manifest, genesis)
        coin = python_node.canonical_state()[0]
        tx = signed_transfer(prev_tx_id=coin["tx_id"], amount=990, fee=10)
        branch_a = block_after(python_node, genesis, [tx])
        python_node.accept_block(branch_a)
        branch_b = block_after(peer_node, genesis, require_hash_less_than=branch_a["block_hash"])
        python_node.accept_block(branch_b)
        branch_b2 = block_after(python_node, branch_b, timestamp_delta=1)
        python_node.accept_block(branch_b2)

        ok, result = self.run_go(manifest, genesis, [branch_a, branch_b, branch_b2])
        self.assertTrue(ok, result)
        state = python_node.canonical_state()
        self.assertEqual(result["tip_hash"], python_node.tip_hash)
        self.assertEqual(result["work"], str(2 << DIFFICULTY_BITS))
        self.assertEqual(result["state_root"], validate_state_utxos_v2(state, address_validator=is_address))
        self.assertEqual(result["utxos"], state)

    def test_both_runtimes_reject_invalid_signature_and_state_root(self):
        manifest, genesis = build_network()
        node = create_node(manifest, genesis)
        coin = node.canonical_state()[0]
        tx = signed_transfer(prev_tx_id=coin["tx_id"], amount=990, fee=10)
        block = block_after(node, genesis, [tx])
        invalid_signature = copy.deepcopy(block)
        invalid_signature["transactions"][0]["inputs"][0]["signature"] = "00" * 32
        with self.assertRaises(V2SchemaError):
            node.accept_block(invalid_signature)
        ok, reason = self.run_go(manifest, genesis, [invalid_signature])
        self.assertFalse(ok)
        self.assertIn("signature", reason)

        invalid_root = copy.deepcopy(block)
        invalid_root["state_root"] = "f" * 64
        with self.assertRaisesRegex(V2SchemaError, "state_root"):
            node.accept_block(invalid_root)
        ok, reason = self.run_go(manifest, genesis, [invalid_root])
        self.assertFalse(ok)
        self.assertIn("state_root", reason)

    def test_both_runtimes_enforce_manifest_transaction_size_limit(self):
        manifest, genesis = build_network()
        manifest["limits"]["max_transaction_bytes"] = 128
        manifest["limits"]["max_metadata_bytes"] = 128
        manifest["manifest_digest"] = v2_network_manifest_digest(manifest)
        node = create_node(manifest, genesis)
        coin = node.canonical_state()[0]
        tx = signed_transfer(prev_tx_id=coin["tx_id"], amount=990, fee=10)
        block = block_after(node, genesis, [tx])
        with self.assertRaisesRegex(V2SchemaError, "128 canonical bytes"):
            node.accept_block(block)
        ok, reason = self.run_go(manifest, genesis, [block])
        self.assertFalse(ok)
        self.assertIn("manifest byte limit", reason)


if __name__ == "__main__":
    unittest.main()
