"""Loopback multi-node tests for the isolated v2 test-network consensus engine."""

import copy
import hashlib
import hmac
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.request import urlopen

from qr_blockchain.portable_encoding import canonical_json_v1, hash_canonical_v1
from qr_blockchain.protocol_v2 import (
    V2SchemaError,
    apply_transfer_v2,
    parse_canonical_v2,
    signature_message_v2,
    signature_preimage_v2,
    validate_state_utxos_v2,
    validate_transaction_with_owners_v2,
)
from qr_blockchain.protocol_v2_consensus import V2ConsensusNode, create_genesis_block_v2
from qr_blockchain.protocol_v2_manifest import v2_network_manifest_digest


CHAIN_ID = "qbc-v2-node-fixture"
GENESIS_TIMESTAMP = 1_700_000_000_000_000
DIFFICULTY_BITS = 4
MAX_STEP_US = 120_000_000
MAX_SUPPLY = 1_000
SECRET = b"test-only-not-a-production-key"
PROVIDER_ID = "fixture_hmac"
ALLOCATIONS = [{"recipient": "qbc1alice", "amount": MAX_SUPPLY}]


def is_address(value):
    return isinstance(value, str) and value.startswith("qbc1")


def provider_verify(public_key, signature, message):
    if not isinstance(public_key, dict) or set(public_key) != {"owner"}:
        raise V2SchemaError("fixture public key shape is invalid")
    if public_key["owner"] not in {"alice", "bob", "carol", "miner"}:
        raise V2SchemaError("fixture public key owner is unknown")
    expected = hmac.new(SECRET, message, hashlib.sha256).hexdigest()
    if not isinstance(signature, str) or not hmac.compare_digest(signature, expected):
        raise V2SchemaError("fixture signature is invalid")
    return "qbc1" + public_key["owner"]


def profile_parameters():
    return {
        "difficulty_bits": DIFFICULTY_BITS,
        "max_timestamp_step_us": MAX_STEP_US,
        "max_supply": MAX_SUPPLY,
        "genesis_timestamp_us": GENESIS_TIMESTAMP,
        "genesis_allocations": copy.deepcopy(ALLOCATIONS),
    }


def build_network():
    genesis, _ = create_genesis_block_v2(
        chain_id=CHAIN_ID, timestamp_us=GENESIS_TIMESTAMP,
        allocations=copy.deepcopy(ALLOCATIONS), max_supply=MAX_SUPPLY,
        address_validator=is_address,
    )
    manifest = {
        "manifest_version": 1,
        "chain_id": CHAIN_ID,
        "genesis_hash": genesis["block_hash"],
        "encoding_profile": "qbc-cjson-v1",
        "transaction_schema_version": 2,
        "block_schema_version": 2,
        "activation": {"mode": "genesis"},
        "transaction_kinds": ["transfer"],
        "signature_providers": [{
            "provider_id": PROVIDER_ID, "provider_version": "1.0.0",
            "signing_mode": "canonical-bytes", "public_key_schema": "fixture-key-v1",
            "signature_schema": "fixture-hmac-v1", "max_public_key_bytes": 128,
            "max_signature_bytes": 128,
        }],
        "consensus_profile": {
            "profile_id": "qbc-pow-fixed", "profile_version": "1",
            "parameters": profile_parameters(),
        },
        "limits": {
            "max_transaction_bytes": 1 << 20, "max_block_bytes": 4 << 20,
            "max_metadata_bytes": 16 << 10, "max_inputs": 256,
            "max_outputs": 256, "max_transactions_per_block": 4096,
        },
    }
    manifest["manifest_digest"] = v2_network_manifest_digest(manifest)
    return manifest, genesis


def create_node(manifest, genesis, database_path=None):
    def validate_profile(parameters):
        if parameters != profile_parameters():
            raise V2SchemaError("unsupported fixed-work profile parameters")

    return V2ConsensusNode(
        manifest=manifest, genesis_block=genesis, expected_chain_id=manifest["chain_id"],
        supported_kinds={"transfer"},
        provider_profiles={(PROVIDER_ID, "1.0.0"): lambda _: None},
        consensus_profiles={("qbc-pow-fixed", "1"): validate_profile},
        providers={PROVIDER_ID: provider_verify}, address_validator=is_address,
        database_path=database_path,
    )


def signed_transfer(*, prev_tx_id, amount, fee=0, owner="alice", recipient="qbc1bob", chain_id=CHAIN_ID):
    tx = {
        "version": 2, "chain_id": chain_id, "kind": "transfer",
        "timestamp_us": GENESIS_TIMESTAMP + 1, "fee": fee,
        "inputs": [{"prev_tx_id": prev_tx_id, "output_index": 0,
                    "public_key": {"owner": owner}, "signature": ""}],
        "outputs": [{"recipient": recipient, "amount": amount}],
        "metadata": {}, "signature_scheme": PROVIDER_ID,
    }
    message = signature_message_v2(signature_preimage_v2(tx), mode="canonical-bytes", domain=None)
    tx["inputs"][0]["signature"] = hmac.new(SECRET, message, hashlib.sha256).hexdigest()
    tx["tx_id"] = hash_canonical_v1("transaction-v2", tx)
    return tx


def block_after(node, parent, transactions=(), *, timestamp_delta=1, miner="qbc1miner", require_hash_less_than=None):
    state = node.states[parent["block_hash"]]
    ids = []
    txids_on_branch = node.branch_txids[parent["block_hash"]]
    for tx in transactions:
        txid, owners = validate_transaction_with_owners_v2(
            tx, chain_id=node.chain_id, kinds={"transfer": lambda _: None},
            providers=node.providers, provider_modes=node.provider_modes,
            address_validator=node.address_validator,
        )
        if txid in txids_on_branch or txid in ids:
            raise ValueError("test builder received a replay transaction")
        ids.append(txid)
        state = apply_transfer_v2(tx, tx_id=txid, input_owners=owners, utxos=state)
    state_root = validate_state_utxos_v2(
        [dict(state[key]) for key in sorted(state)], address_validator=is_address,
    )
    block = {
        "version": 2, "chain_id": node.chain_id,
        "height": parent["height"] + 1, "previous_hash": parent["block_hash"],
        "timestamp_us": parent["timestamp_us"] + timestamp_delta,
        "difficulty": node.difficulty_bits, "nonce": 0, "miner": miner,
        "transactions": list(transactions), "state_root": state_root,
    }
    while True:
        preimage = dict(block)
        preimage["transactions"] = ids
        block_hash = hash_canonical_v1("block-v2", preimage)
        if int(block_hash, 16).bit_length() <= 256 - node.difficulty_bits:
            if require_hash_less_than is None or block_hash < require_hash_less_than:
                block["block_hash"] = block_hash
                return block
        block["nonce"] += 1


class PeerServer:
    def __init__(self, node):
        self.node = node
        node_ref = node

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                if self.path == "/handshake":
                    payload = node_ref.handshake()
                elif self.path == "/blocks":
                    payload = node_ref.canonical_blocks()
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

    def close(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)


class HTTPPeer:
    def __init__(self, base_url):
        self.base_url = base_url

    def _get(self, path):
        with urlopen(self.base_url + path, timeout=2) as response:
            raw = response.read()
        return parse_canonical_v2(raw, maximum=64 << 20)

    def handshake(self):
        return self._get("/handshake")

    def canonical_blocks(self):
        return self._get("/blocks")


class V2NodeToNodeConsensusTests(unittest.TestCase):
    def setUp(self):
        self.manifest, self.genesis = build_network()
        self.alice = create_node(self.manifest, self.genesis)
        self.bob = create_node(self.manifest, self.genesis)

    def test_two_loopback_nodes_converge_on_signed_transfer_and_state(self):
        tx = signed_transfer(prev_tx_id=self.genesis["block_hash"], amount=990, fee=10)
        # Genesis UTXO IDs are deterministic allocation IDs, not the block hash.
        genesis_utxo = self.alice.canonical_state()[0]
        tx = signed_transfer(prev_tx_id=genesis_utxo["tx_id"], amount=990, fee=10)
        block = block_after(self.alice, self.genesis, [tx])
        self.alice.accept_block(block)
        server = PeerServer(self.alice)
        try:
            self.bob.sync_from(HTTPPeer(server.base_url))
        finally:
            server.close()
        self.assertEqual(self.bob.tip_hash, self.alice.tip_hash)
        self.assertEqual(self.bob.canonical_state(), self.alice.canonical_state())
        self.assertEqual(self.bob.canonical_state()[0]["recipient"], "qbc1bob")
        self.assertEqual(sum(item["amount"] for item in self.bob.canonical_state()), 990)

    def test_rejects_bad_signature_bad_value_and_duplicate_replay_without_mutation(self):
        genesis_utxo = self.alice.canonical_state()[0]
        bad_signature = signed_transfer(prev_tx_id=genesis_utxo["tx_id"], amount=990)
        bad_signature["inputs"][0]["signature"] = "00" * 32
        bad_signature["tx_id"] = hash_canonical_v1(
            "transaction-v2", {key: value for key, value in bad_signature.items() if key != "tx_id"},
        )
        before = self.alice.tip_hash
        with self.assertRaisesRegex(V2SchemaError, "signature is invalid"):
            self.alice.accept_block(block_after(self.alice, self.genesis, [bad_signature]))
        self.assertEqual(self.alice.tip_hash, before)

        bad_value = signed_transfer(prev_tx_id=genesis_utxo["tx_id"], amount=999, fee=10)
        # Re-sign after changing the signed outputs, then recompute the transaction ID.
        message = signature_message_v2(signature_preimage_v2(bad_value), mode="canonical-bytes", domain=None)
        bad_value["inputs"][0]["signature"] = hmac.new(SECRET, message, hashlib.sha256).hexdigest()
        bad_value["tx_id"] = hash_canonical_v1(
            "transaction-v2", {key: value for key, value in bad_value.items() if key != "tx_id"},
        )
        with self.assertRaisesRegex(V2SchemaError, "outputs plus burned fee"):
            self.alice.accept_block(block_after(self.alice, self.genesis, [bad_value]))
        self.assertEqual(self.alice.tip_hash, before)

        valid = signed_transfer(prev_tx_id=genesis_utxo["tx_id"], amount=990, fee=10)
        first = block_after(self.alice, self.genesis, [valid])
        self.alice.accept_block(first)
        replay = block_after(self.alice, first)
        replay["transactions"] = [valid]
        preimage = dict(replay)
        preimage.pop("block_hash")
        preimage["transactions"] = [valid["tx_id"]]
        while True:
            replay["block_hash"] = hash_canonical_v1("block-v2", preimage)
            if int(replay["block_hash"], 16).bit_length() <= 256 - self.alice.difficulty_bits:
                break
            replay["nonce"] += 1
            preimage["nonce"] = replay["nonce"]
        with self.assertRaisesRegex(V2SchemaError, "already present on this branch"):
            self.alice.accept_block(replay)
        self.assertEqual(self.alice.tip_hash, first["block_hash"])

    def test_rejects_chain_id_replay_and_timestamp_or_linkage_errors(self):
        genesis_utxo = self.alice.canonical_state()[0]
        foreign_tx = signed_transfer(
            prev_tx_id=genesis_utxo["tx_id"], amount=990, fee=10,
            chain_id="qbc-v2-another-chain",
        )
        candidate = block_after(self.alice, self.genesis)
        candidate["transactions"] = [foreign_tx]
        preimage = {key: value for key, value in candidate.items() if key != "block_hash"}
        preimage["transactions"] = [foreign_tx["tx_id"]]
        while True:
            candidate["block_hash"] = hash_canonical_v1("block-v2", preimage)
            if int(candidate["block_hash"], 16).bit_length() <= 256 - self.alice.difficulty_bits:
                break
            candidate["nonce"] += 1
            preimage["nonce"] = candidate["nonce"]
        before = self.alice.tip_hash
        with self.assertRaisesRegex(V2SchemaError, "chain_id"):
            self.alice.accept_block(candidate)
        self.assertEqual(self.alice.tip_hash, before)

        for delta, message in ((0, "greater than parent"), (MAX_STEP_US + 1, "timestamp exceeds")):
            bad_time = block_after(self.alice, self.genesis, timestamp_delta=delta)
            with self.assertRaisesRegex(V2SchemaError, message):
                self.alice.accept_block(bad_time)
            self.assertEqual(self.alice.tip_hash, before)

        bad_height = block_after(self.alice, self.genesis)
        bad_height["height"] += 1
        with self.assertRaisesRegex(V2SchemaError, "height must be parent height plus one"):
            self.alice.accept_block(bad_height)
        self.assertEqual(self.alice.tip_hash, before)

        bad_parent = block_after(self.alice, self.genesis)
        bad_parent["previous_hash"] = "f" * 64
        with self.assertRaisesRegex(V2SchemaError, "parent is unknown"):
            self.alice.accept_block(bad_parent)
        self.assertEqual(self.alice.tip_hash, before)

    def test_rejects_state_root_pow_and_peer_configuration_mismatches(self):
        valid = block_after(self.alice, self.genesis)
        bad_root = copy.deepcopy(valid)
        bad_root["state_root"] = "f" * 64
        preimage = dict(bad_root)
        preimage.pop("block_hash")
        preimage["transactions"] = []
        bad_root["block_hash"] = hash_canonical_v1("block-v2", preimage)
        while int(bad_root["block_hash"], 16).bit_length() > 256 - self.alice.difficulty_bits:
            bad_root["nonce"] += 1
            preimage["nonce"] = bad_root["nonce"]
            bad_root["block_hash"] = hash_canonical_v1("block-v2", preimage)
        with self.assertRaisesRegex(V2SchemaError, "state_root"):
            self.alice.accept_block(bad_root)
        self.assertEqual(self.alice.tip_hash, self.genesis["block_hash"])

        bad_pow = copy.deepcopy(valid)
        bad_pow["nonce"] += 1
        preimage = dict(bad_pow)
        preimage.pop("block_hash")
        preimage["transactions"] = []
        bad_pow["block_hash"] = hash_canonical_v1("block-v2", preimage)
        while int(bad_pow["block_hash"], 16).bit_length() <= 256 - self.alice.difficulty_bits:
            bad_pow["nonce"] += 1
            preimage["nonce"] = bad_pow["nonce"]
            bad_pow["block_hash"] = hash_canonical_v1("block-v2", preimage)
        with self.assertRaisesRegex(V2SchemaError, "proof of work"):
            self.alice.accept_block(bad_pow)
        self.assertEqual(self.alice.tip_hash, self.genesis["block_hash"])

        foreign_manifest, foreign_genesis = build_network()
        foreign_manifest["chain_id"] = "qbc-v2-foreign"
        foreign_genesis, _ = create_genesis_block_v2(
            chain_id=foreign_manifest["chain_id"], timestamp_us=GENESIS_TIMESTAMP,
            allocations=copy.deepcopy(ALLOCATIONS), max_supply=MAX_SUPPLY,
            address_validator=is_address,
        )
        foreign_manifest["genesis_hash"] = foreign_genesis["block_hash"]
        foreign_manifest["manifest_digest"] = v2_network_manifest_digest(foreign_manifest)
        foreign = create_node(foreign_manifest, foreign_genesis)
        with self.assertRaisesRegex(V2SchemaError, "handshake"):
            self.alice.sync_from(foreign)
        with self.assertRaisesRegex(V2SchemaError, "handshake"):
            self.alice.sync_from(type("LegacyPeer", (), {
                "handshake": lambda _: {"protocol_version": 1},
                "canonical_blocks": lambda _: [],
            })())
        self.assertEqual(self.alice.tip_hash, self.genesis["block_hash"])

    def test_fork_tie_break_and_longer_chain_reorganization(self):
        genesis_utxo = self.alice.canonical_state()[0]
        spend = signed_transfer(prev_tx_id=genesis_utxo["tx_id"], amount=990, fee=10)
        branch_a = block_after(self.alice, self.genesis, [spend])
        self.alice.accept_block(branch_a)
        self.assertEqual(sum(item["amount"] for item in self.alice.canonical_state()), 990)

        # Produce a competing empty block whose lower hash wins the equal-work tie.
        branch_b = block_after(
            self.bob, self.genesis, miner="qbc1carol",
            require_hash_less_than=branch_a["block_hash"],
        )
        self.bob.accept_block(branch_b)
        self.alice.sync_from(self.bob)
        self.bob.sync_from(self.alice)
        self.assertEqual(self.alice.tip_hash, branch_b["block_hash"])
        self.assertEqual(self.bob.tip_hash, branch_b["block_hash"])
        self.assertEqual(sum(item["amount"] for item in self.alice.canonical_state()), MAX_SUPPLY)

        branch_b2 = block_after(self.bob, branch_b, timestamp_delta=1)
        self.bob.accept_block(branch_b2)
        self.alice.sync_from(self.bob)
        self.assertEqual(self.alice.tip_hash, branch_b2["block_hash"])
        self.assertEqual(self.alice.canonical_state(), self.bob.canonical_state())

    def test_restart_replays_persisted_chain_and_rejects_config_change(self):
        with tempfile.TemporaryDirectory(prefix="qbc-v2-node-") as directory:
            database_path = Path(directory) / "node.sqlite3"
            node = create_node(self.manifest, self.genesis, database_path)
            empty_block = block_after(node, self.genesis)
            node.accept_block(empty_block)
            restarted = create_node(self.manifest, self.genesis, database_path)
            self.assertEqual(restarted.tip_hash, empty_block["block_hash"])
            self.assertEqual(restarted.canonical_state(), node.canonical_state())

            wrong_genesis = copy.deepcopy(self.genesis)
            wrong_genesis["timestamp_us"] += 1
            wrong_genesis["block_hash"] = hash_canonical_v1(
                "block-v2", {key: value for key, value in wrong_genesis.items() if key != "block_hash"},
            )
            with self.assertRaisesRegex(V2SchemaError, "manifest genesis_hash"):
                create_node(self.manifest, wrong_genesis, database_path)

    def test_genesis_header_rejects_boolean_integer_fields(self):
        for field in ("version", "height", "timestamp_us", "difficulty", "nonce"):
            malformed = copy.deepcopy(self.genesis)
            malformed[field] = False
            with self.subTest(field=field), self.assertRaisesRegex(V2SchemaError, "genesis block fields"):
                create_node(self.manifest, malformed)


if __name__ == "__main__":
    unittest.main()
