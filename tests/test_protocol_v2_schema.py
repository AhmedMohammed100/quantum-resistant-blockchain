import copy
import unittest

from qr_blockchain.portable_encoding import hash_canonical_v1
from qr_blockchain.protocol_v2 import (
    V2SchemaError,
    parse_canonical_v2,
    validate_block_header_v2,
    validate_state_utxos_v2,
    validate_transaction_v2,
)


def fixture_tx():
    tx = {
        "version": 2, "chain_id": "qr-chain-devnet", "kind": "transfer",
        "timestamp_us": 1700000000123456, "fee": 2,
        "inputs": [{"prev_tx_id": "a" * 64, "output_index": 1,
                    "public_key": {"fixture": "pk-alice"}, "signature": {"fixture": "sig-alice"}}],
        "outputs": [{"recipient": "qbc1alice", "amount": 100}], "metadata": {},
        "signature_scheme": "mldsa65",
    }
    tx["tx_id"] = hash_canonical_v1("transaction-v2", tx)
    return tx


def validate_tx(tx):
    return validate_transaction_v2(
        tx, chain_id="qr-chain-devnet", kinds={"transfer": lambda metadata: None},
        providers={"mldsa65": lambda pk, sig: None}, address_validator=lambda address: address.startswith("qbc1"),
    )


class ProtocolV2SchemaTests(unittest.TestCase):
    def test_valid_transaction_recomputes_golden_vector_id(self):
        tx = fixture_tx()
        self.assertEqual(validate_tx(tx), "01f8a81008a8bde0e793b5e5ca8c569e9c95ffe31fdd473283752f218201a5d0")

    def test_rejects_unknown_field_and_wrong_version_type(self):
        tx = fixture_tx(); tx["extra"] = 1
        with self.assertRaises(V2SchemaError): validate_tx(tx)
        tx = fixture_tx(); tx["version"] = True
        with self.assertRaises(V2SchemaError): validate_tx(tx)

    def test_rejects_duplicate_outpoint_bad_id_unregistered_kind_and_bad_address(self):
        tx = fixture_tx(); tx["inputs"].append(copy.deepcopy(tx["inputs"][0]))
        with self.assertRaises(V2SchemaError): validate_tx(tx)
        tx = fixture_tx(); tx["tx_id"] = "0" * 64
        with self.assertRaises(V2SchemaError): validate_tx(tx)
        tx = fixture_tx(); tx["kind"] = "unregistered"
        with self.assertRaises(V2SchemaError): validate_tx(tx)
        tx = fixture_tx(); tx["kind"] = "reward"
        with self.assertRaisesRegex(V2SchemaError, "only the ordinary transfer"):
            validate_transaction_v2(tx, chain_id="qr-chain-devnet",
                kinds={"transfer": lambda metadata: None, "reward": lambda metadata: None},
                providers={"mldsa65": lambda pk, sig: None}, address_validator=lambda address: True)
        tx = fixture_tx(); tx["outputs"][0]["recipient"] = "invalid"
        with self.assertRaises(V2SchemaError): validate_tx(tx)

    def test_state_root_requires_sorted_unique_utxos(self):
        values = [
            {"tx_id": "a" * 64, "output_index": 1, "recipient": "qbc1alice", "amount": 100},
            {"tx_id": "b" * 64, "output_index": 0, "recipient": "qbc1bob", "amount": 50},
        ]
        self.assertEqual(validate_state_utxos_v2(values, address_validator=lambda x: x.startswith("qbc1")),
                         "14239324cd984646f8169f15ec490d4599b0d8ec4e6c1dac3635a1f8946d18d3")
        with self.assertRaises(V2SchemaError):
            validate_state_utxos_v2(list(reversed(values)), address_validator=lambda x: True)
        with self.assertRaises(V2SchemaError):
            validate_state_utxos_v2([values[0], values[0]], address_validator=lambda x: True)

    def test_strict_json_parser_rejects_duplicates_floats_and_noncanonical_bytes(self):
        with self.assertRaises(V2SchemaError): parse_canonical_v2(b'{"a":1,"a":2}', maximum=100)
        with self.assertRaises(V2SchemaError): parse_canonical_v2(b'{"a":1.0}', maximum=100)
        with self.assertRaises(V2SchemaError): parse_canonical_v2(b'{ "a":1}', maximum=100)
        self.assertEqual(parse_canonical_v2(b'{"a":1}', maximum=100), {"a": 1})

    def test_block_recomputes_ordered_id_preimage_and_rejects_mutation(self):
        value = {"version": 2, "chain_id": "qr-chain-devnet", "height": 7,
                 "previous_hash": "b" * 64, "timestamp_us": 1700000001123456,
                 "difficulty": 2, "nonce": 9, "miner": "qbc1miner",
                 "transactions": [fixture_tx()],
                 "state_root": "14239324cd984646f8169f15ec490d4599b0d8ec4e6c1dac3635a1f8946d18d3"}
        tx_id = validate_tx(value["transactions"][0])
        preimage = dict(value, transactions=[tx_id])
        value["block_hash"] = hash_canonical_v1("block-v2", preimage)
        self.assertEqual(validate_block_header_v2(value, chain_id="qr-chain-devnet", transaction_ids=[tx_id], address_validator=lambda x: x.startswith("qbc1")),
                         "8409f50017640fea77542ad9bfffe42a173b9d740f6381ab805c4f485d810ac4")
        value["transactions"] = []
        with self.assertRaises(V2SchemaError):
            validate_block_header_v2(value, chain_id="qr-chain-devnet", transaction_ids=["c" * 64], address_validator=lambda x: True)


if __name__ == "__main__":
    unittest.main()
