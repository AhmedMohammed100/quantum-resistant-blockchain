import unittest
from qr_blockchain.portable_encoding import canonical_json_v1, hash_canonical_v1

TX_ID = "a" * 64
PREVIOUS_HASH = "b" * 64
STATE_ROOT = "c" * 64
INCLUDED_TX_ID = "d" * 64

class PortableSchemaVectorTests(unittest.TestCase):
    def test_versioned_transaction_vector(self):
        value = {"version": 2, "chain_id": "qr-chain-devnet", "kind": "transfer",
            "timestamp_us": 1700000000123456, "fee": 2,
            "inputs": [{"prev_tx_id": TX_ID, "output_index": 1}],
            "outputs": [{"recipient": "qbc1alice", "amount": 100}],
            "metadata": {}, "signature_scheme": "mldsa65"}
        expected = ('{"chain_id":"qr-chain-devnet","fee":2,"inputs":[{"output_index":1,'
            '"prev_tx_id":"' + TX_ID + '"}],"kind":"transfer","metadata":{},'
            '"outputs":[{"amount":100,"recipient":"qbc1alice"}],'
            '"signature_scheme":"mldsa65","timestamp_us":1700000000123456,"version":2}').encode()
        self.assertEqual(canonical_json_v1(value), expected)
        self.assertEqual(hash_canonical_v1("transaction-v2", value),
            "898a1b493358e23d7bce1bd4b9cb3f2b45471b8e48f048569a04d98a39e79398")

    def test_versioned_block_vector(self):
        value = {"version": 2, "chain_id": "qr-chain-devnet", "height": 7,
            "previous_hash": PREVIOUS_HASH, "timestamp_us": 1700000001123456,
            "difficulty": 2, "nonce": 9, "transactions": [{"tx_id": INCLUDED_TX_ID}],
            "state_root": STATE_ROOT}
        expected = ('{"chain_id":"qr-chain-devnet","difficulty":2,"height":7,"nonce":9,'
            '"previous_hash":"' + PREVIOUS_HASH + '","state_root":"' + STATE_ROOT +
            '","timestamp_us":1700000001123456,"transactions":[{"tx_id":"' +
            INCLUDED_TX_ID + '"}],"version":2}').encode()
        self.assertEqual(canonical_json_v1(value), expected)
        self.assertEqual(hash_canonical_v1("block-v2", value),
            "e265097b5b46d1ca8a55f3fddf04a2c3cee5657e80f614fbc0e95006f9112481")

    def test_signature_preimage_vector(self):
        transaction = {"version": 2, "kind": "transfer", "fee": 2,
            "timestamp_us": 1700000000123456,
            "inputs": [{"prev_tx_id": TX_ID, "output_index": 1}],
            "outputs": [{"recipient": "qbc1alice", "amount": 100}],
            "metadata": {}, "signature_scheme": "mldsa65"}
        value = {"version": 2, "chain_id": "qr-chain-devnet", "transaction": transaction}
        expected = ('{"chain_id":"qr-chain-devnet","transaction":{"fee":2,"inputs":[{"output_index":1,'
            '"prev_tx_id":"' + TX_ID + '"}],"kind":"transfer","metadata":{},'
            '"outputs":[{"amount":100,"recipient":"qbc1alice"}],'
            '"signature_scheme":"mldsa65","timestamp_us":1700000000123456,"version":2},"version":2}').encode()
        self.assertEqual(canonical_json_v1(value), expected)
        self.assertEqual(hash_canonical_v1("signature-preimage-v2", value),
            "b5f703c9ae8298cdf633254078bf82ef4b2c7b34fd8f78474d74afe70628aab9")

    def test_state_root_vector(self):
        value = [
            {"tx_id": TX_ID, "output_index": 1, "recipient": "qbc1alice", "amount": 100},
            {"tx_id": "b" * 64, "output_index": 0, "recipient": "qbc1bob", "amount": 50}]
        expected = ('[{"amount":100,"output_index":1,"recipient":"qbc1alice","tx_id":"' + TX_ID +
            '"},{"amount":50,"output_index":0,"recipient":"qbc1bob","tx_id":"' +
            "b" * 64 + '"}]').encode()
        self.assertEqual(canonical_json_v1(value), expected)
        self.assertEqual(hash_canonical_v1("state-root-v2", value),
            "14239324cd984646f8169f15ec490d4599b0d8ec4e6c1dac3635a1f8946d18d3")

if __name__ == "__main__":
    unittest.main()
