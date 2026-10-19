import unittest

from qr_blockchain.portable_encoding import canonical_json_v1, hash_canonical_v1

TX_ID = "a" * 64
PREVIOUS_HASH = "b" * 64
OTHER_TX_ID = "b" * 64
TX_HASH = "01f8a81008a8bde0e793b5e5ca8c569e9c95ffe31fdd473283752f218201a5d0"
STATE_ROOT = "14239324cd984646f8169f15ec490d4599b0d8ec4e6c1dac3635a1f8946d18d3"


class NormativeV2VectorTests(unittest.TestCase):
    def test_h_transaction_id_preimage(self):
        value = {
            "version": 2,
            "chain_id": "qr-chain-devnet",
            "kind": "transfer",
            "timestamp_us": 1700000000123456,
            "fee": 2,
            "inputs": [{
                "prev_tx_id": TX_ID,
                "output_index": 1,
                "public_key": {"fixture": "pk-alice"},
                "signature": {"fixture": "sig-alice"},
            }],
            "outputs": [{"recipient": "qbc1alice", "amount": 100}],
            "metadata": {},
            "signature_scheme": "mldsa65",
        }
        expected = (
            '{"chain_id":"qr-chain-devnet","fee":2,"inputs":[{"output_index":1,"prev_tx_id":"'
            + TX_ID
            + '","public_key":{"fixture":"pk-alice"},"signature":{"fixture":"sig-alice"}}],'
            '"kind":"transfer","metadata":{},"outputs":[{"amount":100,"recipient":"qbc1alice"}],'
            '"signature_scheme":"mldsa65","timestamp_us":1700000000123456,"version":2}'
        ).encode()
        self.assertEqual(canonical_json_v1(value), expected)
        self.assertEqual(hash_canonical_v1("transaction-v2", value), TX_HASH)

    def test_i_flat_signature_preimage(self):
        value = {
            "version": 2,
            "chain_id": "qr-chain-devnet",
            "kind": "transfer",
            "timestamp_us": 1700000000123456,
            "fee": 2,
            "inputs": [{"prev_tx_id": TX_ID, "output_index": 1}],
            "outputs": [{"recipient": "qbc1alice", "amount": 100}],
            "metadata": {},
            "signature_scheme": "mldsa65",
        }
        expected = (
            '{"chain_id":"qr-chain-devnet","fee":2,"inputs":[{"output_index":1,"prev_tx_id":"'
            + TX_ID
            + '"}],"kind":"transfer","metadata":{},"outputs":[{"amount":100,"recipient":"qbc1alice"}],'
            '"signature_scheme":"mldsa65","timestamp_us":1700000000123456,"version":2}'
        ).encode()
        self.assertEqual(canonical_json_v1(value), expected)
        self.assertEqual(
            hash_canonical_v1("signature-preimage-v2", value),
            "b0bea7b13223c0d6bd1ba90e9908ccf6dbb8394827df2bc68a80d3447c56d3f1",
        )

    def test_j_state_root_preimage(self):
        value = [
            {"tx_id": TX_ID, "output_index": 1, "recipient": "qbc1alice", "amount": 100},
            {"tx_id": OTHER_TX_ID, "output_index": 0, "recipient": "qbc1bob", "amount": 50},
        ]
        expected = (
            '[{"amount":100,"output_index":1,"recipient":"qbc1alice","tx_id":"'
            + TX_ID
            + '"},{"amount":50,"output_index":0,"recipient":"qbc1bob","tx_id":"'
            + OTHER_TX_ID
            + '"}]'
        ).encode()
        self.assertEqual(canonical_json_v1(value), expected)
        self.assertEqual(hash_canonical_v1("state-root-v2", value), STATE_ROOT)

    def test_k_block_hash_preimage(self):
        value = {
            "version": 2,
            "chain_id": "qr-chain-devnet",
            "height": 7,
            "previous_hash": PREVIOUS_HASH,
            "timestamp_us": 1700000001123456,
            "difficulty": 2,
            "nonce": 9,
            "miner": "qbc1miner",
            "transactions": [TX_HASH],
            "state_root": STATE_ROOT,
        }
        expected = (
            '{"chain_id":"qr-chain-devnet","difficulty":2,"height":7,"miner":"qbc1miner","nonce":9,'
            '"previous_hash":"' + PREVIOUS_HASH + '","state_root":"' + STATE_ROOT
            + '","timestamp_us":1700000001123456,"transactions":["' + TX_HASH + '"],"version":2}'
        ).encode()
        self.assertEqual(canonical_json_v1(value), expected)
        self.assertEqual(
            hash_canonical_v1("block-v2", value),
            "8409f50017640fea77542ad9bfffe42a173b9d740f6381ab805c4f485d810ac4",
        )


if __name__ == "__main__":
    unittest.main()
