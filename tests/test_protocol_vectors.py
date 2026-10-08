from __future__ import annotations

import unittest

from qr_blockchain.models import Block, Transaction, TxInput, TxOutput


class QBCProtocolVectorTests(unittest.TestCase):
    """Frozen v0.1 compatibility vectors. Update only with an explicit protocol-version change."""

    def make_transaction(self) -> Transaction:
        transaction = Transaction(
            inputs=[
                TxInput(
                    prev_tx_id="11" * 32,
                    output_index=0,
                    public_key={},
                    signature={},
                )
            ],
            outputs=[TxOutput(recipient="qbc1vectorrecipient", amount=123456789)],
            kind="transfer",
            chain_id="qr-chain-devnet",
            signature_scheme="hash_lamport_v1",
            timestamp=1700000000.125,
            fee=7,
            metadata={"memo": "vector-1"},
        )
        transaction.finalize()
        return transaction

    def test_transaction_serialization_and_id_vector(self) -> None:
        transaction = self.make_transaction()
        self.assertEqual(
            transaction.serialize(),
            '{"chain_id":"qr-chain-devnet","fee":7,"inputs":[{"output_index":0,"prev_tx_id":"'
            + "11" * 32
            + '","public_key":{},"signature":{}}],"kind":"transfer","metadata":{"memo":"vector-1"},'
            '"outputs":[{"amount":123456789,"recipient":"qbc1vectorrecipient"}],'
            '"signature_scheme":"hash_lamport_v1","timestamp":1700000000.125}',
        )
        self.assertEqual(
            transaction.tx_id,
            "9f83e6f9881cf29c25660f19981581883cfa059baf913e3d442803cc088c06e2",
        )

    def test_block_v3_hash_vector_commits_state_root(self) -> None:
        transaction = self.make_transaction()
        block = Block(
            index=1,
            previous_hash="00" * 32,
            transactions=[transaction],
            miner="qbc1miner",
            difficulty=1,
            chain_id="qr-chain-devnet",
            version=3,
            timestamp=1700000001.0,
            nonce=42,
            state_root="22" * 32,
        )
        self.assertEqual(
            block.compute_hash(),
            "56418d7f0f4198a74af542b28759cf450367116db7f8b75b294057527d1b420d",
        )

        changed_root = Block(
            index=block.index,
            previous_hash=block.previous_hash,
            transactions=block.transactions,
            miner=block.miner,
            difficulty=block.difficulty,
            chain_id=block.chain_id,
            version=3,
            timestamp=block.timestamp,
            nonce=block.nonce,
            state_root="33" * 32,
        )
        self.assertNotEqual(block.compute_hash(), changed_root.compute_hash())


if __name__ == "__main__":
    unittest.main()
