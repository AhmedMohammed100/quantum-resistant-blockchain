from __future__ import annotations

import unittest

from qr_blockchain.models import TxOutput
from qr_blockchain.service import NodeService


class QBCStateRootVectorTests(unittest.TestCase):
    def test_empty_utxo_state_root_vector(self) -> None:
        self.assertEqual(
            NodeService.state_root_for_utxos({}),
            "4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945",
        )

    def test_non_empty_utxo_state_root_vector_is_order_independent(self) -> None:
        first = ("11" * 32, 0)
        second = ("22" * 32, 2)
        utxos = {
            first: TxOutput(recipient="qbc1vectorrecipient", amount=123456789),
            second: TxOutput(recipient="qbc1alice", amount=500),
        }
        expected = "d29fd96143c9249ef82725bb6b8a7bcf7865a9af42476084672223ffec770a26"
        self.assertEqual(NodeService.state_root_for_utxos(utxos), expected)
        self.assertEqual(NodeService.state_root_for_utxos(dict(reversed(list(utxos.items())))), expected)


if __name__ == "__main__":
    unittest.main()
