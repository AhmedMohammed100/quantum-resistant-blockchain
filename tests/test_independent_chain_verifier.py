from __future__ import annotations

import copy
import tempfile
import unittest
from pathlib import Path

from qr_blockchain.chain_verifier import verify_chain
from qr_blockchain.chain_state import project_block_utxos, state_root_after_block, utxo_state_root
from qr_blockchain.config import NodeConfig
from qr_blockchain.service import NodeService
from qr_blockchain.signer import Wallet


class IndependentChainVerifierTests(unittest.TestCase):
    def _chain(self):
        temporary_root = tempfile.TemporaryDirectory(prefix="qbc-independent-verifier-")
        self.addCleanup(temporary_root.cleanup)
        root = Path(temporary_root.name)
        service = NodeService(
            NodeConfig(
                db_path=root / "chain.db",
                wallet_state_db_path=root / "wallet.db",
                difficulty=1,
                mining_reward=10,
                chain_id="qbc-independent-verifier-test",
                deployment_mode="test",
                state_root_activation_height=0,
            )
        )
        sender = Wallet("verifier-sender")
        sender_address = sender.create_address()
        service.create_genesis_block({sender_address: 1_000})
        spend = sender.create_transaction(service, "verifier-recipient", amount=999, fee=1)
        service.submit_transaction(spend)
        service.mine_pending_transactions("verifier-miner")
        service.mine_pending_transactions("verifier-miner")
        blocks = service.store.path_to_root(service.store.best_head_hash())
        return service, blocks

    def test_replays_node_chain_without_using_node_block_acceptance(self) -> None:
        service, blocks = self._chain()
        report = verify_chain(
            blocks,
            chain_id=service.config.chain_id,
            subsidy_at_height=service.currency_policy().subsidy_at_height,
            difficulty=service.config.difficulty,
            state_root_activation_height=service.config.state_root_activation_height,
            max_money=service.config.max_money,
        )

        self.assertTrue(report["valid"], report)
        self.assertEqual(report["blocks_checked"], 3)
        self.assertEqual(report["height"], 2)
        self.assertIn("UTXO conservation", " ".join(report["checks"]))
        self.assertTrue(report["limitations"])

    def test_rejects_parent_link_tampering_after_block_is_reminted(self) -> None:
        service, blocks = self._chain()
        tampered = copy.deepcopy(blocks)
        tampered[2].previous_hash = "f" * 64
        tampered[2].mine()

        report = verify_chain(
            tampered,
            chain_id=service.config.chain_id,
            subsidy_at_height=service.currency_policy().subsidy_at_height,
            difficulty=service.config.difficulty,
            state_root_activation_height=service.config.state_root_activation_height,
        )

        self.assertFalse(report["valid"])
        self.assertIn("parent link", str(report["error"]))

    def test_rejects_state_root_mismatch_even_when_block_hash_is_remined(self) -> None:
        service, blocks = self._chain()
        tampered = copy.deepcopy(blocks)
        tampered[1].state_root = "f" * 64
        tampered[1].mine()

        report = verify_chain(
            tampered,
            chain_id=service.config.chain_id,
            subsidy_at_height=service.currency_policy().subsidy_at_height,
            difficulty=service.config.difficulty,
            state_root_activation_height=service.config.state_root_activation_height,
        )

        self.assertFalse(report["valid"])
        self.assertIn("State root mismatch", str(report["error"]))

    def test_extracted_chain_state_functions_match_service_compatibility_methods(self) -> None:
        service, blocks = self._chain()
        parent = service.store.utxos_for_head(blocks[0].block_hash)
        projected = project_block_utxos(parent, blocks[1])
        self.assertEqual(state_root_after_block(parent, blocks[1]), service._state_root_after_block(parent, blocks[1]))
        self.assertEqual(utxo_state_root(projected), service.state_root_for_utxos(projected))
        self.assertEqual(projected, service._state_root_utxos(parent, blocks[1]))


if __name__ == "__main__":
    unittest.main()

