from __future__ import annotations

from pathlib import Path
import shutil
import unittest

from qr_blockchain import NodeConfig, NodeService, Wallet


class NodeServiceTests(unittest.TestCase):
    def make_service(self) -> tuple[NodeService, Path]:
        temp_root = Path("test_runtime")
        temp_root.mkdir(exist_ok=True)
        case_dir = temp_root / self._testMethodName
        if case_dir.exists():
            shutil.rmtree(case_dir)
        case_dir.mkdir(parents=True, exist_ok=True)
        db_path = case_dir / "chain.db"
        service = NodeService(NodeConfig(db_path=db_path, difficulty=1, mining_reward=10))
        self.addCleanup(lambda: shutil.rmtree(case_dir, ignore_errors=True))
        return service, db_path

    def test_persists_chain_state_across_restarts(self) -> None:
        service, db_path = self.make_service()
        alice = Wallet("Alice")
        miner = Wallet("Miner")

        service.create_genesis_block({alice.create_address(): 50})
        miner_address = miner.create_address()
        service.mine_pending_transactions(miner_address)

        restarted = NodeService(NodeConfig(db_path=db_path, difficulty=1, mining_reward=10))
        self.assertEqual(restarted.chain_summary()["height"], 2)
        self.assertEqual(restarted.balance_for_address(miner_address), 10)

    def test_multi_input_transaction_and_fee_reward(self) -> None:
        service, _ = self.make_service()
        alice = Wallet("Alice")
        bob = Wallet("Bob")
        miner = Wallet("Miner")

        alice_first = alice.create_address()
        alice_second = alice.create_address()
        bob_receive = bob.create_address()
        miner_address = miner.create_address()

        service.create_genesis_block({alice_first: 20, alice_second: 15})
        transaction = alice.create_transaction(service, bob_receive, amount=30, fee=2)
        service.submit_transaction(transaction)
        service.mine_pending_transactions(miner_address)

        self.assertEqual(service.balance_for_address(bob_receive), 30)
        self.assertEqual(service.balance_for_address(miner_address), 12)
        self.assertEqual(alice.balance(service), 3)

    def test_rejects_pending_double_spend(self) -> None:
        service, _ = self.make_service()
        alice = Wallet("Alice")
        bob = Wallet("Bob")

        funding = alice.create_address()
        bob_one = bob.create_address()
        bob_two = bob.create_address()

        service.create_genesis_block({funding: 25})
        first = alice.create_transaction(service, bob_one, amount=10, fee=1)
        second = alice.create_transaction(service, bob_two, amount=10, fee=1)

        service.submit_transaction(first)
        with self.assertRaisesRegex(ValueError, "pending spend"):
            service.submit_transaction(second)


if __name__ == "__main__":
    unittest.main()
