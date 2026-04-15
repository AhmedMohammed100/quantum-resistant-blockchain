from __future__ import annotations

from pathlib import Path
import shutil
import unittest
from unittest.mock import patch

from qr_blockchain import NodeConfig, NodeService, Wallet


class NodeServiceTests(unittest.TestCase):
    def make_config(self, db_path: Path, *, chain_id: str = "qr-chain-devnet") -> NodeConfig:
        return NodeConfig(
            db_path=db_path,
            difficulty=1,
            mining_reward=10,
            chain_id=chain_id,
        )

    def make_service(self) -> tuple[NodeService, Path]:
        temp_root = Path("test_runtime")
        temp_root.mkdir(exist_ok=True)
        case_dir = temp_root / self._testMethodName
        if case_dir.exists():
            shutil.rmtree(case_dir)
        case_dir.mkdir(parents=True, exist_ok=True)
        db_path = case_dir / "chain.db"
        service = NodeService(self.make_config(db_path))
        self.addCleanup(lambda: shutil.rmtree(case_dir, ignore_errors=True))
        return service, db_path

    def make_additional_service(self, suffix: str, *, chain_id: str = "qr-chain-devnet") -> NodeService:
        temp_root = Path("test_runtime")
        temp_root.mkdir(exist_ok=True)
        case_dir = temp_root / f"{self._testMethodName}_{suffix}"
        if case_dir.exists():
            shutil.rmtree(case_dir)
        case_dir.mkdir(parents=True, exist_ok=True)
        self.addCleanup(lambda: shutil.rmtree(case_dir, ignore_errors=True))
        return NodeService(self.make_config(case_dir / "chain.db", chain_id=chain_id))

    def test_persists_chain_state_across_restarts(self) -> None:
        service, db_path = self.make_service()
        alice = Wallet("Alice")
        miner = Wallet("Miner")

        service.create_genesis_block({alice.create_address(): 50})
        miner_address = miner.create_address()
        service.mine_pending_transactions(miner_address)

        restarted = NodeService(self.make_config(db_path))
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

    def test_rejects_cross_chain_replay(self) -> None:
        service_a, _ = self.make_service()
        service_b = self.make_additional_service("other", chain_id="qr-chain-alt")

        alice = Wallet("Alice")
        bob = Wallet("Bob")

        funding = alice.create_address()
        service_a.create_genesis_block({funding: 30})
        transaction = alice.create_transaction(service_a, bob.create_address(), amount=10, fee=1)

        service_b.create_genesis_block({alice.create_address(): 30})
        with self.assertRaisesRegex(ValueError, "different chain"):
            service_b.submit_transaction(transaction)

    def test_imports_block_from_peer_node(self) -> None:
        source, _ = self.make_service()
        target = self.make_additional_service("target")

        alice = Wallet("Alice")
        bob = Wallet("Bob")
        miner = Wallet("Miner")

        funding = alice.create_address()
        bob_address = bob.create_address()
        miner_address = miner.create_address()

        source.create_genesis_block({funding: 25})
        target.create_genesis_block({funding: 25})
        transaction = alice.create_transaction(source, bob_address, amount=10, fee=1)
        source.submit_transaction(transaction)
        mined_block = source.mine_pending_transactions(miner_address)

        target.import_block(mined_block)

        self.assertEqual(target.chain_summary()["height"], 2)
        self.assertEqual(target.balance_for_address(bob_address), 10)
        self.assertEqual(target.balance_for_address(miner_address), 11)

    def test_syncs_missing_blocks_from_peer(self) -> None:
        source, _ = self.make_service()
        target = self.make_additional_service("target")

        alice = Wallet("Alice")
        bob = Wallet("Bob")
        miner = Wallet("Miner")

        funding = alice.create_address()
        bob_address = bob.create_address()
        miner_address = miner.create_address()

        source.create_genesis_block({funding: 40})
        target.create_genesis_block({funding: 40})
        transaction = alice.create_transaction(source, bob_address, amount=14, fee=2)
        source.submit_transaction(transaction)
        mined_block = source.mine_pending_transactions(miner_address)

        peer_url = "http://peer-one:8080"

        def fake_fetch_json(url: str, *, method: str = "GET", payload: dict[str, object] | None = None, timeout: float = 10.0) -> dict[str, object]:
            if url.endswith("/chain/summary"):
                return source.chain_summary()
            if "/blocks?start_height=1" in url:
                return {"blocks": [mined_block.to_dict()]}
            raise AssertionError(f"Unexpected URL {url}")

        with patch("qr_blockchain.service.fetch_json", side_effect=fake_fetch_json):
            imported = target.sync_with_peer(peer_url)

        self.assertEqual(imported, 1)
        self.assertEqual(target.balance_for_address(bob_address), 14)
        self.assertIn(peer_url, target.list_peers())


if __name__ == "__main__":
    unittest.main()
