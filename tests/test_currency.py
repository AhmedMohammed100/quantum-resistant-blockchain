from __future__ import annotations

from pathlib import Path
import shutil
import unittest

from qr_blockchain import NodeConfig, NodeService, Wallet
from qr_blockchain.currency import CurrencyPolicy, format_units


class CurrencyTests(unittest.TestCase):
    def make_service(self, *, reward: int = 100, halving: int = 2) -> NodeService:
        root = Path("test_runtime") / self._testMethodName
        if root.exists():
            shutil.rmtree(root)
        root.mkdir(parents=True, exist_ok=True)
        self.addCleanup(lambda: shutil.rmtree(root, ignore_errors=True))
        return NodeService(
            NodeConfig(
                db_path=root / "chain.db",
                wallet_state_db_path=root / "wallet_state.db",
                mining_reward=reward,
                subsidy_halving_interval=halving,
                currency_symbol="QRC",
                currency_decimals=2,
                currency_base_unit="quark",
            )
        )

    def test_currency_policy_halves_subsidy_by_height(self) -> None:
        policy = CurrencyPolicy(
            name="Quantum Resistant Coin",
            symbol="QRC",
            decimals=8,
            base_unit="quark",
            initial_subsidy=100,
            subsidy_halving_interval=2,
            max_money=1000000,
        )

        self.assertEqual(policy.subsidy_at_height(1), 100)
        self.assertEqual(policy.subsidy_at_height(2), 50)
        self.assertEqual(policy.subsidy_at_height(4), 25)
        self.assertEqual(policy.cumulative_subsidy_through_height(4), 225)

    def test_mining_uses_height_based_subsidy_and_supply_snapshot(self) -> None:
        service = self.make_service(reward=100, halving=2)
        alice = Wallet("Alice")
        miner = Wallet("Miner")
        miner_address = miner.create_address()
        service.create_genesis_block({alice.create_address(): 500})

        service.mine_pending_transactions(miner_address)
        service.mine_pending_transactions(miner_address)
        service.mine_pending_transactions(miner_address)

        self.assertEqual(service.balance_for_address(miner_address), 200)
        supply = service.supply_snapshot()
        self.assertEqual(supply["genesis_supply"], 500)
        self.assertEqual(supply["subsidy_issued"], 200)
        self.assertEqual(supply["theoretical_supply"], 700)
        self.assertEqual(supply["unspent_supply"], 700)
        self.assertEqual(supply["currency"]["subsidy_at_next_height"], 25)

    def test_genesis_supply_cap_is_enforced(self) -> None:
        root = Path("test_runtime") / self._testMethodName
        if root.exists():
            shutil.rmtree(root)
        root.mkdir(parents=True, exist_ok=True)
        self.addCleanup(lambda: shutil.rmtree(root, ignore_errors=True))
        service = NodeService(
            NodeConfig(
                db_path=root / "chain.db",
                wallet_state_db_path=root / "wallet_state.db",
                genesis_supply_cap=10,
            )
        )

        with self.assertRaisesRegex(ValueError, "genesis supply cap"):
            service.create_genesis_block({"too-much": 11})

    def test_formatted_balance_uses_currency_metadata(self) -> None:
        service = self.make_service(reward=100, halving=2)
        address = "alice"
        service.create_genesis_block({address: 12345})

        balance = service.formatted_balance_for_address(address)

        self.assertEqual(balance["amount"], 12345)
        self.assertEqual(balance["formatted"], "123.45 QRC")
        self.assertEqual(format_units(1, decimals=2, symbol="QRC"), "0.01 QRC")


if __name__ == "__main__":
    unittest.main()
