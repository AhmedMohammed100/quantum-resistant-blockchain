from __future__ import annotations

import sqlite3
import tempfile
import unittest
from pathlib import Path

from qr_blockchain import NodeConfig, NodeService


class SQLiteRecoveryTests(unittest.TestCase):
    def test_sqlite_online_backup_reopens_with_consistent_chain_state(self) -> None:
        with tempfile.TemporaryDirectory(prefix="qbc-recovery-") as directory:
            root = Path(directory)
            source_path = root / "chain.db"
            backup_path = root / "chain-backup.db"
            service = NodeService(
                NodeConfig(
                    db_path=source_path,
                    wallet_state_db_path=root / "wallet.db",
                    difficulty=1,
                    mining_reward=10,
                    chain_id="recovery-test-chain",
                )
            )
            genesis = service.create_genesis_block({"recovery-address": 100})
            expected_head = service.store.best_head_hash()
            expected_utxos = service.store.all_utxos()
            expected_summary = service.store.summary()

            # SQLite's backup API includes committed WAL content, unlike a raw
            # filesystem copy of only the main database file.
            with sqlite3.connect(source_path) as source, sqlite3.connect(backup_path) as target:
                source.backup(target)

            restored = NodeService(
                NodeConfig(
                    db_path=backup_path,
                    wallet_state_db_path=root / "wallet-restored.db",
                    difficulty=1,
                    mining_reward=10,
                    chain_id="recovery-test-chain",
                )
            )
            self.assertEqual(restored.store.best_head_hash(), expected_head)
            self.assertEqual(restored.store.latest_block()["block_hash"], genesis.block_hash)
            self.assertEqual(restored.store.all_utxos(), expected_utxos)
            self.assertEqual(restored.store.summary()["height"], expected_summary["height"])
            with sqlite3.connect(backup_path) as connection:
                result = connection.execute("PRAGMA integrity_check").fetchone()[0]
            self.assertEqual(result, "ok")


if __name__ == "__main__":
    unittest.main()
