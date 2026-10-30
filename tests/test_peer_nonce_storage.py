from __future__ import annotations

import sqlite3
import tempfile
import unittest
from pathlib import Path

from qr_blockchain.storage import SQLiteChainStore


class PeerNonceStorageTests(unittest.TestCase):
    def test_expired_nonces_are_pruned_before_new_nonce_is_recorded(self) -> None:
        with tempfile.TemporaryDirectory(prefix="qbc-peer-nonce-") as directory:
            store = SQLiteChainStore(Path(directory) / "chain.db")
            store.mark_peer_nonce("peer-a", "expired", 100.0, retention_seconds=10)
            store.mark_peer_nonce("peer-b", "retained", 105.0, retention_seconds=10)
            store.mark_peer_nonce("peer-a", "new", 111.0, retention_seconds=10)

            with sqlite3.connect(store.db_path) as connection:
                rows = connection.execute(
                    "SELECT node_id, nonce FROM peer_nonces ORDER BY node_id, nonce"
                ).fetchall()

            self.assertEqual(rows, [("peer-a", "new"), ("peer-b", "retained")])

            # Duplicate attempts do not roll back cleanup of expired entries.
            with self.assertRaises(sqlite3.IntegrityError):
                store.mark_peer_nonce("peer-b", "retained", 112.0, retention_seconds=10)

            # Once outside the replay retention window, a nonce row is removed
            # and the same value can be recorded again with a fresh signed timestamp.
            store.mark_peer_nonce("peer-a", "expired", 112.0, retention_seconds=10)

    def test_nonce_retention_must_be_positive(self) -> None:
        with tempfile.TemporaryDirectory(prefix="qbc-peer-nonce-") as directory:
            store = SQLiteChainStore(Path(directory) / "chain.db")
            with self.assertRaisesRegex(ValueError, "must be positive"):
                store.mark_peer_nonce("peer-a", "nonce", 100.0, retention_seconds=0)


if __name__ == "__main__":
    unittest.main()
