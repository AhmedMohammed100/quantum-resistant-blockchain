from __future__ import annotations

import json
from pathlib import Path
import sqlite3


class SQLiteWalletStateStore:
    def __init__(self, db_path: Path):
        self.db_path = db_path
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.db_path, timeout=30.0)
        connection.row_factory = sqlite3.Row
        return connection

    def _initialize(self) -> None:
        with self._connect() as connection:
            connection.executescript(
                """
                PRAGMA journal_mode=WAL;
                CREATE TABLE IF NOT EXISTS wallet_keys (
                    label TEXT NOT NULL,
                    address TEXT NOT NULL,
                    provider_id TEXT NOT NULL,
                    key_state_json TEXT NOT NULL,
                    state_version INTEGER NOT NULL DEFAULT 0,
                    PRIMARY KEY (label, address)
                );
                """
            )

    def load_wallet_keys(self, label: str, provider_id: str) -> list[tuple[str, object]]:
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT address, key_state_json
                FROM wallet_keys
                WHERE label = ? AND provider_id = ?
                ORDER BY address ASC
                """,
                (label, provider_id),
            ).fetchall()
        return [(str(row["address"]), json.loads(row["key_state_json"])) for row in rows]

    def save_wallet_key(self, label: str, address: str, provider_id: str, key_state: object) -> None:
        with self._connect() as connection:
            connection.execute(
                """
                INSERT INTO wallet_keys (label, address, provider_id, key_state_json, state_version)
                VALUES (?, ?, ?, ?, 0)
                ON CONFLICT(label, address) DO UPDATE SET
                    provider_id = excluded.provider_id,
                    key_state_json = excluded.key_state_json,
                    state_version = wallet_keys.state_version + 1
                """,
                (label, address, provider_id, json.dumps(key_state, sort_keys=True, separators=(",", ":"))),
            )

    def reserve_wallet_key_state(
        self,
        label: str,
        address: str,
        provider_id: str,
        reserve_fn,
    ) -> tuple[object, object]:
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                """
                SELECT key_state_json, state_version
                FROM wallet_keys
                WHERE label = ? AND address = ? AND provider_id = ?
                """,
                (label, address, provider_id),
            ).fetchone()
            if row is None:
                raise ValueError(f"No wallet key state found for {label}:{address}.")

            current_state = json.loads(row["key_state_json"])
            next_state, reservation = reserve_fn(current_state)
            connection.execute(
                """
                UPDATE wallet_keys
                SET key_state_json = ?, state_version = state_version + 1
                WHERE label = ? AND address = ? AND provider_id = ?
                """,
                (
                    json.dumps(next_state, sort_keys=True, separators=(",", ":")),
                    label,
                    address,
                    provider_id,
                ),
            )
            connection.commit()
            return next_state, reservation
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()
