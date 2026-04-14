from __future__ import annotations

import json
from pathlib import Path
import sqlite3

from .models import Block, Transaction, TxOutput


class SQLiteChainStore:
    def __init__(self, db_path: Path):
        self.db_path = db_path
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.db_path)
        connection.row_factory = sqlite3.Row
        return connection

    def _initialize(self) -> None:
        with self._connect() as connection:
            connection.executescript(
                """
                PRAGMA journal_mode=WAL;
                CREATE TABLE IF NOT EXISTS blocks (
                    height INTEGER PRIMARY KEY,
                    block_hash TEXT NOT NULL UNIQUE,
                    previous_hash TEXT NOT NULL,
                    miner TEXT NOT NULL,
                    difficulty INTEGER NOT NULL,
                    nonce INTEGER NOT NULL,
                    timestamp REAL NOT NULL,
                    body_json TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS pending_transactions (
                    tx_id TEXT PRIMARY KEY,
                    body_json TEXT NOT NULL,
                    created_at REAL NOT NULL
                );
                CREATE TABLE IF NOT EXISTS utxos (
                    tx_id TEXT NOT NULL,
                    output_index INTEGER NOT NULL,
                    recipient TEXT NOT NULL,
                    amount INTEGER NOT NULL,
                    PRIMARY KEY (tx_id, output_index)
                );
                """
            )

    def latest_block(self) -> sqlite3.Row | None:
        with self._connect() as connection:
            return connection.execute(
                "SELECT height, block_hash, previous_hash, miner, difficulty, nonce, timestamp, body_json "
                "FROM blocks ORDER BY height DESC LIMIT 1"
            ).fetchone()

    def block_count(self) -> int:
        with self._connect() as connection:
            row = connection.execute("SELECT COUNT(*) AS count FROM blocks").fetchone()
            return int(row["count"])

    def pending_transactions(self) -> list[Transaction]:
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT body_json FROM pending_transactions ORDER BY created_at ASC"
            ).fetchall()
        return [Transaction.from_dict(json.loads(row["body_json"])) for row in rows]

    def save_pending_transaction(self, transaction: Transaction) -> None:
        with self._connect() as connection:
            connection.execute(
                "INSERT INTO pending_transactions (tx_id, body_json, created_at) VALUES (?, ?, ?)",
                (transaction.tx_id, transaction.serialize_with_id(), transaction.timestamp),
            )

    def list_utxos(self, addresses: list[str] | None = None) -> list[tuple[str, int, TxOutput]]:
        with self._connect() as connection:
            if addresses:
                placeholders = ",".join("?" for _ in addresses)
                rows = connection.execute(
                    f"SELECT tx_id, output_index, recipient, amount FROM utxos WHERE recipient IN ({placeholders}) "
                    "ORDER BY amount ASC, tx_id ASC, output_index ASC",
                    addresses,
                ).fetchall()
            else:
                rows = connection.execute(
                    "SELECT tx_id, output_index, recipient, amount FROM utxos ORDER BY tx_id ASC, output_index ASC"
                ).fetchall()
        return [
            (str(row["tx_id"]), int(row["output_index"]), TxOutput(recipient=str(row["recipient"]), amount=int(row["amount"])))
            for row in rows
        ]

    def utxo(self, tx_id: str, output_index: int) -> TxOutput | None:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT recipient, amount FROM utxos WHERE tx_id = ? AND output_index = ?",
                (tx_id, output_index),
            ).fetchone()
        if row is None:
            return None
        return TxOutput(recipient=str(row["recipient"]), amount=int(row["amount"]))

    def apply_block(self, block: Block) -> None:
        with self._connect() as connection:
            connection.execute(
                """
                INSERT INTO blocks (height, block_hash, previous_hash, miner, difficulty, nonce, timestamp, body_json)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    block.index,
                    block.block_hash,
                    block.previous_hash,
                    block.miner,
                    block.difficulty,
                    block.nonce,
                    block.timestamp,
                    json.dumps(block.to_dict(), sort_keys=True, separators=(",", ":")),
                ),
            )
            for transaction in block.transactions:
                for tx_input in transaction.inputs:
                    connection.execute(
                        "DELETE FROM utxos WHERE tx_id = ? AND output_index = ?",
                        (tx_input.prev_tx_id, tx_input.output_index),
                    )
                for output_index, output in enumerate(transaction.outputs):
                    connection.execute(
                        "INSERT INTO utxos (tx_id, output_index, recipient, amount) VALUES (?, ?, ?, ?)",
                        (transaction.tx_id, output_index, output.recipient, output.amount),
                    )
            connection.execute("DELETE FROM pending_transactions")

    def summary(self) -> dict[str, object]:
        latest = self.latest_block()
        with self._connect() as connection:
            pending = connection.execute("SELECT COUNT(*) AS count FROM pending_transactions").fetchone()
            utxos = connection.execute("SELECT COUNT(*) AS count FROM utxos").fetchone()
        return {
            "height": self.block_count(),
            "pending_transactions": int(pending["count"]),
            "utxo_count": int(utxos["count"]),
            "latest_block_hash": None if latest is None else str(latest["block_hash"]),
        }
