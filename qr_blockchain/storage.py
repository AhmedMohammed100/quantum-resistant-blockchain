from __future__ import annotations

import json
from pathlib import Path
import sqlite3

from .models import Block, Transaction, TxOutput


def block_work(difficulty: int) -> int:
    return 16 ** max(difficulty, 0)


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
                    block_hash TEXT PRIMARY KEY,
                    height INTEGER NOT NULL,
                    previous_hash TEXT NOT NULL,
                    miner TEXT NOT NULL,
                    difficulty INTEGER NOT NULL,
                    nonce INTEGER NOT NULL,
                    timestamp REAL NOT NULL,
                    cumulative_work INTEGER NOT NULL,
                    canonical INTEGER NOT NULL DEFAULT 0,
                    body_json TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_blocks_height ON blocks(height);
                CREATE INDEX IF NOT EXISTS idx_blocks_previous_hash ON blocks(previous_hash);
                CREATE TABLE IF NOT EXISTS chain_state (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
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
                CREATE TABLE IF NOT EXISTS peers (
                    url TEXT PRIMARY KEY
                );
                CREATE TABLE IF NOT EXISTS peer_identities (
                    node_id TEXT PRIMARY KEY,
                    url TEXT NOT NULL,
                    address TEXT NOT NULL,
                    signature_scheme TEXT NOT NULL,
                    public_key_json TEXT NOT NULL,
                    status TEXT NOT NULL,
                    admitted_at REAL NOT NULL,
                    last_seen REAL NOT NULL
                );
                CREATE TABLE IF NOT EXISTS peer_nonces (
                    node_id TEXT NOT NULL,
                    nonce TEXT NOT NULL,
                    seen_at REAL NOT NULL,
                    PRIMARY KEY (node_id, nonce)
                );
                CREATE TABLE IF NOT EXISTS peer_sessions (
                    session_id TEXT PRIMARY KEY,
                    node_id TEXT NOT NULL,
                    url TEXT NOT NULL,
                    created_at REAL NOT NULL,
                    last_seen REAL NOT NULL,
                    expires_at REAL NOT NULL,
                    status TEXT NOT NULL
                );
                """
            )

    def latest_block(self) -> sqlite3.Row | None:
        best_hash = self.best_head_hash()
        if best_hash is None:
            return None
        return self.block_row(best_hash)

    def best_head_hash(self) -> str | None:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT value FROM chain_state WHERE key = 'best_head_hash'"
            ).fetchone()
        return None if row is None else str(row["value"])

    def set_best_head_hash(self, block_hash: str) -> None:
        with self._connect() as connection:
            connection.execute(
                """
                INSERT INTO chain_state (key, value)
                VALUES ('best_head_hash', ?)
                ON CONFLICT(key) DO UPDATE SET value = excluded.value
                """,
                (block_hash,),
            )

    def block_count(self) -> int:
        best = self.latest_block()
        return 0 if best is None else int(best["height"]) + 1

    def block_row(self, block_hash: str) -> sqlite3.Row | None:
        with self._connect() as connection:
            return connection.execute(
                """
                SELECT block_hash, height, previous_hash, miner, difficulty, nonce, timestamp, cumulative_work, canonical, body_json
                FROM blocks
                WHERE block_hash = ?
                """,
                (block_hash,),
            ).fetchone()

    def has_block(self, block_hash: str) -> bool:
        return self.block_row(block_hash) is not None

    def cumulative_work_for(self, block_hash: str) -> int | None:
        row = self.block_row(block_hash)
        return None if row is None else int(row["cumulative_work"])

    def block_by_hash(self, block_hash: str) -> Block | None:
        row = self.block_row(block_hash)
        if row is None:
            return None
        return Block.from_dict(json.loads(row["body_json"]))

    def block_at_height(self, height: int) -> Block | None:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT body_json FROM blocks WHERE height = ? AND canonical = 1",
                (height,),
            ).fetchone()
        if row is None:
            return None
        return Block.from_dict(json.loads(row["body_json"]))

    def blocks_from_height(self, start_height: int) -> list[Block]:
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT body_json
                FROM blocks
                WHERE height >= ? AND canonical = 1
                ORDER BY height ASC
                """,
                (start_height,),
            ).fetchall()
        return [Block.from_dict(json.loads(row["body_json"])) for row in rows]

    def canonical_chain(self) -> list[Block]:
        return self.blocks_from_height(0)

    def path_to_root(self, block_hash: str) -> list[Block]:
        path: list[Block] = []
        cursor = block_hash
        while cursor and cursor != "0" * 64:
            block = self.block_by_hash(cursor)
            if block is None:
                break
            path.append(block)
            cursor = block.previous_hash
        path.reverse()
        return path

    def canonical_hashes(self) -> set[str]:
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT block_hash FROM blocks WHERE canonical = 1"
            ).fetchall()
        return {str(row["block_hash"]) for row in rows}

    def all_utxos(self) -> dict[tuple[str, int], TxOutput]:
        return {(tx_id, output_index): output for tx_id, output_index, output in self.list_utxos()}

    def utxos_for_head(self, block_hash: str | None) -> dict[tuple[str, int], TxOutput]:
        if block_hash is None:
            return {}
        utxos: dict[tuple[str, int], TxOutput] = {}
        for block in self.path_to_root(block_hash):
            self._apply_block_to_utxos(utxos, block)
        return utxos

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

    def remove_pending_transactions(self, transaction_ids: list[str]) -> None:
        if not transaction_ids:
            return
        placeholders = ",".join("?" for _ in transaction_ids)
        with self._connect() as connection:
            connection.execute(
                f"DELETE FROM pending_transactions WHERE tx_id IN ({placeholders})",
                transaction_ids,
            )

    def list_utxos(self, addresses: list[str] | None = None) -> list[tuple[str, int, TxOutput]]:
        with self._connect() as connection:
            if addresses:
                placeholders = ",".join("?" for _ in addresses)
                rows = connection.execute(
                    f"""
                    SELECT tx_id, output_index, recipient, amount
                    FROM utxos
                    WHERE recipient IN ({placeholders})
                    ORDER BY amount ASC, tx_id ASC, output_index ASC
                    """,
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

    def store_block(self, block: Block) -> None:
        parent_work = 0
        if block.previous_hash != "0" * 64:
            parent = self.block_row(block.previous_hash)
            if parent is None:
                raise ValueError("Parent block is not stored.")
            parent_work = int(parent["cumulative_work"])
        cumulative_work = parent_work + block_work(block.difficulty)
        with self._connect() as connection:
            connection.execute(
                """
                INSERT INTO blocks (
                    block_hash, height, previous_hash, miner, difficulty, nonce, timestamp, cumulative_work, canonical, body_json
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0, ?)
                """,
                (
                    block.block_hash,
                    block.index,
                    block.previous_hash,
                    block.miner,
                    block.difficulty,
                    block.nonce,
                    block.timestamp,
                    cumulative_work,
                    json.dumps(block.to_dict(), sort_keys=True, separators=(",", ":")),
                ),
            )

    def apply_best_chain(self, head_hash: str) -> None:
        canonical_blocks = self.path_to_root(head_hash)
        canonical_hashes = {block.block_hash for block in canonical_blocks}
        utxos: dict[tuple[str, int], TxOutput] = {}
        included_ids: list[str] = []
        for block in canonical_blocks:
            self._apply_block_to_utxos(utxos, block)
            included_ids.extend(
                transaction.tx_id for transaction in block.transactions if transaction.tx_id
            )

        with self._connect() as connection:
            connection.execute("UPDATE blocks SET canonical = 0")
            if canonical_hashes:
                placeholders = ",".join("?" for _ in canonical_hashes)
                connection.execute(
                    f"UPDATE blocks SET canonical = 1 WHERE block_hash IN ({placeholders})",
                    list(canonical_hashes),
                )
            connection.execute("DELETE FROM utxos")
            for (tx_id, output_index), output in utxos.items():
                connection.execute(
                    "INSERT INTO utxos (tx_id, output_index, recipient, amount) VALUES (?, ?, ?, ?)",
                    (tx_id, output_index, output.recipient, output.amount),
                )
            if included_ids:
                placeholders = ",".join("?" for _ in included_ids)
                connection.execute(
                    f"DELETE FROM pending_transactions WHERE tx_id IN ({placeholders})",
                    included_ids,
                )
            connection.execute(
                """
                INSERT INTO chain_state (key, value)
                VALUES ('best_head_hash', ?)
                ON CONFLICT(key) DO UPDATE SET value = excluded.value
                """,
                (head_hash,),
            )

    def _apply_block_to_utxos(self, utxos: dict[tuple[str, int], TxOutput], block: Block) -> None:
        for transaction in block.transactions:
            for tx_input in transaction.inputs:
                utxos.pop((tx_input.prev_tx_id, tx_input.output_index), None)
            for output_index, output in enumerate(transaction.outputs):
                utxos[(transaction.tx_id, output_index)] = output

    def add_peer(self, url: str) -> None:
        with self._connect() as connection:
            connection.execute("INSERT OR IGNORE INTO peers (url) VALUES (?)", (url,))

    def list_peers(self) -> list[str]:
        with self._connect() as connection:
            rows = connection.execute("SELECT url FROM peers ORDER BY url ASC").fetchall()
        return [str(row["url"]) for row in rows]

    def upsert_peer_identity(
        self,
        *,
        node_id: str,
        url: str,
        address: str,
        signature_scheme: str,
        public_key: object,
        status: str,
        admitted_at: float,
        last_seen: float,
    ) -> None:
        with self._connect() as connection:
            connection.execute(
                """
                INSERT INTO peer_identities (
                    node_id, url, address, signature_scheme, public_key_json, status, admitted_at, last_seen
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(node_id) DO UPDATE SET
                    url = excluded.url,
                    address = excluded.address,
                    signature_scheme = excluded.signature_scheme,
                    public_key_json = excluded.public_key_json,
                    status = excluded.status,
                    admitted_at = excluded.admitted_at,
                    last_seen = excluded.last_seen
                """,
                (
                    node_id,
                    url,
                    address,
                    signature_scheme,
                    json.dumps(public_key, sort_keys=True, separators=(",", ":")),
                    status,
                    admitted_at,
                    last_seen,
                ),
            )

    def peer_identity_by_url(self, url: str) -> dict[str, object] | None:
        with self._connect() as connection:
            row = connection.execute(
                """
                SELECT node_id, url, address, signature_scheme, public_key_json, status, admitted_at, last_seen
                FROM peer_identities
                WHERE url = ?
                """,
                (url,),
            ).fetchone()
        if row is None:
            return None
        return {
            "node_id": str(row["node_id"]),
            "url": str(row["url"]),
            "address": str(row["address"]),
            "signature_scheme": str(row["signature_scheme"]),
            "public_key": json.loads(row["public_key_json"]),
            "status": str(row["status"]),
            "admitted_at": float(row["admitted_at"]),
            "last_seen": float(row["last_seen"]),
        }

    def peer_identity_by_node_id(self, node_id: str) -> dict[str, object] | None:
        with self._connect() as connection:
            row = connection.execute(
                """
                SELECT node_id, url, address, signature_scheme, public_key_json, status, admitted_at, last_seen
                FROM peer_identities
                WHERE node_id = ?
                """,
                (node_id,),
            ).fetchone()
        if row is None:
            return None
        return {
            "node_id": str(row["node_id"]),
            "url": str(row["url"]),
            "address": str(row["address"]),
            "signature_scheme": str(row["signature_scheme"]),
            "public_key": json.loads(row["public_key_json"]),
            "status": str(row["status"]),
            "admitted_at": float(row["admitted_at"]),
            "last_seen": float(row["last_seen"]),
        }

    def mark_peer_nonce(self, node_id: str, nonce: str, seen_at: float) -> None:
        with self._connect() as connection:
            connection.execute(
                "INSERT INTO peer_nonces (node_id, nonce, seen_at) VALUES (?, ?, ?)",
                (node_id, nonce, seen_at),
            )

    def upsert_peer_session(
        self,
        *,
        session_id: str,
        node_id: str,
        url: str,
        created_at: float,
        last_seen: float,
        expires_at: float,
        status: str,
    ) -> None:
        with self._connect() as connection:
            connection.execute(
                """
                INSERT INTO peer_sessions (
                    session_id, node_id, url, created_at, last_seen, expires_at, status
                )
                VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(session_id) DO UPDATE SET
                    node_id = excluded.node_id,
                    url = excluded.url,
                    created_at = excluded.created_at,
                    last_seen = excluded.last_seen,
                    expires_at = excluded.expires_at,
                    status = excluded.status
                """,
                (session_id, node_id, url, created_at, last_seen, expires_at, status),
            )

    def peer_session(self, session_id: str) -> dict[str, object] | None:
        with self._connect() as connection:
            row = connection.execute(
                """
                SELECT session_id, node_id, url, created_at, last_seen, expires_at, status
                FROM peer_sessions
                WHERE session_id = ?
                """,
                (session_id,),
            ).fetchone()
        if row is None:
            return None
        return {
            "session_id": str(row["session_id"]),
            "node_id": str(row["node_id"]),
            "url": str(row["url"]),
            "created_at": float(row["created_at"]),
            "last_seen": float(row["last_seen"]),
            "expires_at": float(row["expires_at"]),
            "status": str(row["status"]),
        }

    def active_peer_session_for_node(self, node_id: str, now: float) -> dict[str, object] | None:
        with self._connect() as connection:
            row = connection.execute(
                """
                SELECT session_id, node_id, url, created_at, last_seen, expires_at, status
                FROM peer_sessions
                WHERE node_id = ? AND status = 'active' AND expires_at > ?
                ORDER BY expires_at DESC
                LIMIT 1
                """,
                (node_id, now),
            ).fetchone()
        if row is None:
            return None
        return {
            "session_id": str(row["session_id"]),
            "node_id": str(row["node_id"]),
            "url": str(row["url"]),
            "created_at": float(row["created_at"]),
            "last_seen": float(row["last_seen"]),
            "expires_at": float(row["expires_at"]),
            "status": str(row["status"]),
        }

    def expire_peer_sessions_for_node(self, node_id: str) -> None:
        with self._connect() as connection:
            connection.execute(
                "UPDATE peer_sessions SET status = 'expired' WHERE node_id = ? AND status = 'active'",
                (node_id,),
            )

    def touch_peer_session(self, session_id: str, *, last_seen: float, expires_at: float) -> None:
        with self._connect() as connection:
            connection.execute(
                """
                UPDATE peer_sessions
                SET last_seen = ?, expires_at = ?, status = 'active'
                WHERE session_id = ?
                """,
                (last_seen, expires_at, session_id),
            )

    def prune_expired_peer_sessions(self, now: float) -> None:
        with self._connect() as connection:
            connection.execute(
                """
                UPDATE peer_sessions
                SET status = 'expired'
                WHERE status = 'active' AND expires_at <= ?
                """,
                (now,),
            )

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
            "canonical_work": 0 if latest is None else int(latest["cumulative_work"]),
        }
