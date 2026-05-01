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
                    fee INTEGER NOT NULL DEFAULT 0,
                    size_bytes INTEGER NOT NULL DEFAULT 0,
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
                CREATE TABLE IF NOT EXISTS migration_sources (
                    classical_address TEXT PRIMARY KEY,
                    provider_id TEXT NOT NULL,
                    source_network TEXT NOT NULL,
                    amount INTEGER NOT NULL,
                    snapshot_ref TEXT NOT NULL,
                    snapshot_hash TEXT NOT NULL DEFAULT '',
                    source_address TEXT NOT NULL DEFAULT '',
                    source_address_format TEXT NOT NULL DEFAULT '',
                    added_at REAL NOT NULL
                );
                CREATE TABLE IF NOT EXISTS migration_snapshots (
                    snapshot_ref TEXT PRIMARY KEY,
                    source_network TEXT NOT NULL,
                    manifest_hash TEXT NOT NULL,
                    entries_root TEXT NOT NULL,
                    entry_count INTEGER NOT NULL,
                    total_amount INTEGER NOT NULL,
                    generated_at REAL NOT NULL,
                    imported_at REAL NOT NULL,
                    signer_address TEXT NOT NULL DEFAULT '',
                    signer_node_id TEXT NOT NULL DEFAULT '',
                    signer_signature_scheme TEXT NOT NULL DEFAULT '',
                    signer_signature_provider TEXT NOT NULL DEFAULT ''
                );
                CREATE TABLE IF NOT EXISTS migration_claims (
                    classical_address TEXT PRIMARY KEY,
                    provider_id TEXT NOT NULL,
                    source_network TEXT NOT NULL,
                    destination_address TEXT NOT NULL,
                    amount INTEGER NOT NULL,
                    tx_id TEXT NOT NULL,
                    claimed_at REAL NOT NULL
                );
                """
            )
            columns = {
                str(row["name"])
                for row in connection.execute("PRAGMA table_info(pending_transactions)").fetchall()
            }
            if "fee" not in columns:
                connection.execute("ALTER TABLE pending_transactions ADD COLUMN fee INTEGER NOT NULL DEFAULT 0")
            if "size_bytes" not in columns:
                connection.execute("ALTER TABLE pending_transactions ADD COLUMN size_bytes INTEGER NOT NULL DEFAULT 0")
            migration_source_columns = {
                str(row["name"])
                for row in connection.execute("PRAGMA table_info(migration_sources)").fetchall()
            }
            if "snapshot_hash" not in migration_source_columns:
                connection.execute("ALTER TABLE migration_sources ADD COLUMN snapshot_hash TEXT NOT NULL DEFAULT ''")
            if "source_address" not in migration_source_columns:
                connection.execute("ALTER TABLE migration_sources ADD COLUMN source_address TEXT NOT NULL DEFAULT ''")
            if "source_address_format" not in migration_source_columns:
                connection.execute(
                    "ALTER TABLE migration_sources ADD COLUMN source_address_format TEXT NOT NULL DEFAULT ''"
                )
            migration_snapshot_columns = {
                str(row["name"])
                for row in connection.execute("PRAGMA table_info(migration_snapshots)").fetchall()
            }
            if "signer_address" not in migration_snapshot_columns:
                connection.execute("ALTER TABLE migration_snapshots ADD COLUMN signer_address TEXT NOT NULL DEFAULT ''")
            if "signer_node_id" not in migration_snapshot_columns:
                connection.execute("ALTER TABLE migration_snapshots ADD COLUMN signer_node_id TEXT NOT NULL DEFAULT ''")
            if "signer_signature_scheme" not in migration_snapshot_columns:
                connection.execute(
                    "ALTER TABLE migration_snapshots ADD COLUMN signer_signature_scheme TEXT NOT NULL DEFAULT ''"
                )
            if "signer_signature_provider" not in migration_snapshot_columns:
                connection.execute(
                    "ALTER TABLE migration_snapshots ADD COLUMN signer_signature_provider TEXT NOT NULL DEFAULT ''"
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

    def claimed_classical_addresses_for_head(self, block_hash: str | None) -> set[str]:
        if block_hash is None:
            return set()
        claims: set[str] = set()
        for block in self.path_to_root(block_hash):
            for transaction in block.transactions:
                if transaction.kind == "migration_claim":
                    claims.add(str(transaction.metadata.get("classical_address", "")))
        return claims

    def pending_transactions(self) -> list[Transaction]:
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT body_json FROM pending_transactions ORDER BY created_at ASC"
            ).fetchall()
        return [Transaction.from_dict(json.loads(row["body_json"])) for row in rows]

    def save_pending_transaction(self, transaction: Transaction) -> None:
        serialized = transaction.serialize_with_id()
        with self._connect() as connection:
            connection.execute(
                """
                INSERT INTO pending_transactions (tx_id, body_json, fee, size_bytes, created_at)
                VALUES (?, ?, ?, ?, ?)
                """,
                (transaction.tx_id, serialized, transaction.fee, len(serialized.encode("utf-8")), transaction.timestamp),
            )

    def has_pending_transaction(self, tx_id: str) -> bool:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT 1 FROM pending_transactions WHERE tx_id = ? LIMIT 1",
                (tx_id,),
            ).fetchone()
        return row is not None

    def pending_transaction_count(self) -> int:
        with self._connect() as connection:
            row = connection.execute("SELECT COUNT(*) AS count FROM pending_transactions").fetchone()
        return int(row["count"])

    def remove_pending_transactions(self, transaction_ids: list[str]) -> None:
        if not transaction_ids:
            return
        placeholders = ",".join("?" for _ in transaction_ids)
        with self._connect() as connection:
            connection.execute(
                f"DELETE FROM pending_transactions WHERE tx_id IN ({placeholders})",
                transaction_ids,
            )

    def add_migration_source(
        self,
        *,
        classical_address: str,
        provider_id: str,
        source_network: str,
        amount: int,
        snapshot_ref: str,
        snapshot_hash: str = "",
        source_address: str = "",
        source_address_format: str = "",
        added_at: float,
    ) -> None:
        with self._connect() as connection:
            connection.execute(
                """
                INSERT INTO migration_sources (
                    classical_address, provider_id, source_network, amount, snapshot_ref, snapshot_hash,
                    source_address, source_address_format, added_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(classical_address) DO UPDATE SET
                    provider_id = excluded.provider_id,
                    source_network = excluded.source_network,
                    amount = excluded.amount,
                    snapshot_ref = excluded.snapshot_ref,
                    snapshot_hash = excluded.snapshot_hash,
                    source_address = excluded.source_address,
                    source_address_format = excluded.source_address_format,
                    added_at = excluded.added_at
                """,
                (
                    classical_address,
                    provider_id,
                    source_network,
                    amount,
                    snapshot_ref,
                    snapshot_hash,
                    source_address,
                    source_address_format,
                    added_at,
                ),
            )

    def import_migration_snapshot(
        self,
        *,
        snapshot_ref: str,
        source_network: str,
        manifest_hash: str,
        entries_root: str,
        entry_count: int,
        total_amount: int,
        generated_at: float,
        imported_at: float,
        entries: list[dict[str, object]],
        signer_address: str = "",
        signer_node_id: str = "",
        signer_signature_scheme: str = "",
        signer_signature_provider: str = "",
    ) -> None:
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            existing = connection.execute(
                """
                SELECT snapshot_ref, source_network, manifest_hash, entries_root, entry_count, total_amount, generated_at,
                       signer_address, signer_node_id, signer_signature_scheme, signer_signature_provider
                FROM migration_snapshots
                WHERE snapshot_ref = ?
                """,
                (snapshot_ref,),
            ).fetchone()
            if existing is not None:
                if (
                    str(existing["source_network"]) != source_network
                    or str(existing["manifest_hash"]) != manifest_hash
                    or str(existing["entries_root"]) != entries_root
                    or int(existing["entry_count"]) != entry_count
                    or int(existing["total_amount"]) != total_amount
                    or float(existing["generated_at"]) != generated_at
                    or str(existing["signer_address"]) != signer_address
                    or str(existing["signer_node_id"]) != signer_node_id
                    or str(existing["signer_signature_scheme"]) != signer_signature_scheme
                    or str(existing["signer_signature_provider"]) != signer_signature_provider
                ):
                    raise ValueError("Migration snapshot_ref already exists with different contents.")
            else:
                connection.execute(
                    """
                    INSERT INTO migration_snapshots (
                        snapshot_ref, source_network, manifest_hash, entries_root, entry_count, total_amount, generated_at, imported_at,
                        signer_address, signer_node_id, signer_signature_scheme, signer_signature_provider
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        snapshot_ref,
                        source_network,
                        manifest_hash,
                        entries_root,
                        entry_count,
                        total_amount,
                        generated_at,
                        imported_at,
                        signer_address,
                        signer_node_id,
                        signer_signature_scheme,
                        signer_signature_provider,
                    ),
                )

            for entry in entries:
                classical_address = str(entry["classical_address"])
                provider_id = str(entry["provider_id"])
                amount = int(entry["amount"])
                existing_source = connection.execute(
                    """
                    SELECT provider_id, source_network, amount, snapshot_ref, snapshot_hash,
                           source_address, source_address_format
                    FROM migration_sources
                    WHERE classical_address = ?
                    """,
                    (classical_address,),
                ).fetchone()
                if existing_source is not None:
                    if (
                        str(existing_source["provider_id"]) != provider_id
                        or str(existing_source["source_network"]) != source_network
                        or int(existing_source["amount"]) != amount
                        or str(existing_source["snapshot_ref"]) != snapshot_ref
                        or str(existing_source["snapshot_hash"]) != manifest_hash
                        or str(existing_source["source_address"]) != str(entry["source_address"])
                        or str(existing_source["source_address_format"]) != str(entry["source_address_format"])
                    ):
                        raise ValueError(
                            f"Migration source '{classical_address}' already exists with different contents."
                        )
                    continue
                connection.execute(
                    """
                    INSERT INTO migration_sources (
                        classical_address, provider_id, source_network, amount, snapshot_ref, snapshot_hash,
                        source_address, source_address_format, added_at
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        classical_address,
                        provider_id,
                        source_network,
                        amount,
                        snapshot_ref,
                        manifest_hash,
                        str(entry["source_address"]),
                        str(entry["source_address_format"]),
                        imported_at,
                    ),
                )
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def migration_source(self, classical_address: str) -> dict[str, object] | None:
        with self._connect() as connection:
            row = connection.execute(
                """
                SELECT classical_address, provider_id, source_network, amount, snapshot_ref, snapshot_hash,
                       source_address, source_address_format, added_at
                FROM migration_sources
                WHERE classical_address = ?
                """,
                (classical_address,),
            ).fetchone()
        if row is None:
            return None
        return {
            "classical_address": str(row["classical_address"]),
            "provider_id": str(row["provider_id"]),
            "source_network": str(row["source_network"]),
            "amount": int(row["amount"]),
            "snapshot_ref": str(row["snapshot_ref"]),
            "snapshot_hash": str(row["snapshot_hash"]),
            "source_address": str(row["source_address"]),
            "source_address_format": str(row["source_address_format"]),
            "added_at": float(row["added_at"]),
        }

    def list_migration_snapshots(self) -> list[dict[str, object]]:
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT snapshot_ref, source_network, manifest_hash, entries_root, entry_count, total_amount, generated_at, imported_at,
                       signer_address, signer_node_id, signer_signature_scheme, signer_signature_provider
                FROM migration_snapshots
                ORDER BY imported_at ASC, snapshot_ref ASC
                """
            ).fetchall()
        return [
            {
                "snapshot_ref": str(row["snapshot_ref"]),
                "source_network": str(row["source_network"]),
                "manifest_hash": str(row["manifest_hash"]),
                "entries_root": str(row["entries_root"]),
                "entry_count": int(row["entry_count"]),
                "total_amount": int(row["total_amount"]),
                "generated_at": float(row["generated_at"]),
                "imported_at": float(row["imported_at"]),
                "signer_address": str(row["signer_address"]),
                "signer_node_id": str(row["signer_node_id"]),
                "signer_signature_scheme": str(row["signer_signature_scheme"]),
                "signer_signature_provider": str(row["signer_signature_provider"]),
            }
            for row in rows
        ]

    def list_migration_sources(self) -> list[dict[str, object]]:
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT source.classical_address,
                       source.provider_id,
                       source.source_network,
                       source.amount,
                       source.snapshot_ref,
                       source.snapshot_hash,
                       source.source_address,
                       source.source_address_format,
                       source.added_at,
                       claim.destination_address,
                       claim.tx_id,
                       claim.claimed_at
                FROM migration_sources AS source
                LEFT JOIN migration_claims AS claim
                    ON claim.classical_address = source.classical_address
                ORDER BY source.classical_address ASC
                """
            ).fetchall()
        items: list[dict[str, object]] = []
        for row in rows:
            items.append(
                {
                    "classical_address": str(row["classical_address"]),
                    "provider_id": str(row["provider_id"]),
                    "source_network": str(row["source_network"]),
                    "amount": int(row["amount"]),
                    "snapshot_ref": str(row["snapshot_ref"]),
                    "snapshot_hash": str(row["snapshot_hash"]),
                    "source_address": str(row["source_address"]),
                    "source_address_format": str(row["source_address_format"]),
                    "added_at": float(row["added_at"]),
                    "claimed": row["tx_id"] is not None,
                    "destination_address": None if row["destination_address"] is None else str(row["destination_address"]),
                    "claim_tx_id": None if row["tx_id"] is None else str(row["tx_id"]),
                    "claimed_at": None if row["claimed_at"] is None else float(row["claimed_at"]),
                }
            )
        return items

    def export_migration_sources(
        self,
        *,
        source_network: str,
        snapshot_ref: str = "",
        include_claimed: bool = False,
    ) -> list[dict[str, object]]:
        query = """
            SELECT source.classical_address,
                   source.provider_id,
                   source.source_network,
                   source.amount,
                   source.snapshot_ref,
                   source.snapshot_hash,
                   source.source_address,
                   source.source_address_format,
                   source.added_at,
                   claim.tx_id
            FROM migration_sources AS source
            LEFT JOIN migration_claims AS claim
                ON claim.classical_address = source.classical_address
            WHERE source.source_network = ?
        """
        parameters: list[object] = [source_network]
        if snapshot_ref:
            query += " AND source.snapshot_ref = ?"
            parameters.append(snapshot_ref)
        if not include_claimed:
            query += " AND claim.tx_id IS NULL"
        query += " ORDER BY source.snapshot_ref ASC, source.classical_address ASC"
        with self._connect() as connection:
            rows = connection.execute(query, tuple(parameters)).fetchall()
        return [
            {
                "classical_address": str(row["classical_address"]),
                "provider_id": str(row["provider_id"]),
                "source_network": str(row["source_network"]),
                "amount": int(row["amount"]),
                "snapshot_ref": str(row["snapshot_ref"]),
                "snapshot_hash": str(row["snapshot_hash"]),
                "source_address": str(row["source_address"]),
                "source_address_format": str(row["source_address_format"]),
                "added_at": float(row["added_at"]),
                "claimed": row["tx_id"] is not None,
            }
            for row in rows
        ]

    def migration_claim(self, classical_address: str) -> dict[str, object] | None:
        with self._connect() as connection:
            row = connection.execute(
                """
                SELECT classical_address, provider_id, source_network, destination_address, amount, tx_id, claimed_at
                FROM migration_claims
                WHERE classical_address = ?
                """,
                (classical_address,),
            ).fetchone()
        if row is None:
            return None
        return {
            "classical_address": str(row["classical_address"]),
            "provider_id": str(row["provider_id"]),
            "source_network": str(row["source_network"]),
            "destination_address": str(row["destination_address"]),
            "amount": int(row["amount"]),
            "tx_id": str(row["tx_id"]),
            "claimed_at": float(row["claimed_at"]),
        }

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
            connection.execute("DELETE FROM migration_claims")
            for block in canonical_blocks:
                for transaction in block.transactions:
                    if transaction.kind != "migration_claim":
                        continue
                    connection.execute(
                        """
                        INSERT OR REPLACE INTO migration_claims (
                            classical_address, provider_id, source_network, destination_address, amount, tx_id, claimed_at
                        )
                        VALUES (?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            str(transaction.metadata.get("classical_address", "")),
                            str(transaction.metadata.get("classical_provider_id", "")),
                            str(transaction.metadata.get("source_network", "")),
                            transaction.outputs[0].recipient if transaction.outputs else "",
                            sum(output.amount for output in transaction.outputs),
                            transaction.tx_id,
                            transaction.timestamp,
                        ),
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

    def peer_identity_count(self, *, status: str | None = None) -> int:
        with self._connect() as connection:
            if status is None:
                row = connection.execute("SELECT COUNT(*) AS count FROM peer_identities").fetchone()
            else:
                row = connection.execute(
                    "SELECT COUNT(*) AS count FROM peer_identities WHERE status = ?",
                    (status,),
                ).fetchone()
        return int(row["count"])

    def peer_session_counts(self) -> dict[str, int]:
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT status, COUNT(*) AS count
                FROM peer_sessions
                GROUP BY status
                """
            ).fetchall()
        return {str(row["status"]): int(row["count"]) for row in rows}

    def summary(self) -> dict[str, object]:
        latest = self.latest_block()
        with self._connect() as connection:
            pending = connection.execute("SELECT COUNT(*) AS count FROM pending_transactions").fetchone()
            pending_bytes = connection.execute("SELECT COALESCE(SUM(size_bytes), 0) AS total FROM pending_transactions").fetchone()
            utxos = connection.execute("SELECT COUNT(*) AS count FROM utxos").fetchone()
            migration_sources = connection.execute("SELECT COUNT(*) AS count FROM migration_sources").fetchone()
            migration_claims = connection.execute("SELECT COUNT(*) AS count FROM migration_claims").fetchone()
        return {
            "height": self.block_count(),
            "pending_transactions": int(pending["count"]),
            "pending_transaction_bytes": int(pending_bytes["total"]),
            "utxo_count": int(utxos["count"]),
            "migration_source_count": int(migration_sources["count"]),
            "migration_claim_count": int(migration_claims["count"]),
            "latest_block_hash": None if latest is None else str(latest["block_hash"]),
            "canonical_work": 0 if latest is None else int(latest["cumulative_work"]),
        }
