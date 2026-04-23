from __future__ import annotations

import json
from pathlib import Path
import secrets
import sqlite3
import time

from .custody import WalletCustodyProvider, build_wallet_custody_provider, WalletCustodyConfig


class SQLiteWalletStateStore:
    _PROTECTED_MARKER = "__protected__"

    def __init__(
        self,
        db_path: Path,
        *,
        custody_provider: WalletCustodyProvider | None = None,
        custody_config: WalletCustodyConfig | None = None,
        reservation_ttl_seconds: int = 60,
    ):
        self.db_path = db_path
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._custody = custody_provider or build_wallet_custody_provider(custody_config or WalletCustodyConfig())
        self._reservation_ttl_seconds = reservation_ttl_seconds
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
            columns = {
                str(row["name"])
                for row in connection.execute("PRAGMA table_info(wallet_keys)").fetchall()
            }
            if "key_state_blob" not in columns:
                connection.execute("ALTER TABLE wallet_keys ADD COLUMN key_state_blob BLOB")
            if "custody_backend" not in columns:
                connection.execute("ALTER TABLE wallet_keys ADD COLUMN custody_backend TEXT")
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS wallet_signing_reservations (
                    reservation_id TEXT PRIMARY KEY,
                    label TEXT NOT NULL,
                    address TEXT NOT NULL,
                    provider_id TEXT NOT NULL,
                    owner_id TEXT NOT NULL,
                    reservation_json TEXT NOT NULL,
                    state_advanced INTEGER NOT NULL,
                    status TEXT NOT NULL,
                    created_at REAL NOT NULL,
                    expires_at REAL NOT NULL,
                    completed_at REAL,
                    last_error TEXT
                );
                CREATE INDEX IF NOT EXISTS idx_wallet_reservation_key
                    ON wallet_signing_reservations(label, address, provider_id, status, expires_at);
                """
            )

    def custody_status(self) -> dict[str, object]:
        return self._custody.status()

    def load_wallet_keys(self, label: str, provider_id: str) -> list[tuple[str, object]]:
        migrated_rows: list[tuple[str, bytes]] = []
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT address, key_state_json, key_state_blob
                FROM wallet_keys
                WHERE label = ? AND provider_id = ?
                ORDER BY address ASC
                """,
                (label, provider_id),
            ).fetchall()
        loaded: list[tuple[str, object]] = []
        for row in rows:
            address = str(row["address"])
            payload_bytes = self._decode_state_row(
                label,
                address,
                provider_id,
                row["key_state_blob"],
                row["key_state_json"],
            )
            if row["key_state_blob"] is None and row["key_state_json"] is not None:
                migrated_rows.append((address, payload_bytes))
            loaded.append((address, json.loads(payload_bytes.decode("utf-8"))))
        for address, payload_bytes in migrated_rows:
            self._persist_protected_bytes(label, address, provider_id, payload_bytes)
        return loaded

    def save_wallet_key(self, label: str, address: str, provider_id: str, key_state: object) -> None:
        payload_bytes = self._encode_state_bytes(key_state)
        self._persist_protected_bytes(label, address, provider_id, payload_bytes)

    def _persist_protected_bytes(self, label: str, address: str, provider_id: str, payload_bytes: bytes) -> None:
        protected_blob = self._custody.protect(
            payload_bytes,
            context=self._custody_context(label, address, provider_id),
        )
        with self._connect() as connection:
            connection.execute(
                """
                INSERT INTO wallet_keys (
                    label,
                    address,
                    provider_id,
                    key_state_json,
                    key_state_blob,
                    custody_backend,
                    state_version
                )
                VALUES (?, ?, ?, ?, ?, ?, 0)
                ON CONFLICT(label, address) DO UPDATE SET
                    provider_id = excluded.provider_id,
                    key_state_json = excluded.key_state_json,
                    key_state_blob = excluded.key_state_blob,
                    custody_backend = excluded.custody_backend,
                    state_version = wallet_keys.state_version + 1
                """,
                (
                    label,
                    address,
                    provider_id,
                    self._PROTECTED_MARKER,
                    sqlite3.Binary(protected_blob),
                    self._custody.backend_id,
                ),
            )

    def reserve_wallet_key_state(
        self,
        label: str,
        address: str,
        provider_id: str,
        reserve_fn,
        *,
        owner_id: str,
        now: float | None = None,
    ) -> tuple[object, object, str]:
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            timestamp = time.time() if now is None else now
            self._expire_completed_reservations(connection, timestamp)
            self._assert_key_is_available(connection, label, address, provider_id, timestamp)
            row = connection.execute(
                """
                SELECT key_state_json, key_state_blob, state_version
                FROM wallet_keys
                WHERE label = ? AND address = ? AND provider_id = ?
                """,
                (label, address, provider_id),
            ).fetchone()
            if row is None:
                raise ValueError(f"No wallet key state found for {label}:{address}.")

            current_state = json.loads(
                self._decode_state_row(
                    label,
                    address,
                    provider_id,
                    row["key_state_blob"],
                    row["key_state_json"],
                ).decode("utf-8")
            )
            current_state_json = self._encode_state_bytes(current_state)
            next_state, reservation = reserve_fn(current_state)
            next_state_json = self._encode_state_bytes(next_state)
            state_advanced = int(next_state_json != current_state_json)
            payload_bytes = self._encode_state_bytes(next_state)
            protected_blob = self._custody.protect(
                payload_bytes,
                context=self._custody_context(label, address, provider_id),
            )
            reservation_id = secrets.token_hex(24)
            connection.execute(
                """
                UPDATE wallet_keys
                SET
                    key_state_json = ?,
                    key_state_blob = ?,
                    custody_backend = ?,
                    state_version = state_version + 1
                WHERE label = ? AND address = ? AND provider_id = ?
                """,
                (
                    self._PROTECTED_MARKER,
                    sqlite3.Binary(protected_blob),
                    self._custody.backend_id,
                    label,
                    address,
                    provider_id,
                ),
            )
            connection.execute(
                """
                INSERT INTO wallet_signing_reservations (
                    reservation_id,
                    label,
                    address,
                    provider_id,
                    owner_id,
                    reservation_json,
                    state_advanced,
                    status,
                    created_at,
                    expires_at,
                    completed_at,
                    last_error
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, 'pending', ?, ?, NULL, NULL)
                """,
                (
                    reservation_id,
                    label,
                    address,
                    provider_id,
                    owner_id,
                    json.dumps(reservation, sort_keys=True, separators=(",", ":")),
                    state_advanced,
                    timestamp,
                    timestamp + self._reservation_ttl_seconds,
                ),
            )
            connection.commit()
            return next_state, reservation, reservation_id
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def complete_wallet_key_reservation(
        self,
        label: str,
        address: str,
        provider_id: str,
        reservation_id: str,
        final_state: object,
        *,
        owner_id: str,
        now: float | None = None,
    ) -> None:
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                """
                SELECT status, owner_id
                FROM wallet_signing_reservations
                WHERE reservation_id = ? AND label = ? AND address = ? AND provider_id = ?
                """,
                (reservation_id, label, address, provider_id),
            ).fetchone()
            if row is None:
                raise ValueError("Wallet signing reservation was not found.")
            if str(row["owner_id"]) != owner_id:
                raise ValueError("Wallet signing reservation owner mismatch.")
            if str(row["status"]) != "pending":
                raise ValueError("Wallet signing reservation is not pending.")

            payload_bytes = self._encode_state_bytes(final_state)
            protected_blob = self._custody.protect(
                payload_bytes,
                context=self._custody_context(label, address, provider_id),
            )
            connection.execute(
                """
                UPDATE wallet_keys
                SET
                    key_state_json = ?,
                    key_state_blob = ?,
                    custody_backend = ?,
                    state_version = state_version + 1
                WHERE label = ? AND address = ? AND provider_id = ?
                """,
                (
                    self._PROTECTED_MARKER,
                    sqlite3.Binary(protected_blob),
                    self._custody.backend_id,
                    label,
                    address,
                    provider_id,
                ),
            )
            connection.execute(
                """
                UPDATE wallet_signing_reservations
                SET status = 'completed', completed_at = ?, last_error = NULL
                WHERE reservation_id = ?
                """,
                (time.time() if now is None else now, reservation_id),
            )
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def fail_wallet_key_reservation(
        self,
        label: str,
        address: str,
        provider_id: str,
        reservation_id: str,
        *,
        owner_id: str,
        error_message: str,
        now: float | None = None,
    ) -> None:
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                """
                SELECT status, owner_id
                FROM wallet_signing_reservations
                WHERE reservation_id = ? AND label = ? AND address = ? AND provider_id = ?
                """,
                (reservation_id, label, address, provider_id),
            ).fetchone()
            if row is None:
                raise ValueError("Wallet signing reservation was not found.")
            if str(row["owner_id"]) != owner_id:
                raise ValueError("Wallet signing reservation owner mismatch.")
            if str(row["status"]) != "pending":
                return
            connection.execute(
                """
                UPDATE wallet_signing_reservations
                SET status = 'failed', completed_at = ?, last_error = ?
                WHERE reservation_id = ?
                """,
                (time.time() if now is None else now, error_message[:512], reservation_id),
            )
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def has_pending_reservation(self, label: str, address: str, provider_id: str) -> bool:
        with self._connect() as connection:
            row = connection.execute(
                """
                SELECT 1
                FROM wallet_signing_reservations
                WHERE label = ? AND address = ? AND provider_id = ? AND status = 'pending'
                LIMIT 1
                """,
                (label, address, provider_id),
            ).fetchone()
        return row is not None

    def reservation_status_counts(self) -> dict[str, int]:
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT status, COUNT(*) AS count
                FROM wallet_signing_reservations
                GROUP BY status
                """
            ).fetchall()
        return {str(row["status"]): int(row["count"]) for row in rows}

    @staticmethod
    def _encode_state_bytes(key_state: object) -> bytes:
        return json.dumps(key_state, sort_keys=True, separators=(",", ":")).encode("utf-8")

    def _decode_state_row(
        self,
        label: str,
        address: str,
        provider_id: str,
        key_state_blob: object,
        legacy_json: object,
    ) -> bytes:
        if key_state_blob is not None:
            raw = bytes(key_state_blob)
            return self._custody.unprotect(
                raw,
                context=self._custody_context(label, address, provider_id),
            )
        if legacy_json is not None:
            return str(legacy_json).encode("utf-8")
        raise ValueError(f"Wallet key state for {label}:{address} is missing.")

    @staticmethod
    def _custody_context(label: str, address: str, provider_id: str) -> dict[str, object]:
        return {
            "purpose": "wallet_key_state_v1",
            "label": label,
            "address": address,
            "provider_id": provider_id,
        }

    @staticmethod
    def _expire_completed_reservations(connection: sqlite3.Connection, now: float) -> None:
        connection.execute(
            """
            UPDATE wallet_signing_reservations
            SET status = CASE
                WHEN status = 'pending' AND expires_at <= ? AND state_advanced = 1 THEN 'expired'
                WHEN status = 'pending' AND expires_at <= ? AND state_advanced = 0 THEN 'requires_recovery'
                ELSE status
            END,
            completed_at = CASE
                WHEN status = 'pending' AND expires_at <= ? THEN ?
                ELSE completed_at
            END
            WHERE status = 'pending'
            """,
            (now, now, now, now),
        )

    @staticmethod
    def _assert_key_is_available(
        connection: sqlite3.Connection,
        label: str,
        address: str,
        provider_id: str,
        now: float,
    ) -> None:
        row = connection.execute(
            """
            SELECT reservation_id, status, state_advanced, expires_at
            FROM wallet_signing_reservations
            WHERE label = ? AND address = ? AND provider_id = ?
              AND status IN ('pending', 'requires_recovery')
            ORDER BY created_at DESC
            LIMIT 1
            """,
            (label, address, provider_id),
        ).fetchone()
        if row is None:
            return
        status = str(row["status"])
        if status == "requires_recovery":
            raise ValueError(
                "Wallet key has an interrupted signing reservation that requires operator recovery before reuse."
            )
        if float(row["expires_at"]) > now:
            raise ValueError("Wallet key already has an active signing reservation.")
