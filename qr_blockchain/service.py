from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import sqlite3
import secrets
import time

from .auth import NodeIdentityManager, request_claims_digest, verify_signed_envelope
from .config import NodeConfig
from .crypto import get_signature_provider, get_signature_verifier, list_signature_provider_statuses
from .custody import WalletCustodyConfig
from .legacy_networks import (
    describe_legacy_network,
    list_legacy_network_profiles,
    validate_legacy_source_binding,
)
from .migration import (
    classical_claim_message_bytes,
    destination_acceptance_message_bytes,
    get_classical_claim_verifier,
    list_classical_claim_verifier_statuses,
)
from .models import Block, Transaction, TxInput, TxOutput
from .network import fetch_json, normalize_peer_url, with_path
from .protocol import build_peer_frame, parse_peer_frame
from .snapshot import (
    MigrationSnapshotEntry,
    MigrationSnapshotBundle,
    parse_snapshot_import_payload,
    snapshot_manifest_claims,
    validate_snapshot_bundle,
)
from .source_ingestion import (
    build_source_ingestion_runbook,
    build_ingestion_approval,
    normalize_source_export,
    normalize_source_export_batch,
    validate_ingestion_approval,
    validate_ingestion_manifest,
)
from .storage import SQLiteChainStore
from .wallet_store import SQLiteWalletStateStore


class NodeService:
    def __init__(self, config: NodeConfig):
        self.config = config
        self.store = SQLiteChainStore(config.db_path)
        self.wallet_state_store = SQLiteWalletStateStore(
            config.wallet_state_db_path,
            custody_config=WalletCustodyConfig(
                mode=config.wallet_custody_mode,
                scope=config.wallet_custody_scope,
            ),
            reservation_ttl_seconds=config.wallet_reservation_ttl_seconds,
        )
        self.identity = NodeIdentityManager(config, config.default_signature_provider, config.wallet_state_db_path)
        for peer in config.peers:
            self.store.add_peer(normalize_peer_url(peer))

    def create_genesis_block(self, initial_allocations: dict[str, int]) -> Block:
        if self.store.best_head_hash() is not None:
            raise ValueError("Genesis block already exists.")

        genesis_outputs = [
            TxOutput(recipient=address, amount=amount)
            for address, amount in initial_allocations.items()
            if amount > 0
        ]
        if not genesis_outputs:
            raise ValueError("Genesis block must contain at least one positive allocation.")

        genesis_transaction = Transaction(
            inputs=[],
            outputs=genesis_outputs,
            chain_id=self.config.chain_id,
            signature_scheme=self.config.default_signature_provider,
            timestamp=0.0,
            fee=0,
        )
        genesis_transaction.finalize()

        block = Block(
            index=0,
            previous_hash="0" * 64,
            transactions=[genesis_transaction],
            miner="genesis",
            difficulty=1,
            chain_id=self.config.chain_id,
            version=2,
            timestamp=0.0,
        )
        block.mine()
        self.store.store_block(block)
        self.store.apply_best_chain(block.block_hash)
        return block

    def submit_transaction(self, transaction: Transaction) -> None:
        self._enforce_mempool_policy(transaction)
        self._validate_transaction_against_view(
            transaction,
            self.store.all_utxos(),
            effective_height=self.store.block_count(),
        )
        self._check_pending_double_spends(transaction)
        try:
            self.store.save_pending_transaction(transaction)
        except sqlite3.IntegrityError as error:
            raise ValueError("Transaction is already pending.") from error

    def mine_pending_transactions(self, miner_address: str) -> Block:
        latest = self.store.latest_block()
        if latest is None:
            raise ValueError("Create a genesis block before mining.")

        pending = self.store.pending_transactions()[: self.config.max_transactions_per_block]
        reward = sum(transaction.fee for transaction in pending) + self.config.mining_reward
        reward_transaction = Transaction(
            inputs=[],
            outputs=[TxOutput(recipient=miner_address, amount=reward)],
            chain_id=self.config.chain_id,
            signature_scheme=self.config.default_signature_provider,
            fee=0,
        )
        reward_transaction.finalize()

        block = Block(
            index=int(latest["height"]) + 1,
            previous_hash=str(latest["block_hash"]),
            transactions=[reward_transaction, *pending],
            miner=miner_address,
            difficulty=self.config.difficulty,
            chain_id=self.config.chain_id,
            version=2,
        )
        block.mine()
        self.import_block(block)
        return block

    def import_block(self, block: Block) -> None:
        self.validate_block(block)
        if self.store.has_block(block.block_hash):
            return
        self.store.store_block(block)
        self._select_best_chain(block.block_hash)

    def validate_block(self, block: Block) -> None:
        latest = self.store.latest_block()
        if block.chain_id != self.config.chain_id:
            raise ValueError("Block belongs to a different chain.")
        if block.compute_hash() != block.block_hash:
            raise ValueError("Block hash mismatch.")
        if not block.block_hash.startswith("0" * block.difficulty):
            raise ValueError("Block does not satisfy proof-of-work difficulty.")
        if block.version < 2:
            raise ValueError("Unsupported block version.")
        if not block.transactions:
            raise ValueError("Block must include at least one transaction.")
        if self.store.has_block(block.block_hash):
            raise ValueError("Block is already stored.")

        if block.index == 0:
            if latest is not None:
                raise ValueError("Genesis block already exists.")
            if block.previous_hash != "0" * 64:
                raise ValueError("Genesis block previous hash mismatch.")
            if any(transaction.chain_id != self.config.chain_id for transaction in block.transactions):
                raise ValueError("Genesis block contains a transaction for a different chain.")
            for transaction in block.transactions:
                self._validate_transaction_against_view(transaction, {}, effective_height=0)
            return

        parent_row = self.store.block_row(block.previous_hash)
        if parent_row is None:
            raise ValueError("Block parent is unknown.")
        parent_height = int(parent_row["height"])
        if block.index != parent_height + 1:
            raise ValueError("Unexpected block height.")

        if block.transactions[0].inputs:
            raise ValueError("First block transaction must be the reward transaction.")

        utxo_view = self.store.utxos_for_head(block.previous_hash)
        claimed_view = self.store.claimed_classical_addresses_for_head(block.previous_hash)
        spent_in_block: set[tuple[str, int]] = set()
        claimed_in_block: set[str] = set()
        fee_total = 0

        for index, transaction in enumerate(block.transactions):
            self._validate_transaction_against_view(
                transaction,
                utxo_view,
                effective_height=block.index,
                claimed_classical_addresses=claimed_view | claimed_in_block,
            )
            if index == 0:
                continue
            fee_total += transaction.fee
            if transaction.kind == "migration_claim":
                classical_address = str(transaction.metadata.get("classical_address", ""))
                if classical_address in claimed_in_block:
                    raise ValueError("Block contains a duplicate migration claim.")
                claimed_in_block.add(classical_address)
                for output_index, output in enumerate(transaction.outputs):
                    utxo_view[(transaction.tx_id, output_index)] = output
                continue
            for tx_input in transaction.inputs:
                key = (tx_input.prev_tx_id, tx_input.output_index)
                if key in spent_in_block:
                    raise ValueError("Block contains a double spend.")
                spent_in_block.add(key)
                utxo_view.pop(key, None)
            for output_index, output in enumerate(transaction.outputs):
                utxo_view[(transaction.tx_id, output_index)] = output

        reward_transaction = block.transactions[0]
        expected_reward = self.config.mining_reward + fee_total
        actual_reward = sum(output.amount for output in reward_transaction.outputs)
        if actual_reward != expected_reward:
            raise ValueError("Reward transaction amount is invalid.")

    def sync_with_peer(self, peer_url: str) -> int:
        normalized = normalize_peer_url(peer_url)
        session = self.ensure_peer_admission(normalized)
        summary = fetch_json(
            with_path(normalized, "/peer/summary"),
            method="POST",
            payload=self._build_peer_request_frame(
                message_type="peer_summary_request",
                payload={},
                auth=self.build_peer_session_envelope(
                    "peer_summary_v2",
                    normalized,
                    session["session_id"],
                    "/peer/summary",
                ),
            ),
        )
        summary_payload = self._parse_peer_response_frame(summary, "peer_summary_response")
        remote_height = int(summary_payload.get("height", 0))
        local_height = self.store.block_count()
        imported = 0
        if remote_height <= local_height:
            self.store.add_peer(normalized)
            return imported

        response = fetch_json(
            with_path(normalized, "/peer/blocks"),
            method="POST",
            payload=self._build_peer_request_frame(
                message_type="peer_blocks_request",
                payload={"start_height": local_height},
                auth=self.build_peer_session_envelope(
                    "peer_blocks_v2",
                    normalized,
                    session["session_id"],
                    "/peer/blocks",
                    {"start_height": local_height},
                ),
            ),
        )
        response_payload = self._parse_peer_response_frame(response, "peer_blocks_response")
        for item in response_payload.get("blocks", []):
            block = Block.from_dict(item)
            self.import_block(block)
            imported += 1

        self.store.add_peer(normalized)
        return imported

    def sync_with_peers(self) -> dict[str, int]:
        results: dict[str, int] = {}
        for peer in self.list_peers():
            results[peer] = self.sync_with_peer(peer)
        return results

    def register_peer(self, peer_url: str) -> str:
        normalized = normalize_peer_url(peer_url)
        self.store.add_peer(normalized)
        return normalized

    def build_signed_envelope(self, purpose: str, claims: dict[str, object]) -> dict[str, object]:
        return self.identity.sign_claims(purpose, claims)

    def build_peer_session_envelope(
        self,
        purpose: str,
        peer_url: str,
        session_id: str,
        request_path: str,
        request_claims: dict[str, object] | None = None,
    ) -> dict[str, object]:
        normalized = normalize_peer_url(peer_url)
        claims = {
            "target_url": normalized,
            "session_id": session_id,
            "request_method": "POST",
            "request_path": request_path,
            "request_payload_hash": request_claims_digest(request_claims or {}),
        }
        return self.build_signed_envelope(purpose, claims)

    def local_peer_identity(self) -> dict[str, object]:
        return self.identity.public_identity()

    def ensure_peer_admission(self, peer_url: str) -> dict[str, object]:
        normalized = normalize_peer_url(peer_url)
        record = self.store.peer_identity_by_url(normalized)
        if record is not None and record["status"] == "admitted":
            session = self.store.active_peer_session_for_node(str(record["node_id"]), time.time())
            if session is not None:
                return session

        request_envelope = self.build_signed_envelope("peer_handshake_v2", {"target_url": normalized})
        response = fetch_json(
            with_path(normalized, "/peer/handshake"),
            method="POST",
            payload=self._build_peer_request_frame(
                message_type="peer_handshake_request",
                payload={},
                auth=request_envelope,
            ),
        )
        response_payload, response_envelope = parse_peer_frame(
            response,
            expected_protocol_version=self.config.peer_protocol_version,
            expected_message_type="peer_handshake_response",
        )
        peer_identity = verify_signed_envelope(
            response_envelope,
            expected_purpose="peer_handshake_ack_v2",
            expected_chain_id=self.config.chain_id,
            time_skew_seconds=self.config.auth_time_skew_seconds,
        )
        claims = peer_identity["claims"]
        if response_payload.get("node_id") != peer_identity["node_id"]:
            raise ValueError("Peer handshake response node id does not match signed identity.")
        if claims.get("target_url") != normalize_peer_url(self.config.advertised_url):
            raise ValueError("Peer handshake ack target does not match this node.")
        session_id = str(claims.get("session_id", ""))
        if not session_id:
            raise ValueError("Peer handshake ack did not include a session id.")
        session_expires_at = float(claims.get("session_expires_at", 0))
        if session_expires_at <= time.time():
            raise ValueError("Peer session already expired.")
        self._admit_peer(peer_identity)
        self.store.expire_peer_sessions_for_node(peer_identity["node_id"])
        self.store.upsert_peer_session(
            session_id=session_id,
            node_id=peer_identity["node_id"],
            url=normalized,
            created_at=time.time(),
            last_seen=time.time(),
            expires_at=session_expires_at,
            status="active",
        )
        session = self.store.peer_session(session_id)
        if session is None:
            raise ValueError("Failed to persist peer session.")
        return session

    def accept_peer_handshake(self, envelope: dict[str, object]) -> dict[str, object]:
        peer_identity = self._authenticate_peer_envelope(
            envelope,
            expected_purpose="peer_handshake_v2",
            require_existing_peer=False,
            require_session=False,
        )
        self._admit_peer(peer_identity)
        session = self._issue_peer_session(peer_identity)
        return self._build_peer_response_frame(
            message_type="peer_handshake_response",
            payload={
                "node_id": self.config.node_id,
                "session_id": session["session_id"],
                "session_expires_at": int(session["expires_at"]),
            },
            auth=self.build_signed_envelope(
                "peer_handshake_ack_v2",
                {
                    "target_url": peer_identity["advertised_url"],
                    "session_id": session["session_id"],
                    "session_expires_at": int(session["expires_at"]),
                },
            ),
        )

    def authenticated_chain_summary(self, envelope: dict[str, object]) -> dict[str, object]:
        self._authenticate_peer_envelope(
            envelope,
            expected_purpose="peer_summary_v2",
            request_path="/peer/summary",
        )
        return self._build_peer_response_frame(
            message_type="peer_summary_response",
            payload=self.chain_summary(),
        )

    def authenticated_blocks(self, envelope: dict[str, object], start_height: int) -> dict[str, object]:
        if start_height < 0:
            raise ValueError("Peer block request start height is invalid.")
        self._authenticate_peer_envelope(
            envelope,
            expected_purpose="peer_blocks_v2",
            request_path="/peer/blocks",
            request_claims={"start_height": start_height},
        )
        blocks = self.get_blocks_from_height(start_height)[: self.config.max_peer_blocks_per_request]
        return self._build_peer_response_frame(
            message_type="peer_blocks_response",
            payload={"blocks": [block.to_dict() for block in blocks]},
        )

    def list_peers(self) -> list[str]:
        stored = set(self.store.list_peers())
        stored.update(normalize_peer_url(peer) for peer in self.config.peers)
        return sorted(stored)

    def get_blocks_from_height(self, start_height: int) -> list[Block]:
        return self.store.blocks_from_height(start_height)

    def get_block(self, height: int) -> Block | None:
        return self.store.block_at_height(height)

    def balance_for_address(self, address: str) -> int:
        return sum(output.amount for _, _, output in self.store.list_utxos([address]))

    def balance_for_addresses(self, addresses: list[str]) -> int:
        return sum(output.amount for _, _, output in self.store.list_utxos(addresses))

    def list_utxos(self, addresses: list[str]) -> list[tuple[str, int, TxOutput]]:
        return self.store.list_utxos(addresses)

    def chain_summary(self) -> dict[str, object]:
        summary = self.store.summary()
        summary["chain_id"] = self.config.chain_id
        summary["node_id"] = self.config.node_id
        summary["peer_count"] = len(self.list_peers())
        summary["advertised_url"] = normalize_peer_url(self.config.advertised_url)
        summary["best_head_hash"] = self.store.best_head_hash()
        return summary

    def migration_policy(self, height: int | None = None) -> dict[str, object]:
        effective_height = self.store.block_count() if height is None else height
        dual_control_required = self._migration_dual_control_required(effective_height)
        claims_open = self._height_in_window(
            effective_height,
            self.config.migration_claim_start_height,
            self.config.migration_claim_end_height,
        )
        return {
            "effective_height": effective_height,
            "claims_open": claims_open,
            "claim_start_height": self.config.migration_claim_start_height,
            "claim_end_height": self.config.migration_claim_end_height,
            "dual_control_required": dual_control_required,
            "dual_control_start_height": self.config.migration_dual_control_start_height,
            "dual_control_end_height": self.config.migration_dual_control_end_height,
            "allowed_classical_providers": list(self.config.migration_allowed_classical_providers),
            "require_snapshot_signatures": self.config.migration_require_snapshot_signatures,
            "trusted_snapshot_signers": list(self.config.migration_trusted_snapshot_signers),
            "trusted_snapshot_nodes": list(self.config.migration_trusted_snapshot_nodes),
        }

    def migration_network_profiles(self) -> dict[str, object]:
        return {
            "profiles": list_legacy_network_profiles(),
        }

    @staticmethod
    def _validate_migration_status(status: str) -> str:
        normalized = status.strip().lower()
        if normalized not in {"active", "quarantined", "revoked"}:
            raise ValueError("Migration status must be one of: active, quarantined, revoked.")
        return normalized

    def signature_provider_statuses(self) -> dict[str, object]:
        providers = list_signature_provider_statuses()
        return {
            "default_signature_provider": self.config.default_signature_provider,
            "provider_policy": self.signature_provider_policy(),
            "wallet_custody": self.identity.custody_status(),
            "wallet_reservation_status": self.identity.reservation_status_counts(),
            "peer_protocol_version": self.config.peer_protocol_version,
            "providers": providers,
            "migration_providers": list_classical_claim_verifier_statuses(),
        }

    def signature_provider_policy(self) -> dict[str, object]:
        provider_statuses = {item["provider_id"]: item for item in list_signature_provider_statuses()}
        allowed = list(self.config.allowed_signature_providers)
        preferred = list(self.config.preferred_signature_providers)
        candidates = preferred or list(provider_statuses.keys())
        if allowed:
            candidates = [provider_id for provider_id in candidates if provider_id in allowed]
        recommended = next(
            (
                provider_id
                for provider_id in candidates
                if provider_statuses.get(provider_id, {}).get("available", False)
            ),
            None,
        )
        recommended_stateless = next(
            (
                provider_id
                for provider_id in candidates
                if provider_statuses.get(provider_id, {}).get("available", False)
                and not provider_statuses.get(provider_id, {}).get("supports_stateful_signing", True)
            ),
            recommended,
        )
        return {
            "allowed_signature_providers": allowed,
            "preferred_signature_providers": preferred,
            "recommended_signature_provider": recommended,
            "recommended_stateless_provider": recommended_stateless,
        }

    def wallet_key_statuses(
        self,
        *,
        label: str | None = None,
        provider_id: str | None = None,
    ) -> dict[str, object]:
        statuses = self.wallet_state_store.wallet_key_statuses(label=label, provider_id=provider_id)
        return {
            "wallet_keys": statuses,
            "reservation_status": self.wallet_state_store.reservation_status_counts(),
            "wallet_custody": self.wallet_state_store.custody_status(),
        }

    def recover_wallet_key(
        self,
        label: str,
        address: str,
        provider_id: str,
        *,
        note: str = "operator acknowledged interrupted signer reservation",
    ) -> dict[str, object]:
        return self.wallet_state_store.recover_wallet_key(
            label,
            address,
            provider_id,
            note=note,
        )

    def operational_status(self) -> dict[str, object]:
        chain = self.chain_summary()
        provider_statuses = list_signature_provider_statuses()
        migration_provider_statuses = list_classical_claim_verifier_statuses()
        reservation_counts = self.wallet_state_store.reservation_status_counts()
        peer_session_counts = self.store.peer_session_counts()
        default_provider_unavailable = [
            item["provider_id"]
            for item in provider_statuses
            if item["provider_id"] == self.config.default_signature_provider and not item.get("available", False)
        ]
        requires_recovery = int(reservation_counts.get("requires_recovery", 0))
        health = "ok"
        reasons: list[str] = []
        if default_provider_unavailable:
            health = "degraded"
            reasons.append("the configured default PQ provider is not available")
        if requires_recovery:
            health = "degraded"
            reasons.append("one or more wallet keys require signer recovery")
        return {
            "status": health,
            "reasons": reasons,
            "chain": chain,
            "wallet_custody": self.wallet_state_store.custody_status(),
            "wallet_reservation_status": reservation_counts,
            "providers": {
                "default_signature_provider": self.config.default_signature_provider,
                "policy": self.signature_provider_policy(),
                "unavailable_provider_ids": [
                    item["provider_id"] for item in provider_statuses if not item.get("available", False)
                ],
                "migration_provider_ids": [item["provider_id"] for item in migration_provider_statuses],
            },
            "migration_policy": self.migration_policy(chain["height"]),
            "migration_snapshots": {
                "count": len(self.store.list_migration_snapshots()),
                "signature_required": self.config.migration_require_snapshot_signatures,
                "quarantined": sum(1 for item in self.store.list_migration_snapshots() if item["status"] == "quarantined"),
                "revoked": sum(1 for item in self.store.list_migration_snapshots() if item["status"] == "revoked"),
            },
            "peers": {
                "configured": len(self.config.peers),
                "known": len(self.list_peers()),
                "admitted": self.store.peer_identity_count(status="admitted"),
                "sessions": peer_session_counts,
            },
        }

    def metrics_snapshot(self) -> dict[str, object]:
        chain = self.chain_summary()
        peer_session_counts = self.store.peer_session_counts()
        provider_statuses = list_signature_provider_statuses()
        active_provider_statuses = [item for item in provider_statuses if item.get("status") != "planned"]
        available_provider_count = sum(1 for item in active_provider_statuses if item.get("available", False))
        return {
            "chain_height": int(chain["height"]),
            "canonical_work": int(chain["canonical_work"]),
            "pending_transactions": int(chain["pending_transactions"]),
            "pending_transaction_bytes": int(chain.get("pending_transaction_bytes", 0)),
            "utxo_count": int(chain["utxo_count"]),
            "migration_source_count": int(chain.get("migration_source_count", 0)),
            "migration_claim_count": int(chain.get("migration_claim_count", 0)),
            "migration_snapshot_count": len(self.store.list_migration_snapshots()),
            "peer_count": len(self.list_peers()),
            "admitted_peer_count": self.store.peer_identity_count(status="admitted"),
            "active_peer_sessions": int(peer_session_counts.get("active", 0)),
            "expired_peer_sessions": int(peer_session_counts.get("expired", 0)),
            "wallet_key_count": len(self.wallet_state_store.wallet_key_statuses()),
            "wallet_reservation_status": self.wallet_state_store.reservation_status_counts(),
            "available_provider_count": available_provider_count,
            "configured_provider_count": len(active_provider_statuses),
            "migration_provider_count": len(list_classical_claim_verifier_statuses()),
        }

    def _validate_migration_source_binding(
        self,
        *,
        classical_address: str,
        provider_id: str,
        source_network: str,
        source_address: str,
        source_address_format: str,
    ) -> dict[str, object]:
        if not source_network:
            raise ValueError("source_network is required.")
        source_address_value = source_address or classical_address
        return validate_legacy_source_binding(
            source_network=source_network,
            provider_id=provider_id,
            classical_address=classical_address,
            source_address=source_address_value,
            source_address_format=source_address_format,
        )

    def seed_migration_source(
        self,
        *,
        classical_address: str,
        provider_id: str,
        source_network: str,
        amount: int,
        snapshot_ref: str = "",
        source_address: str = "",
        source_address_format: str = "",
    ) -> dict[str, object]:
        if not classical_address:
            raise ValueError("classical_address is required.")
        if amount <= 0:
            raise ValueError("migration source amount must be positive.")
        get_classical_claim_verifier(provider_id)
        binding = self._validate_migration_source_binding(
            classical_address=classical_address,
            provider_id=provider_id,
            source_network=source_network,
            source_address=source_address,
            source_address_format=source_address_format,
        )
        reviewed_at = time.time()
        self.store.ensure_migration_snapshot_stub(
            snapshot_ref=snapshot_ref,
            source_network=source_network,
            imported_at=reviewed_at,
            reviewed_at=reviewed_at,
        )
        self.store.add_migration_source(
            classical_address=classical_address,
            provider_id=provider_id,
            source_network=source_network,
            amount=amount,
            snapshot_ref=snapshot_ref,
            source_address=str(binding["source_address"]),
            source_address_format=str(binding["source_address_format"]),
            reviewed_at=reviewed_at,
            added_at=reviewed_at,
        )
        source = self.store.migration_source(classical_address)
        if source is None:
            raise ValueError("Failed to store migration source.")
        return source

    def import_migration_snapshot(self, payload: dict[str, object]) -> dict[str, object]:
        bundle, envelope = parse_snapshot_import_payload(payload)
        allowed = set(self.config.migration_allowed_classical_providers)
        for entry in bundle.entries:
            if allowed and entry.provider_id not in allowed:
                raise ValueError(
                    f"Migration snapshot entry provider '{entry.provider_id}' is not allowed by node policy."
                )
            self._validate_migration_source_binding(
                classical_address=entry.classical_address,
                provider_id=entry.provider_id,
                source_network=bundle.source_network,
                source_address=entry.source_address,
                source_address_format=entry.source_address_format,
            )
        signer_metadata = {
            "signer_address": "",
            "signer_node_id": "",
            "signer_signature_scheme": "",
            "signer_signature_provider": "",
        }
        if envelope is None and self.config.migration_require_snapshot_signatures:
            raise ValueError("Migration snapshot imports require a signed snapshot envelope by node policy.")
        if envelope is not None:
            verified = verify_signed_envelope(
                envelope,
                expected_purpose="migration_snapshot_manifest_v1",
                expected_chain_id=self.config.chain_id,
                time_skew_seconds=None,
            )
            claims = snapshot_manifest_claims(bundle)
            envelope_claims = dict(envelope.get("claims", {}))
            for key, value in claims.items():
                if envelope_claims.get(key) != value:
                    raise ValueError(f"Migration snapshot signed claim mismatch for '{key}'.")
            signer_metadata = {
                "signer_address": str(verified["address"]),
                "signer_node_id": str(verified["node_id"]),
                "signer_signature_scheme": str(verified["signature_scheme"]),
                "signer_signature_provider": str(verified["signature_provider"]),
            }
            if self.config.migration_trusted_snapshot_signers and signer_metadata["signer_address"] not in set(
                self.config.migration_trusted_snapshot_signers
            ):
                raise ValueError("Migration snapshot signer address is not trusted by node policy.")
            if self.config.migration_trusted_snapshot_nodes and signer_metadata["signer_node_id"] not in set(
                self.config.migration_trusted_snapshot_nodes
            ):
                raise ValueError("Migration snapshot signer node_id is not trusted by node policy.")
        finalized = bundle.to_dict()
        self.store.import_migration_snapshot(
            snapshot_ref=bundle.snapshot_ref,
            source_network=bundle.source_network,
            manifest_hash=str(finalized["manifest_hash"]),
            entries_root=str(finalized["entries_root"]),
            entry_count=int(finalized["entry_count"]),
            total_amount=int(finalized["total_amount"]),
            generated_at=float(bundle.generated_at),
            imported_at=time.time(),
            entries=[dict(item) for item in finalized["entries"]],
            signer_address=signer_metadata["signer_address"],
            signer_node_id=signer_metadata["signer_node_id"],
            signer_signature_scheme=signer_metadata["signer_signature_scheme"],
            signer_signature_provider=signer_metadata["signer_signature_provider"],
        )
        snapshots = self.store.list_migration_snapshots()
        return next(item for item in snapshots if item["snapshot_ref"] == bundle.snapshot_ref)

    def normalize_source_export_snapshot(self, payload: dict[str, object], *, sign: bool = False) -> dict[str, object]:
        normalized = normalize_source_export(payload)
        bundle = normalized["bundle"]
        result: dict[str, object] = {
            "bundle": bundle.to_dict(),  # type: ignore[union-attr]
            "ingestion_manifest": normalized["ingestion_manifest"],
            "source_count": len(bundle.entries),  # type: ignore[union-attr]
            "source_network_profile": describe_legacy_network(bundle.source_network),  # type: ignore[union-attr]
        }
        if sign:
            result["envelope"] = self.identity.sign_claims(
                "migration_snapshot_manifest_v1",
                snapshot_manifest_claims(bundle),  # type: ignore[arg-type]
            )
        return result

    def normalize_source_export_batch(self, payloads: list[dict[str, object]]) -> dict[str, object]:
        return normalize_source_export_batch(payloads)

    def source_ingestion_runbook(self, normalized_payload: dict[str, object]) -> dict[str, object]:
        return build_source_ingestion_runbook(normalized_payload)

    def source_ingestion_manifest_status(self, normalized_payload: dict[str, object]) -> dict[str, object]:
        return validate_ingestion_manifest(normalized_payload)

    def approve_source_ingestion(
        self,
        normalized_payload: dict[str, object],
        *,
        operator: str,
        decision: str,
        reason: str,
    ) -> dict[str, object]:
        return build_ingestion_approval(
            normalized_payload,
            operator=operator,
            decision=decision,
            reason=reason,
        )

    def source_ingestion_import_plan(
        self,
        normalized_payload: dict[str, object],
        *,
        approval: dict[str, object] | None = None,
    ) -> dict[str, object]:
        manifest_status = self.source_ingestion_manifest_status(normalized_payload)
        reconciliation = self.reconcile_migration_snapshot(normalized_payload)
        approval_status = {"accepted": approval is None, "checks": []}
        if approval is not None:
            approval_status = validate_ingestion_approval(normalized_payload, approval)
        blockers = []
        if not manifest_status["valid"]:
            blockers.append("ingestion_manifest_invalid")
        if approval is not None and not approval_status["accepted"]:
            blockers.append("approval_invalid")
        if reconciliation["summary"]["changed"]:
            blockers.append("existing_sources_would_change")
        if reconciliation["summary"]["review_conflicts"]:
            blockers.append("review_conflicts")
        return {
            "ready": not blockers,
            "blockers": blockers,
            "manifest_status": manifest_status,
            "approval_status": approval_status,
            "reconciliation": reconciliation,
            "actions": {
                "would_import": reconciliation["summary"]["would_add"],
                "would_skip_unchanged": reconciliation["summary"]["unchanged"],
                "would_block_changed": reconciliation["summary"]["changed"],
            },
        }

    def import_approved_source_ingestion(
        self,
        normalized_payload: dict[str, object],
        *,
        approval: dict[str, object],
    ) -> dict[str, object]:
        plan = self.source_ingestion_import_plan(normalized_payload, approval=approval)
        if not plan["ready"]:
            raise ValueError("Source ingestion import plan is blocked.")
        imported = self.import_migration_snapshot(normalized_payload)
        return {
            "imported": imported,
            "plan": plan,
            "approval": approval,
            "rollback_evidence": {
                "snapshot_ref": imported["snapshot_ref"],
                "manifest_hash": imported["manifest_hash"],
                "entries_root": imported["entries_root"],
                "entry_count": imported["entry_count"],
                "status_reversal": {
                    "endpoint": "/migration/snapshots/status",
                    "status": "quarantined",
                    "reason": "rollback requested after approved source ingestion",
                    "cascade_sources": True,
                },
            },
            "post_import_audit_report": self.migration_audit_report(source_network=str(imported["source_network"])),
        }

    def list_migration_snapshots(self) -> list[dict[str, object]]:
        return self.store.list_migration_snapshots()

    def set_migration_snapshot_status(
        self,
        snapshot_ref: str,
        *,
        status: str,
        reason: str,
        cascade_sources: bool = True,
    ) -> dict[str, object]:
        normalized = self._validate_migration_status(status)
        if normalized != "active" and not reason.strip():
            raise ValueError("A reason is required when quarantining or revoking a migration snapshot.")
        return self.store.set_migration_snapshot_status(
            snapshot_ref,
            status=normalized,
            reason=reason.strip(),
            reviewed_at=time.time(),
            cascade_sources=cascade_sources,
        )

    def set_migration_source_status(
        self,
        classical_address: str,
        *,
        status: str,
        reason: str,
    ) -> dict[str, object]:
        normalized = self._validate_migration_status(status)
        if normalized != "active" and not reason.strip():
            raise ValueError("A reason is required when quarantining or revoking a migration source.")
        return self.store.set_migration_source_status(
            classical_address,
            status=normalized,
            reason=reason.strip(),
            reviewed_at=time.time(),
        )

    def sign_migration_snapshot(self, payload: dict[str, object]) -> dict[str, object]:
        bundle = validate_snapshot_bundle(MigrationSnapshotBundle.from_dict(payload))
        for entry in bundle.entries:
            self._validate_migration_source_binding(
                classical_address=entry.classical_address,
                provider_id=entry.provider_id,
                source_network=bundle.source_network,
                source_address=entry.source_address,
                source_address_format=entry.source_address_format,
            )
        claims = snapshot_manifest_claims(bundle)
        envelope = self.identity.sign_claims("migration_snapshot_manifest_v1", claims)
        return {
            "bundle": bundle.to_dict(),
            "envelope": envelope,
        }

    def export_migration_snapshot(
        self,
        *,
        source_network: str,
        snapshot_ref: str = "",
        include_claimed: bool = False,
        include_inactive: bool = False,
        sign: bool = False,
        generated_at: float | None = None,
    ) -> dict[str, object]:
        exported_sources = self.store.export_migration_sources(
            source_network=source_network,
            snapshot_ref=snapshot_ref,
            include_claimed=include_claimed,
        )
        if not include_inactive:
            exported_sources = [item for item in exported_sources if item.get("status") == "active"]
        if not exported_sources:
            raise ValueError("No migration sources matched the requested export filter.")
        resolved_generated_at = round(time.time(), 6) if generated_at is None else generated_at
        resolved_snapshot_ref = snapshot_ref or f"{source_network}-live-export"
        bundle = validate_snapshot_bundle(
            MigrationSnapshotBundle(
                source_network=source_network,
                snapshot_ref=resolved_snapshot_ref,
                generated_at=resolved_generated_at,
                entries=tuple(
                    MigrationSnapshotEntry(
                        classical_address=str(item["classical_address"]),
                        provider_id=str(item["provider_id"]),
                        amount=int(item["amount"]),
                        source_address=str(item["source_address"]),
                        source_address_format=str(item["source_address_format"]),
                        status=str(item.get("status", "active")),
                        status_reason=str(item.get("status_reason", "")),
                        reviewed_at=float(item.get("reviewed_at", 0.0)),
                    )
                    for item in exported_sources
                ),
            )
        )
        payload = {
            "bundle": bundle.to_dict(),
            "source_count": len(exported_sources),
            "include_claimed": include_claimed,
            "source_network_profile": describe_legacy_network(source_network),
        }
        if sign:
            payload["envelope"] = self.identity.sign_claims(
                "migration_snapshot_manifest_v1",
                snapshot_manifest_claims(bundle),
            )
        return payload

    def reconcile_migration_snapshot(self, payload: dict[str, object]) -> dict[str, object]:
        bundle, envelope = parse_snapshot_import_payload(payload)
        incoming_by_address = {entry.classical_address: entry for entry in bundle.entries}
        existing_sources = {
            str(item["classical_address"]): item
            for item in self.store.list_migration_sources()
            if item["source_network"] == bundle.source_network
        }
        existing_snapshots = {
            str(item["snapshot_ref"]): item
            for item in self.store.list_migration_snapshots()
            if item["source_network"] == bundle.source_network
        }

        would_add: list[dict[str, object]] = []
        unchanged: list[dict[str, object]] = []
        changed: list[dict[str, object]] = []
        review_conflicts: list[dict[str, object]] = []

        for entry in bundle.normalized_entries():
            existing = existing_sources.get(entry.classical_address)
            if existing is None:
                would_add.append(
                    {
                        "classical_address": entry.classical_address,
                        "provider_id": entry.provider_id,
                        "amount": entry.amount,
                    }
                )
                continue

            differences: dict[str, dict[str, object]] = {}
            comparisons = {
                "provider_id": entry.provider_id,
                "amount": entry.amount,
                "source_address": entry.source_address or entry.classical_address,
                "source_address_format": entry.source_address_format,
                "status": entry.status,
            }
            for key, incoming_value in comparisons.items():
                if existing.get(key) != incoming_value:
                    differences[key] = {
                        "existing": existing.get(key),
                        "incoming": incoming_value,
                    }
            if differences:
                changed.append(
                    {
                        "classical_address": entry.classical_address,
                        "differences": differences,
                    }
                )
            else:
                unchanged.append({"classical_address": entry.classical_address})
            if existing.get("status") != "active" and entry.status == "active":
                review_conflicts.append(
                    {
                        "classical_address": entry.classical_address,
                        "existing_status": existing.get("status"),
                        "incoming_status": entry.status,
                    }
                )

        local_missing_from_incoming = [
            {
                "classical_address": address,
                "snapshot_ref": item["snapshot_ref"],
                "status": item["status"],
                "claimed": item["claimed"],
            }
            for address, item in sorted(existing_sources.items())
            if item["snapshot_ref"] == bundle.snapshot_ref and address not in incoming_by_address
        ]
        existing_snapshot = existing_snapshots.get(bundle.snapshot_ref)
        manifest_matches = (
            existing_snapshot is not None
            and existing_snapshot.get("manifest_hash") == bundle.finalized().manifest_hash
            and existing_snapshot.get("entries_root") == bundle.finalized().entries_root()
        )

        return {
            "source_network": bundle.source_network,
            "snapshot_ref": bundle.snapshot_ref,
            "incoming_entry_count": len(bundle.entries),
            "has_signed_envelope": envelope is not None,
            "existing_snapshot": existing_snapshot or {},
            "manifest_matches": manifest_matches,
            "would_add": would_add,
            "unchanged": unchanged,
            "changed": changed,
            "review_conflicts": review_conflicts,
            "local_missing_from_incoming": local_missing_from_incoming,
            "summary": {
                "would_add": len(would_add),
                "unchanged": len(unchanged),
                "changed": len(changed),
                "review_conflicts": len(review_conflicts),
                "local_missing_from_incoming": len(local_missing_from_incoming),
            },
        }

    def preflight_migration_claim(
        self,
        *,
        destination_address: str,
        classical_address: str,
        classical_provider_id: str,
        source_network: str,
        snapshot_ref: str = "",
        classical_public_key: object | None = None,
    ) -> dict[str, object]:
        draft = self.build_migration_claim_draft(
            destination_address=destination_address,
            classical_address=classical_address,
            classical_provider_id=classical_provider_id,
            source_network=source_network,
            snapshot_ref=snapshot_ref,
            classical_public_key=classical_public_key,
        )
        source = self.store.migration_source(classical_address)
        if source is None:
            raise ValueError("Migration source address is unknown.")

        checks: list[dict[str, object]] = []
        policy = self.migration_policy()
        checks.append({"name": "claims_open", "passed": bool(policy["claims_open"])})
        checks.append({"name": "source_active", "passed": source.get("status") == "active"})
        checks.append({"name": "not_claimed", "passed": self.store.migration_claim(classical_address) is None})
        checks.append(
            {
                "name": "provider_allowed",
                "passed": classical_provider_id in self.config.migration_allowed_classical_providers,
            }
        )
        snapshot = next(
            (item for item in self.store.list_migration_snapshots() if item["snapshot_ref"] == source["snapshot_ref"]),
            None,
        )
        checks.append({"name": "snapshot_active", "passed": snapshot is None or snapshot["status"] == "active"})
        if classical_public_key is not None:
            verifier = get_classical_claim_verifier(classical_provider_id)
            checks.append(
                {
                    "name": "classical_public_key_derives_address",
                    "passed": verifier.address_from_public_key(classical_public_key) == classical_address,
                }
            )
            checks.append(
                {
                    "name": "classical_public_key_derives_source_address",
                    "passed": verifier.verify_source_address_ownership(
                        classical_public_key,
                        source_address=str(source.get("source_address", classical_address)),
                        source_address_format=str(source.get("source_address_format", "")),
                        source_network=source_network,
                    ),
                }
            )

        return {
            "ready": all(bool(item["passed"]) for item in checks),
            "checks": checks,
            "source": source,
            "policy": policy,
            "draft_transaction": json.loads(draft.serialize_with_id()),
            "classical_claim_message_hex": classical_claim_message_bytes(draft.migration_claim_payload()).hex(),
            "destination_acceptance_message_hex": destination_acceptance_message_bytes(
                draft.migration_claim_payload()
            ).hex(),
        }

    def migration_claim_receipt(self, classical_address: str, *, sign: bool = True) -> dict[str, object]:
        claim = self.store.migration_claim(classical_address)
        if claim is None:
            raise ValueError("Migration claim is unknown.")
        source = self.store.migration_source(classical_address) or {}
        claims = {
            "classical_address": claim["classical_address"],
            "provider_id": claim["provider_id"],
            "source_network": claim["source_network"],
            "source_address": source.get("source_address", claim["classical_address"]),
            "source_address_format": source.get("source_address_format", ""),
            "destination_address": claim["destination_address"],
            "amount": claim["amount"],
            "tx_id": claim["tx_id"],
            "claimed_at": claim["claimed_at"],
        }
        receipt = {
            "receipt_version": 1,
            "claims": claims,
        }
        if sign:
            receipt["envelope"] = self.identity.sign_claims("migration_claim_receipt_v1", claims)
        return receipt

    def migration_audit_report(
        self,
        *,
        source_network: str | None = None,
    ) -> dict[str, object]:
        snapshots = self.store.list_migration_snapshots()
        sources = self.store.list_migration_sources()
        if source_network:
            snapshots = [item for item in snapshots if item["source_network"] == source_network]
            sources = [item for item in sources if item["source_network"] == source_network]
        snapshot_map = {item["snapshot_ref"]: item for item in snapshots}
        summary_by_network: dict[str, dict[str, int]] = {}
        summary_by_provider: dict[str, dict[str, int]] = {}
        summary_by_source_status: dict[str, int] = {}
        summary_by_snapshot_status: dict[str, int] = {}
        anomalies: list[dict[str, object]] = []

        for snapshot in snapshots:
            summary_by_snapshot_status[snapshot["status"]] = summary_by_snapshot_status.get(snapshot["status"], 0) + 1

        for source in sources:
            network_summary = summary_by_network.setdefault(
                str(source["source_network"]),
                {"total": 0, "active": 0, "claimed": 0, "blocked": 0},
            )
            provider_summary = summary_by_provider.setdefault(
                str(source["provider_id"]),
                {"total": 0, "active": 0, "claimed": 0, "blocked": 0},
            )
            source_status = str(source["status"])
            blocked = source_status != "active"
            claimed = bool(source["claimed"])
            network_summary["total"] += 1
            provider_summary["total"] += 1
            if source_status == "active":
                network_summary["active"] += 1
                provider_summary["active"] += 1
            if claimed:
                network_summary["claimed"] += 1
                provider_summary["claimed"] += 1
            if blocked:
                network_summary["blocked"] += 1
                provider_summary["blocked"] += 1
            summary_by_source_status[source_status] = summary_by_source_status.get(source_status, 0) + 1

            snapshot = snapshot_map.get(str(source["snapshot_ref"]))
            if snapshot is None and str(source["snapshot_ref"]):
                anomalies.append(
                    {
                        "kind": "missing_snapshot_record",
                        "classical_address": source["classical_address"],
                        "snapshot_ref": source["snapshot_ref"],
                    }
                )
            elif snapshot is not None and snapshot["status"] != "active" and source_status == "active":
                anomalies.append(
                    {
                        "kind": "active_source_on_blocked_snapshot",
                        "classical_address": source["classical_address"],
                        "snapshot_ref": source["snapshot_ref"],
                        "snapshot_status": snapshot["status"],
                    }
                )
            if claimed and blocked:
                anomalies.append(
                    {
                        "kind": "claimed_blocked_source",
                        "classical_address": source["classical_address"],
                        "source_status": source_status,
                    }
                )

        return {
            "generated_at": round(time.time(), 6),
            "source_network": source_network or "",
            "snapshot_count": len(snapshots),
            "source_count": len(sources),
            "summary_by_network": summary_by_network,
            "summary_by_provider": summary_by_provider,
            "summary_by_source_status": summary_by_source_status,
            "summary_by_snapshot_status": summary_by_snapshot_status,
            "anomalies": anomalies,
        }

    def list_migration_sources(self) -> list[dict[str, object]]:
        items = self.store.list_migration_sources()
        effective_height = self.store.block_count()
        policy = self.migration_policy(effective_height)
        for item in items:
            item["claims_open"] = policy["claims_open"]
            item["dual_control_required"] = policy["dual_control_required"]
            item["claimable"] = policy["claims_open"] and not item["claimed"] and item["status"] == "active"
            item["source_network_profile"] = describe_legacy_network(str(item["source_network"]))
        return items

    def build_migration_claim_draft(
        self,
        *,
        destination_address: str,
        classical_address: str,
        classical_provider_id: str,
        source_network: str,
        snapshot_ref: str = "",
        classical_public_key: object | None = None,
        timestamp: float | None = None,
    ) -> Transaction:
        source = self.store.migration_source(classical_address)
        if source is None:
            raise ValueError("Migration source address is unknown.")
        return Transaction(
            inputs=[],
            outputs=[TxOutput(recipient=destination_address, amount=int(source["amount"]))],
            kind="migration_claim",
            chain_id=self.config.chain_id,
            signature_scheme=classical_provider_id,
            timestamp=round(time.time(), 6) if timestamp is None else timestamp,
            fee=0,
            metadata={
                "classical_address": classical_address,
                "classical_provider_id": classical_provider_id,
                "source_network": source_network,
                "snapshot_ref": snapshot_ref or str(source.get("snapshot_ref", "")),
                "source_address": str(source.get("source_address", classical_address)),
                "source_address_format": str(source.get("source_address_format", "")),
                "classical_public_key": {} if classical_public_key is None else classical_public_key,
            },
        )

    def select_inputs(self, addresses: list[str], target_amount: int) -> tuple[list[tuple[str, int, TxOutput]], int]:
        selected: list[tuple[str, int, TxOutput]] = []
        running_total = 0
        for tx_id, output_index, output in reversed(self.store.list_utxos(addresses)):
            selected.append((tx_id, output_index, output))
            running_total += output.amount
            if running_total >= target_amount:
                return selected, running_total
        raise ValueError("Insufficient funds.")

    def _validate_transaction_against_view(
        self,
        transaction: Transaction,
        utxo_view: dict[tuple[str, int], TxOutput],
        *,
        effective_height: int | None = None,
        claimed_classical_addresses: set[str] | None = None,
    ) -> None:
        if not transaction.tx_id:
            transaction.finalize()
        expected_tx_id = hashlib.sha256(transaction.serialize().encode("utf-8")).hexdigest()
        if transaction.tx_id != expected_tx_id:
            raise ValueError("Transaction hash mismatch.")
        if transaction.chain_id != self.config.chain_id:
            raise ValueError("Transaction belongs to a different chain.")
        if transaction.kind not in {"transfer", "migration_claim"}:
            raise ValueError("Unsupported transaction kind.")
        if not transaction.outputs:
            raise ValueError("Transaction must include at least one output.")
        if any(output.amount <= 0 for output in transaction.outputs):
            raise ValueError("All outputs must be positive.")
        if transaction.fee < 0:
            raise ValueError("Transaction fee cannot be negative.")

        if transaction.kind == "migration_claim":
            self._validate_migration_claim(
                transaction,
                effective_height=self.store.block_count() if effective_height is None else effective_height,
                claimed_classical_addresses=claimed_classical_addresses,
            )
            return

        provider = get_signature_verifier(transaction.signature_scheme)
        if not transaction.inputs:
            return

        seen_inputs: set[tuple[str, int]] = set()
        signing_payload = transaction.signing_payload()
        total_input = 0

        for tx_input in transaction.inputs:
            key = (tx_input.prev_tx_id, tx_input.output_index)
            if key in seen_inputs:
                raise ValueError("Transaction cannot spend the same UTXO twice.")
            seen_inputs.add(key)

            previous_output = utxo_view.get(key)
            if previous_output is None:
                raise ValueError(f"Unknown UTXO reference: {key}.")
            if provider.address_from_public_key(tx_input.public_key) != previous_output.recipient:
                raise ValueError("Input public key does not match the referenced address.")
            if not provider.verify(signing_payload, tx_input.signature, tx_input.public_key):
                raise ValueError("Quantum signature verification failed.")
            total_input += previous_output.amount

        total_output = sum(output.amount for output in transaction.outputs)
        if total_output + transaction.fee > total_input:
            raise ValueError("Transaction spends more than its inputs provide.")

    def _check_pending_double_spends(self, candidate: Transaction) -> None:
        if candidate.kind == "migration_claim":
            classical_address = str(candidate.metadata.get("classical_address", ""))
            if not classical_address:
                raise ValueError("Migration claim metadata is missing classical_address.")
            for pending in self.store.pending_transactions():
                if pending.kind != "migration_claim":
                    continue
                if str(pending.metadata.get("classical_address", "")) == classical_address:
                    raise ValueError("Migration claim conflicts with an existing pending classical address claim.")
            return
        candidate_inputs = {(item.prev_tx_id, item.output_index) for item in candidate.inputs}
        if not candidate_inputs:
            return
        for pending in self.store.pending_transactions():
            pending_inputs = {(item.prev_tx_id, item.output_index) for item in pending.inputs}
            if candidate_inputs & pending_inputs:
                raise ValueError("Transaction conflicts with a pending spend.")

    def _enforce_mempool_policy(self, transaction: Transaction) -> None:
        if not transaction.tx_id:
            transaction.finalize()
        if self.store.has_pending_transaction(transaction.tx_id):
            raise ValueError("Transaction is already pending.")
        if self.store.pending_transaction_count() >= self.config.max_pending_transactions:
            raise ValueError("Mempool is full.")
        serialized = transaction.serialize_with_id().encode("utf-8")
        if len(serialized) > self.config.max_transaction_size_bytes:
            raise ValueError("Transaction exceeds the maximum mempool size policy.")
        if len(transaction.inputs) > self.config.max_transaction_inputs:
            raise ValueError("Transaction exceeds the maximum input policy.")
        if len(transaction.outputs) > self.config.max_transaction_outputs:
            raise ValueError("Transaction exceeds the maximum output policy.")
        if transaction.inputs and transaction.fee < self.config.min_transaction_fee:
            raise ValueError("Transaction fee is below the minimum relay policy.")
        if transaction.timestamp > time.time() + self.config.auth_time_skew_seconds:
            raise ValueError("Transaction timestamp is too far in the future.")
        if transaction.kind == "migration_claim":
            if transaction.inputs:
                raise ValueError("Migration claim transactions cannot include UTXO inputs.")
            if transaction.fee != 0:
                raise ValueError("Migration claim transactions cannot charge a fee.")
            if len(transaction.outputs) != 1:
                raise ValueError("Migration claim transactions must create exactly one PQ output.")

    def _select_best_chain(self, candidate_head_hash: str) -> None:
        current_best = self.store.best_head_hash()
        if current_best is None:
            self.store.apply_best_chain(candidate_head_hash)
            return

        current_work = self.store.cumulative_work_for(current_best)
        candidate_work = self.store.cumulative_work_for(candidate_head_hash)
        if candidate_work is None:
            raise ValueError("Candidate head work is unavailable.")

        should_switch = False
        if current_work is None or candidate_work > current_work:
            should_switch = True
        elif candidate_work == current_work and candidate_head_hash > current_best:
            should_switch = True

        if should_switch:
            self.store.apply_best_chain(candidate_head_hash)

    def _admit_peer(self, peer_identity: dict[str, object]) -> None:
        node_id = peer_identity["node_id"]
        if not node_id or node_id == self.config.node_id:
            raise ValueError("Peer node identity is invalid.")
        if peer_identity["chain_id"] != self.config.chain_id:
            raise ValueError("Peer belongs to a different chain.")

        normalized_url = normalize_peer_url(peer_identity["advertised_url"])
        existing = self.store.peer_identity_by_node_id(node_id)
        if existing is not None and existing["address"] != peer_identity["address"]:
            raise ValueError("Peer node identity conflicts with an existing admitted address.")

        now = time.time()
        self.store.add_peer(normalized_url)
        self.store.upsert_peer_identity(
            node_id=node_id,
            url=normalized_url,
            address=peer_identity["address"],
            signature_scheme=peer_identity["signature_scheme"],
            public_key=peer_identity["public_key"],
            status="admitted",
            admitted_at=existing["admitted_at"] if existing is not None else now,
            last_seen=now,
        )

    def _issue_peer_session(self, peer_identity: dict[str, object]) -> dict[str, object]:
        now = time.time()
        session_id = secrets.token_hex(24)
        expires_at = now + self.config.peer_session_ttl_seconds
        self.store.expire_peer_sessions_for_node(peer_identity["node_id"])
        self.store.upsert_peer_session(
            session_id=session_id,
            node_id=peer_identity["node_id"],
            url=normalize_peer_url(peer_identity["advertised_url"]),
            created_at=now,
            last_seen=now,
            expires_at=expires_at,
            status="active",
        )
        session = self.store.peer_session(session_id)
        if session is None:
            raise ValueError("Failed to create peer session.")
        return session

    def _authenticate_peer_envelope(
        self,
        envelope: dict[str, object],
        *,
        expected_purpose: str,
        require_existing_peer: bool = True,
        require_session: bool = True,
        request_path: str | None = None,
        request_claims: dict[str, object] | None = None,
    ) -> dict[str, object]:
        peer_identity = verify_signed_envelope(
            envelope,
            expected_purpose=expected_purpose,
            expected_chain_id=self.config.chain_id,
            time_skew_seconds=self.config.auth_time_skew_seconds,
        )
        claims = peer_identity["claims"]
        expected_target = normalize_peer_url(self.config.advertised_url)
        if claims.get("target_url") != expected_target:
            raise ValueError("Peer request target does not match this node.")
        if request_path is not None:
            if claims.get("request_method") != "POST":
                raise ValueError("Peer request method is invalid.")
            if claims.get("request_path") != request_path:
                raise ValueError("Peer request path is invalid.")
            expected_payload_hash = request_claims_digest(request_claims or {})
            if claims.get("request_payload_hash") != expected_payload_hash:
                raise ValueError("Peer request payload binding is invalid.")

        existing = self.store.peer_identity_by_node_id(peer_identity["node_id"])
        if require_existing_peer:
            if existing is None or existing["status"] != "admitted":
                raise ValueError("Peer is not admitted.")
            if existing["address"] != peer_identity["address"]:
                raise ValueError("Peer address does not match the admitted identity.")
            if existing["url"] != peer_identity["advertised_url"]:
                raise ValueError("Peer URL does not match the admitted identity.")

        self.store.prune_expired_peer_sessions(time.time())
        if require_session:
            session_id = str(claims.get("session_id", ""))
            if not session_id:
                raise ValueError("Peer session is required.")
            session = self.store.peer_session(session_id)
            if session is None or session["status"] != "active":
                raise ValueError("Peer session is unknown.")
            if session["node_id"] != peer_identity["node_id"]:
                raise ValueError("Peer session does not belong to this node identity.")
            if session["url"] != peer_identity["advertised_url"]:
                raise ValueError("Peer session URL does not match the peer identity.")
            now = time.time()
            if float(session["expires_at"]) <= now:
                raise ValueError("Peer session has expired.")
            self.store.touch_peer_session(
                session_id,
                last_seen=now,
                expires_at=now + self.config.peer_session_ttl_seconds,
            )

        try:
            self.store.mark_peer_nonce(peer_identity["node_id"], peer_identity["nonce"], time.time())
        except sqlite3.IntegrityError as error:
            raise ValueError("Peer request nonce has already been used.") from error

        return peer_identity

    def _build_peer_request_frame(
        self,
        *,
        message_type: str,
        payload: dict[str, object],
        auth: dict[str, object],
    ) -> dict[str, object]:
        return build_peer_frame(
            protocol_version=self.config.peer_protocol_version,
            message_type=message_type,
            payload=payload,
            auth=auth,
        )

    def _build_peer_response_frame(
        self,
        *,
        message_type: str,
        payload: dict[str, object],
        auth: dict[str, object] | None = None,
    ) -> dict[str, object]:
        return build_peer_frame(
            protocol_version=self.config.peer_protocol_version,
            message_type=message_type,
            payload=payload,
            auth=auth,
        )

    def _parse_peer_response_frame(self, frame: dict[str, object], expected_message_type: str) -> dict[str, object]:
        payload, _ = parse_peer_frame(
            frame,
            expected_protocol_version=self.config.peer_protocol_version,
            expected_message_type=expected_message_type,
        )
        return payload

    def _validate_migration_claim(
        self,
        transaction: Transaction,
        *,
        effective_height: int,
        claimed_classical_addresses: set[str] | None = None,
    ) -> None:
        classical_address = str(transaction.metadata.get("classical_address", ""))
        provider_id = str(transaction.metadata.get("classical_provider_id", ""))
        source_network = str(transaction.metadata.get("source_network", ""))
        public_key = transaction.metadata.get("classical_public_key", {})
        proof = transaction.metadata.get("classical_signature", {})
        snapshot_ref = str(transaction.metadata.get("snapshot_ref", ""))
        source_address = str(transaction.metadata.get("source_address", ""))
        source_address_format = str(transaction.metadata.get("source_address_format", ""))

        if not classical_address or not provider_id or not source_network:
            raise ValueError("Migration claim metadata is incomplete.")
        if provider_id not in self.config.migration_allowed_classical_providers:
            raise ValueError("Migration claim provider is not allowed by node policy.")
        if not self._height_in_window(
            effective_height,
            self.config.migration_claim_start_height,
            self.config.migration_claim_end_height,
        ):
            raise ValueError("Migration claim is outside the configured claim window.")
        source = self.store.migration_source(classical_address)
        if source is None:
            raise ValueError("Migration claim source address is unknown.")
        if str(source.get("status", "active")) != "active":
            raise ValueError("Migration claim source is blocked by migration review policy.")
        snapshot = next((item for item in self.store.list_migration_snapshots() if item["snapshot_ref"] == source["snapshot_ref"]), None)
        if snapshot is not None and snapshot["status"] != "active":
            raise ValueError("Migration claim snapshot is blocked by migration review policy.")
        if source["provider_id"] != provider_id:
            raise ValueError("Migration claim provider does not match the seeded source.")
        if source["source_network"] != source_network:
            raise ValueError("Migration claim source network does not match the seeded source.")
        if snapshot_ref and source["snapshot_ref"] and snapshot_ref != source["snapshot_ref"]:
            raise ValueError("Migration claim snapshot reference does not match the seeded source.")
        if source_address and source_address != str(source.get("source_address", "")):
            raise ValueError("Migration claim source address does not match the seeded source.")
        if source_address_format and source_address_format != str(source.get("source_address_format", "")):
            raise ValueError("Migration claim source address format does not match the seeded source.")
        if classical_address in (claimed_classical_addresses or set()):
            raise ValueError("Migration source has already been claimed on this branch.")
        if claimed_classical_addresses is None and self.store.migration_claim(classical_address) is not None:
            raise ValueError("Migration source has already been claimed on the canonical chain.")
        if len(transaction.outputs) != 1:
            raise ValueError("Migration claim transactions must create exactly one PQ output.")
        if transaction.outputs[0].amount != int(source["amount"]):
            raise ValueError("Migration claim amount does not match the seeded source balance.")

        verifier = get_classical_claim_verifier(provider_id)
        claim_message = classical_claim_message_bytes(transaction.migration_claim_payload())
        if verifier.address_from_public_key(public_key) != classical_address:
            raise ValueError("Migration claim public key does not derive the seeded classical address.")
        if not verifier.verify_claim(claim_message, proof, public_key):
            raise ValueError("Migration claim proof verification failed.")
        seeded_source_address = str(source.get("source_address", classical_address))
        seeded_source_address_format = str(source.get("source_address_format", ""))
        if not verifier.verify_source_address_ownership(
            public_key,
            source_address=seeded_source_address,
            source_address_format=seeded_source_address_format,
            source_network=source_network,
        ):
            raise ValueError("Migration claim public key does not prove ownership of the seeded source address.")
        if self._migration_dual_control_required(effective_height):
            self._validate_destination_attestation(transaction)

    def _validate_destination_attestation(self, transaction: Transaction) -> None:
        attestation = transaction.metadata.get("destination_attestation", {})
        if not isinstance(attestation, dict):
            raise ValueError("Migration claim destination attestation is missing.")
        signature_scheme = str(attestation.get("signature_scheme", ""))
        public_key = attestation.get("public_key", {})
        signature = attestation.get("signature", {})
        if not signature_scheme:
            raise ValueError("Migration claim destination attestation is missing signature_scheme.")
        if not transaction.outputs:
            raise ValueError("Migration claim destination attestation requires an output.")
        provider = get_signature_verifier(signature_scheme)
        destination_address = transaction.outputs[0].recipient
        if provider.address_from_public_key(public_key) != destination_address:
            raise ValueError("Migration claim destination attestation does not match the PQ destination address.")
        message = destination_acceptance_message_bytes(transaction.migration_claim_payload())
        if not provider.verify(message, signature, public_key):
            raise ValueError("Migration claim destination attestation verification failed.")

    @staticmethod
    def _height_in_window(height: int, start_height: int, end_height: int) -> bool:
        if height < start_height:
            return False
        if end_height > 0 and height > end_height:
            return False
        return True

    def _migration_dual_control_required(self, effective_height: int) -> bool:
        if (
            self.config.migration_dual_control_start_height == 0
            and self.config.migration_dual_control_end_height == 0
        ):
            return False
        return self._height_in_window(
            effective_height,
            self.config.migration_dual_control_start_height,
            self.config.migration_dual_control_end_height,
        )


class Wallet:
    def __init__(
        self,
        label: str,
        signature_provider: str = "xmss_merkle_lamport_v1",
        state_db_path: Path | None = None,
        custody_mode: str = "auto",
        custody_scope: str = "current_user",
        reservation_ttl_seconds: int = 60,
    ):
        self.label = label
        self.signature_provider = signature_provider
        self._provider = get_signature_provider(signature_provider)
        self._owner_id = f"wallet:{label}:{os.getpid()}:{secrets.token_hex(8)}"
        self._state_store = (
            None
            if state_db_path is None
            else SQLiteWalletStateStore(
                Path(state_db_path),
                custody_config=WalletCustodyConfig(
                    mode=custody_mode,
                    scope=custody_scope,
                ),
                reservation_ttl_seconds=reservation_ttl_seconds,
            )
        )
        self._keys: dict[str, object] = {}
        self._load_persisted_keys()

    def _load_persisted_keys(self) -> None:
        if self._state_store is None:
            return
        for address, payload in self._state_store.load_wallet_keys(self.label, self.signature_provider):
            self._keys[address] = self._provider.deserialize_keypair(payload)

    def _persist_key(self, address: str) -> None:
        if self._state_store is None:
            return
        keypair = self._keys[address]
        key_state = self._provider.serialize_keypair(keypair)
        self._state_store.save_wallet_key(self.label, address, self.signature_provider, key_state)

    def _reserve_key_usage(self, address: str) -> tuple[object, object, str | None]:
        if self._state_store is None:
            keypair = self._keys[address]
            reservation = self._provider.reserve_signing_material(keypair)
            return keypair, reservation, None

        def reserve_fn(current_state: object) -> tuple[object, object]:
            keypair = self._provider.deserialize_keypair(current_state)
            reservation = self._provider.reserve_signing_material(keypair)
            return self._provider.serialize_keypair(keypair), reservation

        next_state, reservation, reservation_id = self._state_store.reserve_wallet_key_state(
            self.label,
            address,
            self.signature_provider,
            reserve_fn,
            owner_id=self._owner_id,
        )
        keypair = self._provider.deserialize_keypair(next_state)
        self._keys[address] = keypair
        return keypair, reservation, reservation_id

    def create_address(self) -> str:
        keypair = self._provider.generate_keypair()
        address = self._provider.derive_address(keypair)
        self._keys[address] = keypair
        self._persist_key(address)
        return address

    def addresses(self) -> list[str]:
        return list(self._keys.keys())

    def balance(self, service: NodeService) -> int:
        return service.balance_for_addresses(self.addresses())

    def create_transaction(self, service: NodeService, recipient: str, amount: int, fee: int = 1) -> Transaction:
        if amount <= 0:
            raise ValueError("Amount must be positive.")
        if fee < 0:
            raise ValueError("Fee cannot be negative.")

        selected, total_input = service.select_inputs(self.addresses(), amount + fee)
        inputs = [TxInput(prev_tx_id=tx_id, output_index=output_index) for tx_id, output_index, _ in selected]
        outputs = [TxOutput(recipient=recipient, amount=amount)]

        change = total_input - amount - fee
        if change > 0:
            outputs.append(TxOutput(recipient=self.create_address(), amount=change))

        transaction = Transaction(
            inputs=inputs,
            outputs=outputs,
            chain_id=service.config.chain_id,
            signature_scheme=self._provider.metadata.scheme_id,
            fee=fee,
        )
        signing_payload = transaction.signing_payload()
        for tx_input, (_, _, previous_output) in zip(transaction.inputs, selected):
            address = previous_output.recipient
            keypair, reservation, reservation_id = self._reserve_key_usage(address)
            try:
                if reservation is not None:
                    tx_input.public_key, tx_input.signature = self._provider.sign_with_reservation(
                        keypair, signing_payload, reservation
                    )
                    if self._state_store is not None and reservation_id is not None:
                        self._state_store.complete_wallet_key_reservation(
                            self.label,
                            address,
                            self.signature_provider,
                            reservation_id,
                            self._provider.serialize_keypair(keypair),
                            owner_id=self._owner_id,
                        )
                    else:
                        self._persist_key(address)
                else:
                    tx_input.public_key, tx_input.signature = self._provider.sign(keypair, signing_payload)
                    self._persist_key(address)
            except Exception as error:
                if self._state_store is not None and reservation_id is not None:
                    self._state_store.fail_wallet_key_reservation(
                        self.label,
                        address,
                        self.signature_provider,
                        reservation_id,
                        owner_id=self._owner_id,
                        error_message=str(error),
                    )
                raise
        transaction.finalize()
        return transaction

    def create_migration_claim(
        self,
        service: NodeService,
        *,
        classical_address: str,
        classical_provider_id: str,
        classical_public_key: object,
        classical_signature: object,
        source_network: str,
        snapshot_ref: str = "",
        destination_address: str | None = None,
        timestamp: float | None = None,
    ) -> Transaction:
        source = service.store.migration_source(classical_address)
        if source is None:
            raise ValueError("Migration source address is unknown.")
        if source["provider_id"] != classical_provider_id:
            raise ValueError("Migration source provider does not match the requested claim provider.")
        if source["source_network"] != source_network:
            raise ValueError("Migration source network does not match the requested claim network.")
        target_address = destination_address or self.create_address()
        if target_address not in self._keys:
            raise ValueError("Destination address is not controlled by this wallet.")
        transaction = service.build_migration_claim_draft(
            destination_address=target_address,
            classical_address=classical_address,
            classical_provider_id=classical_provider_id,
            source_network=source_network,
            snapshot_ref=snapshot_ref or str(source.get("snapshot_ref", "")),
            classical_public_key=classical_public_key,
            timestamp=timestamp,
        )
        transaction.metadata["classical_signature"] = classical_signature
        if service._migration_dual_control_required(service.store.block_count()):
            transaction.metadata["destination_attestation"] = self._build_destination_attestation(
                service,
                target_address,
                transaction,
            )
        transaction.finalize()
        return transaction

    def _build_destination_attestation(
        self,
        service: NodeService,
        address: str,
        transaction: Transaction,
    ) -> dict[str, object]:
        keypair, reservation, reservation_id = self._reserve_key_usage(address)
        message = destination_acceptance_message_bytes(transaction.migration_claim_payload())
        try:
            if reservation is not None:
                public_key, signature = self._provider.sign_with_reservation(keypair, message, reservation)
                if self._state_store is not None and reservation_id is not None:
                    self._state_store.complete_wallet_key_reservation(
                        self.label,
                        address,
                        self.signature_provider,
                        reservation_id,
                        self._provider.serialize_keypair(keypair),
                        owner_id=self._owner_id,
                    )
                else:
                    self._persist_key(address)
            else:
                public_key, signature = self._provider.sign(keypair, message)
                self._persist_key(address)
        except Exception as error:
            if self._state_store is not None and reservation_id is not None:
                self._state_store.fail_wallet_key_reservation(
                    self.label,
                    address,
                    self.signature_provider,
                    reservation_id,
                    owner_id=self._owner_id,
                    error_message=str(error),
                )
            raise
        return {
            "address": address,
            "signature_scheme": self._provider.metadata.scheme_id,
            "public_key": public_key,
            "signature": signature,
        }
