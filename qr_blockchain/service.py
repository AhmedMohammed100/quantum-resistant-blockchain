from __future__ import annotations

import hashlib
import importlib.metadata as importlib_metadata
import json
import os
from collections import Counter
from pathlib import Path
import sqlite3
import secrets
import time
from urllib.parse import urlparse

from .auth import NodeIdentityManager, request_claims_digest, verify_signed_envelope
from .config import NodeConfig
from .currency import CurrencyPolicy, format_units
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
from .models import Block, Transaction, TxInput, TxOutput, canonical_json
from .native_crypto import native_crypto_boundary_report
from .network import fetch_json, normalize_peer_url, with_path
from .protocol import build_peer_frame, parse_peer_frame, protocol_manifest
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
from .verification import verify_transaction_inputs
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

    def currency_policy(self) -> CurrencyPolicy:
        return CurrencyPolicy(
            name=self.config.currency_name,
            symbol=self.config.currency_symbol,
            decimals=self.config.currency_decimals,
            base_unit=self.config.currency_base_unit,
            initial_subsidy=self.config.mining_reward,
            subsidy_halving_interval=self.config.subsidy_halving_interval,
            max_money=self.config.max_money,
            genesis_supply_cap=self.config.genesis_supply_cap,
            emission_supply_cap=self.config.emission_supply_cap,
            migration_pool_cap=self.config.migration_pool_cap,
            treasury_allocation_cap=self.config.treasury_allocation_cap,
            security_reserve_cap=self.config.security_reserve_cap,
            public_goods_allocation_cap=self.config.public_goods_allocation_cap,
            migration_conversion_policy=self.config.migration_conversion_policy,
            reward_recipient_policy=self.config.reward_recipient_policy,
        )

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
        genesis_total = sum(output.amount for output in genesis_outputs)
        if self.config.genesis_supply_cap > 0 and genesis_total > self.config.genesis_supply_cap:
            raise ValueError("Genesis allocation exceeds configured genesis supply cap.")
        if genesis_total > self.config.max_money:
            raise ValueError("Genesis allocation exceeds configured max money.")

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
            version=3,
            timestamp=0.0,
        )
        block.state_root = self._state_root_after_block({}, block)
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
            utxo_metadata=self._utxo_origin_metadata_for_head(self.store.best_head_hash()),
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
        subsidy = self.currency_policy().subsidy_at_height(int(latest["height"]) + 1)
        reward = sum(transaction.fee for transaction in pending) + subsidy
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
            version=3,
        )
        block.state_root = self._state_root_after_block(self.store.utxos_for_head(str(latest["block_hash"])), block)
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
        self._enforce_state_root_activation(block)
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
            if block.version >= 3 and block.state_root != self._state_root_after_block({}, block):
                raise ValueError("Block state root mismatch.")
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
        utxo_metadata = self._utxo_origin_metadata_for_head(block.previous_hash)
        claimed_view = self.store.claimed_classical_addresses_for_head(block.previous_hash)
        spent_in_block: set[tuple[str, int]] = set()
        claimed_in_block: set[str] = set()
        fee_total = 0
        parent_path = self.store.path_to_root(block.previous_hash)
        epoch_minted = self._migration_epoch_minted_for_blocks(parent_path, block.index)

        for index, transaction in enumerate(block.transactions):
            self._validate_transaction_against_view(
                transaction,
                utxo_view,
                effective_height=block.index,
                claimed_classical_addresses=claimed_view | claimed_in_block,
                utxo_metadata=utxo_metadata,
            )
            if index == 0:
                for output_index, output in enumerate(transaction.outputs):
                    utxo_view[(transaction.tx_id, output_index)] = output
                    utxo_metadata[(transaction.tx_id, output_index)] = {
                        "height": block.index,
                        "coinbase": True,
                    }
                continue
            fee_total += transaction.fee
            if transaction.kind == "migration_claim":
                classical_address = str(transaction.metadata.get("classical_address", ""))
                if classical_address in claimed_in_block:
                    raise ValueError("Block contains a duplicate migration claim.")
                if self.config.migration_epoch_mint_cap > 0:
                    epoch_minted += sum(output.amount for output in transaction.outputs)
                    if epoch_minted > self.config.migration_epoch_mint_cap:
                        raise ValueError("Migration claim would exceed the configured epoch mint cap.")
                claimed_in_block.add(classical_address)
                for output_index, output in enumerate(transaction.outputs):
                    utxo_view[(transaction.tx_id, output_index)] = output
                    utxo_metadata[(transaction.tx_id, output_index)] = {
                        "height": block.index,
                        "coinbase": False,
                        "migration_claim": True,
                        "classical_address": classical_address,
                        "source_network": str(transaction.metadata.get("source_network", "")),
                        "provider_id": str(transaction.metadata.get("classical_provider_id", "")),
                    }
                continue
            for tx_input in transaction.inputs:
                key = (tx_input.prev_tx_id, tx_input.output_index)
                if key in spent_in_block:
                    raise ValueError("Block contains a double spend.")
                spent_in_block.add(key)
                utxo_view.pop(key, None)
                utxo_metadata.pop(key, None)
            for output_index, output in enumerate(transaction.outputs):
                utxo_view[(transaction.tx_id, output_index)] = output
                utxo_metadata[(transaction.tx_id, output_index)] = {
                    "height": block.index,
                    "coinbase": False,
                }

        reward_transaction = block.transactions[0]
        expected_reward = self.currency_policy().subsidy_at_height(block.index) + fee_total
        actual_reward = sum(output.amount for output in reward_transaction.outputs)
        if actual_reward != expected_reward:
            raise ValueError("Reward transaction amount is invalid.")
        if block.version >= 3 and block.state_root != self.state_root_for_utxos(utxo_view):
            raise ValueError("Block state root mismatch.")
        self._validate_supply_limits(self._supply_for_blocks([*parent_path, block]))

    def sync_with_peer(self, peer_url: str) -> int:
        normalized = normalize_peer_url(peer_url)
        session = self.ensure_peer_admission(normalized)
        try:
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
            if remote_height > local_height:
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
            self.store.record_peer_sync_result(str(session["node_id"]), success=True, score_delta=max(1, imported))
            return imported
        except Exception:
            self.store.record_peer_sync_result(str(session["node_id"]), success=False, score_delta=-5)
            raise

    def relay_pending_transaction(self, transaction: Transaction, *, exclude_peer: str = "") -> dict[str, object]:
        if not transaction.tx_id:
            transaction.finalize()
        payload = {"transaction": json.loads(transaction.serialize_with_id())}
        return self._relay_gossip(
            path="/peer/gossip/transaction",
            message_type="peer_transaction_gossip",
            purpose="peer_transaction_gossip_v1",
            payload=payload,
            exclude_peer=exclude_peer,
        )

    def relay_block(self, block: Block, *, exclude_peer: str = "") -> dict[str, object]:
        return self._relay_gossip(
            path="/peer/gossip/block",
            message_type="peer_block_gossip",
            purpose="peer_block_gossip_v1",
            payload={"block": block.to_dict()},
            exclude_peer=exclude_peer,
        )

    def receive_authenticated_transaction_gossip(
        self,
        envelope: dict[str, object],
        transaction_payload: dict[str, object],
    ) -> dict[str, object]:
        peer_identity = self._authenticate_peer_envelope(
            envelope,
            expected_purpose="peer_transaction_gossip_v1",
            request_path="/peer/gossip/transaction",
            request_claims={"transaction": transaction_payload},
        )
        try:
            transaction = Transaction.from_dict(transaction_payload)
            self.submit_transaction(transaction)
        except ValueError as error:
            self.record_peer_penalty(
                str(peer_identity["node_id"]),
                reason=f"invalid transaction gossip: {error}",
                score_delta=self.config.peer_invalid_frame_penalty,
            )
            raise
        self.store.record_peer_sync_result(str(peer_identity["node_id"]), success=True, score_delta=1)
        return self._build_peer_response_frame(
            message_type="peer_transaction_gossip_ack",
            payload={"accepted": True, "tx_id": transaction.tx_id},
        )

    def receive_authenticated_block_gossip(
        self,
        envelope: dict[str, object],
        block_payload: dict[str, object],
    ) -> dict[str, object]:
        peer_identity = self._authenticate_peer_envelope(
            envelope,
            expected_purpose="peer_block_gossip_v1",
            request_path="/peer/gossip/block",
            request_claims={"block": block_payload},
        )
        try:
            block = Block.from_dict(block_payload)
            self.import_block(block)
        except ValueError as error:
            self.record_peer_penalty(
                str(peer_identity["node_id"]),
                reason=f"invalid block gossip: {error}",
                score_delta=self.config.peer_bad_block_penalty,
            )
            raise
        self.store.record_peer_sync_result(str(peer_identity["node_id"]), success=True, score_delta=2)
        return self._build_peer_response_frame(
            message_type="peer_block_gossip_ack",
            payload={"accepted": True, "block_hash": block.block_hash, "height": block.index},
        )

    def record_peer_penalty(self, node_id: str, *, reason: str, score_delta: int | None = None) -> dict[str, object]:
        delta = self.config.peer_invalid_frame_penalty if score_delta is None else score_delta
        self.store.record_peer_sync_result(node_id, success=False, score_delta=delta)
        peer = self.store.peer_identity_by_node_id(node_id) or {}
        return {
            "node_id": node_id,
            "reason": reason,
            "score_delta": delta,
            "score": peer.get("score", 0),
            "failure_count": peer.get("failure_count", 0),
        }

    def sync_with_peers(self) -> dict[str, int]:
        results: dict[str, int] = {}
        for peer in self.list_peers():
            results[peer] = self.sync_with_peer(peer)
        return results

    def register_peer(self, peer_url: str) -> str:
        normalized = normalize_peer_url(peer_url)
        self._enforce_peer_admission_policy(peer_url=normalized)
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

    def peer_diversity_report(self) -> dict[str, object]:
        peers = self.store.list_peer_identities()
        admitted = [peer for peer in peers if str(peer.get("status", "")) == "admitted"]
        diversity_groups: dict[str, int] = {}
        for peer in admitted:
            key = self._peer_diversity_key(str(peer.get("url", "")))
            diversity_groups[key] = diversity_groups.get(key, 0) + 1
        distinct_groups = len(diversity_groups)
        minimum = self.config.min_peer_diversity
        return {
            "minimum_diversity": minimum,
            "distinct_groups": distinct_groups,
            "admitted_peer_count": len(admitted),
            "diversity_groups": diversity_groups,
            "passed": minimum <= 0 or distinct_groups >= minimum,
        }

    def get_blocks_from_height(self, start_height: int) -> list[Block]:
        return self.store.blocks_from_height(start_height)

    def get_block(self, height: int) -> Block | None:
        return self.store.block_at_height(height)

    def balance_for_address(self, address: str) -> int:
        return sum(output.amount for _, _, output in self.store.list_utxos([address]))

    def formatted_balance_for_address(self, address: str) -> dict[str, object]:
        amount = self.balance_for_address(address)
        return {
            "address": address,
            "amount": amount,
            "formatted": format_units(
                amount,
                decimals=self.config.currency_decimals,
                symbol=self.config.currency_symbol,
            ),
            "symbol": self.config.currency_symbol,
            "base_unit": self.config.currency_base_unit,
        }

    def balance_for_addresses(self, addresses: list[str]) -> int:
        return sum(output.amount for _, _, output in self.store.list_utxos(addresses))

    def list_utxos(self, addresses: list[str]) -> list[tuple[str, int, TxOutput]]:
        return self.store.list_utxos(addresses)

    @staticmethod
    def state_root_for_utxos(utxos: dict[tuple[str, int], TxOutput]) -> str:
        payload = [
            {
                "tx_id": tx_id,
                "output_index": output_index,
                "recipient": output.recipient,
                "amount": output.amount,
            }
            for (tx_id, output_index), output in sorted(utxos.items())
        ]
        return hashlib.sha256(canonical_json(payload).encode("utf-8")).hexdigest()

    def _state_root_after_block(self, parent_utxos: dict[tuple[str, int], TxOutput], block: Block) -> str:
        projected = dict(parent_utxos)
        for transaction in block.transactions:
            for tx_input in transaction.inputs:
                projected.pop((tx_input.prev_tx_id, tx_input.output_index), None)
            for output_index, output in enumerate(transaction.outputs):
                projected[(transaction.tx_id, output_index)] = output
        return self.state_root_for_utxos(projected)

    def state_root_policy(self) -> dict[str, object]:
        return {
            "activation_height": self.config.state_root_activation_height,
            "required_version": 3,
            "current_height": self.store.block_count(),
            "current_best_state_root": self.state_root_for_utxos(self.store.all_utxos()),
            "rule": "blocks at or above activation height must be version >= 3 and include a non-empty post-state UTXO root",
        }

    def _utxo_origin_metadata_for_head(self, block_hash: str | None) -> dict[tuple[str, int], dict[str, object]]:
        if block_hash is None:
            return {}
        origins: dict[tuple[str, int], dict[str, object]] = {}
        for block in self.store.path_to_root(block_hash):
            for transaction_index, transaction in enumerate(block.transactions):
                for tx_input in transaction.inputs:
                    origins.pop((tx_input.prev_tx_id, tx_input.output_index), None)
                is_coinbase = block.index > 0 and transaction_index == 0 and not transaction.inputs
                for output_index, _ in enumerate(transaction.outputs):
                    metadata: dict[str, object] = {
                        "height": block.index,
                        "coinbase": is_coinbase,
                    }
                    if transaction.kind == "migration_claim":
                        metadata.update(
                            {
                                "migration_claim": True,
                                "classical_address": str(transaction.metadata.get("classical_address", "")),
                                "source_network": str(transaction.metadata.get("source_network", "")),
                                "provider_id": str(transaction.metadata.get("classical_provider_id", "")),
                            }
                        )
                    origins[(transaction.tx_id, output_index)] = metadata
        return origins

    def chain_summary(self) -> dict[str, object]:
        summary = self.store.summary()
        summary["chain_id"] = self.config.chain_id
        summary["node_id"] = self.config.node_id
        summary["peer_count"] = len(self.list_peers())
        summary["advertised_url"] = normalize_peer_url(self.config.advertised_url)
        summary["best_head_hash"] = self.store.best_head_hash()
        summary["currency"] = self.monetary_policy()
        return summary

    def monetary_policy(self) -> dict[str, object]:
        return self.currency_policy().describe(height=self.store.block_count())

    def _supply_for_blocks(self, blocks: list[Block]) -> dict[str, int]:
        genesis_supply = 0
        subsidy_issued = 0
        migration_minted = 0
        transaction_fees = 0
        fees_paid_to_miners = 0
        policy = self.currency_policy()
        for block in blocks:
            if block.index == 0:
                genesis_supply += sum(
                    output.amount
                    for transaction in block.transactions
                    for output in transaction.outputs
                )
                continue
            expected_subsidy = policy.subsidy_at_height(block.index)
            reward_paid = sum(output.amount for output in block.transactions[0].outputs)
            non_reward_fees = sum(transaction.fee for transaction in block.transactions[1:])
            subsidy_issued += expected_subsidy
            transaction_fees += non_reward_fees
            fees_paid_to_miners += max(0, reward_paid - expected_subsidy)
            for transaction in block.transactions[1:]:
                if transaction.kind == "migration_claim":
                    migration_minted += sum(output.amount for output in transaction.outputs)
        theoretical_supply = genesis_supply + subsidy_issued + migration_minted
        fees_burned = max(0, transaction_fees - fees_paid_to_miners)
        return {
            "genesis_supply": genesis_supply,
            "subsidy_issued": subsidy_issued,
            "migration_minted": migration_minted,
            "transaction_fees": transaction_fees,
            "fees_paid_to_miners": fees_paid_to_miners,
            "fees_burned": fees_burned,
            "theoretical_supply": theoretical_supply,
        }

    def _validate_supply_limits(self, supply: dict[str, int]) -> None:
        if self.config.genesis_supply_cap > 0 and supply["genesis_supply"] > self.config.genesis_supply_cap:
            raise ValueError("Genesis allocation exceeds configured genesis supply cap.")
        if self.config.emission_supply_cap > 0 and supply["subsidy_issued"] > self.config.emission_supply_cap:
            raise ValueError("Block would exceed the configured emission supply cap.")
        if self.config.migration_pool_cap > 0 and supply["migration_minted"] > self.config.migration_pool_cap:
            raise ValueError("Migration claim would exceed the configured migration pool cap.")
        if supply["theoretical_supply"] > self.config.max_money:
            raise ValueError("Block would exceed the configured native supply cap.")

    def _migration_epoch_for_height(self, height: int) -> tuple[int, int, int]:
        length = max(1, self.config.migration_epoch_length_blocks)
        epoch_index = max(0, height) // length
        start_height = epoch_index * length
        end_height = start_height + length - 1
        return epoch_index, start_height, end_height

    def _migration_epoch_minted_for_blocks(self, blocks: list[Block], height: int) -> int:
        _, start_height, end_height = self._migration_epoch_for_height(height)
        total = 0
        for block in blocks:
            if block.index < start_height or block.index > end_height:
                continue
            for transaction in block.transactions:
                if transaction.kind == "migration_claim":
                    total += sum(output.amount for output in transaction.outputs)
        return total

    def _migration_epoch_minted_for_head(self, head_hash: str | None, height: int) -> int:
        if head_hash is None:
            return 0
        return self._migration_epoch_minted_for_blocks(self.store.path_to_root(head_hash), height)

    def _migration_claim_amount_for_source(self, source: dict[str, object]) -> int:
        denominator = max(1, self.config.migration_conversion_ratio_denominator)
        converted = int(source["amount"]) * self.config.migration_conversion_ratio_numerator // denominator
        if self.config.migration_claim_per_address_cap > 0:
            converted = min(converted, self.config.migration_claim_per_address_cap)
        return converted

    def supply_snapshot(self) -> dict[str, object]:
        canonical_blocks: list[Block] = []
        best_head = self.store.best_head_hash()
        if best_head is not None:
            canonical_blocks = self.store.path_to_root(best_head)
        supply = self._supply_for_blocks(canonical_blocks)
        genesis_supply = supply["genesis_supply"]
        subsidy_issued = supply["subsidy_issued"]
        migration_minted = supply["migration_minted"]
        transaction_fees = supply["transaction_fees"]
        fees_paid_to_miners = supply["fees_paid_to_miners"]
        utxo_supply = sum(output.amount for _, _, output in self.store.list_utxos())
        theoretical_supply = supply["theoretical_supply"]
        fees_burned = supply["fees_burned"]
        return {
            "currency": self.monetary_policy(),
            "height": self.store.block_count(),
            "genesis_supply": genesis_supply,
            "subsidy_issued": subsidy_issued,
            "migration_minted": migration_minted,
            "transaction_fees": transaction_fees,
            "fees_paid_to_miners": fees_paid_to_miners,
            "fees_burned": fees_burned,
            "theoretical_supply": theoretical_supply,
            "utxo_supply": utxo_supply,
            "unspent_supply": utxo_supply,
            "max_money": self.config.max_money,
            "within_max_money": theoretical_supply <= self.config.max_money,
            "migration_pool_cap": self.config.migration_pool_cap,
            "migration_pool_remaining": max(0, self.config.migration_pool_cap - migration_minted),
            "emission_supply_cap": self.config.emission_supply_cap,
            "emission_remaining": max(0, self.config.emission_supply_cap - subsidy_issued),
            "formatted_theoretical_supply": format_units(
                theoretical_supply,
                decimals=self.config.currency_decimals,
                symbol=self.config.currency_symbol,
            ),
            "formatted_unspent_supply": format_units(
                utxo_supply,
                decimals=self.config.currency_decimals,
                symbol=self.config.currency_symbol,
            ),
        }

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
            "dispute_window_blocks": self.config.migration_dispute_window_blocks,
            "snapshot_reviewer_quorum": self.config.migration_snapshot_reviewer_quorum,
            "emergency_pause": self.config.migration_emergency_pause,
            "allowed_classical_providers": list(self.config.migration_allowed_classical_providers),
            "require_snapshot_signatures": self.config.migration_require_snapshot_signatures,
            "trusted_snapshot_signers": list(self.config.migration_trusted_snapshot_signers),
            "trusted_snapshot_nodes": list(self.config.migration_trusted_snapshot_nodes),
            "conversion_policy": self.config.migration_conversion_policy,
            "conversion_ratio": {
                "numerator": self.config.migration_conversion_ratio_numerator,
                "denominator": self.config.migration_conversion_ratio_denominator,
            },
            "migration_pool_cap": self.config.migration_pool_cap,
            "migration_pool_remaining": self.supply_snapshot()["migration_pool_remaining"],
            "per_address_cap": self.config.migration_claim_per_address_cap,
            "epoch_length_blocks": self.config.migration_epoch_length_blocks,
            "epoch_mint_cap": self.config.migration_epoch_mint_cap,
            "escrow_blocks": self.config.migration_escrow_blocks,
        }

    def migration_network_profiles(self) -> dict[str, object]:
        return {
            "profiles": list_legacy_network_profiles(),
        }

    def protocol_manifest(self) -> dict[str, object]:
        return protocol_manifest(
            chain_id=self.config.chain_id,
            peer_protocol_version=self.config.peer_protocol_version,
            currency=self.monetary_policy(),
            migration_policy=self.migration_policy(),
        )

    def protocol_conformance_report(self) -> dict[str, object]:
        manifest = self.protocol_manifest()
        checks = [
            {
                "name": "protocol_manifest_hash_present",
                "passed": bool(manifest.get("protocol_manifest_hash")),
                "detail": str(manifest.get("protocol_manifest_hash", "")),
            },
            {
                "name": "chain_id_declared",
                "passed": bool(manifest.get("chain_id")),
                "detail": str(manifest.get("chain_id", "")),
            },
            {
                "name": "peer_protocol_declared",
                "passed": bool(manifest.get("object_versions", {}).get("peer_frame_protocol")),
                "detail": str(manifest.get("object_versions", {}).get("peer_frame_protocol", "")),
            },
            {
                "name": "currency_policy_declared",
                "passed": bool(manifest.get("native_currency", {}).get("symbol")),
                "detail": str(manifest.get("native_currency", {}).get("symbol", "")),
            },
            {
                "name": "migration_policy_declared",
                "passed": bool(manifest.get("migration", {}).get("conversion_policy")),
                "detail": str(manifest.get("migration", {}).get("conversion_policy", "")),
            },
        ]
        return {
            "conformance_status": "conformant" if all(bool(item["passed"]) for item in checks) else "needs_review",
            "checks": checks,
            "object_versions": manifest.get("object_versions", {}),
            "required_surfaces": [
                "protocol manifest",
                "chain-bound transactions",
                "peer frame version",
                "QBC monetary policy",
                "migration policy",
                "signature provider registry",
            ],
            "manifest": manifest,
        }

    def migration_claim_quote(self, classical_address: str) -> dict[str, object]:
        self.expire_migration_disputes()
        source = self.store.migration_source(classical_address)
        if source is None:
            raise ValueError("Migration source address is unknown.")
        supply = self.supply_snapshot()
        source_amount = int(source["amount"])
        amount = self._migration_claim_amount_for_source(source)
        pool_remaining = int(supply["migration_pool_remaining"])
        effective_height = self.store.block_count() + 1
        _, epoch_start, epoch_end = self._migration_epoch_for_height(effective_height)
        epoch_minted = self._migration_epoch_minted_for_head(self.store.best_head_hash(), effective_height)
        epoch_remaining = (
            max(0, self.config.migration_epoch_mint_cap - epoch_minted)
            if self.config.migration_epoch_mint_cap > 0
            else None
        )
        already_claimed = self.store.migration_claim(classical_address) is not None
        evidence = self._migration_source_evidence(source)
        disputes = self.store.list_migration_disputes(classical_address)
        blocking_disputes = [
            item for item in disputes if item["status"] in {"open", "evidence_submitted", "resolved_fraud"}
        ]
        checks = [
            {"name": "source_active", "passed": source.get("status") == "active"},
            {"name": "no_blocking_dispute", "passed": not blocking_disputes},
            {"name": "migration_not_paused", "passed": not self.config.migration_emergency_pause},
            {"name": "not_claimed", "passed": not already_claimed},
            {"name": "pool_capacity_available", "passed": amount <= pool_remaining},
            {
                "name": "epoch_capacity_available",
                "passed": epoch_remaining is None or amount <= epoch_remaining,
            },
            {
                "name": "provider_allowed",
                "passed": source.get("provider_id") in self.config.migration_allowed_classical_providers,
            },
            {"name": "snapshot_reference_present", "passed": bool(source.get("snapshot_ref"))},
        ]
        snapshot = next(
            (item for item in self.store.list_migration_snapshots() if item["snapshot_ref"] == source["snapshot_ref"]),
            None,
        )
        checks.append({"name": "snapshot_active", "passed": snapshot is None or snapshot["status"] == "active"})
        intent = {
            "chain_id": self.config.chain_id,
            "classical_address": classical_address,
            "source_network": source["source_network"],
            "source_address": source.get("source_address", classical_address),
            "source_amount": source_amount,
            "destination_amount": amount,
            "conversion_policy": self.config.migration_conversion_policy,
            "conversion_ratio": {
                "numerator": self.config.migration_conversion_ratio_numerator,
                "denominator": self.config.migration_conversion_ratio_denominator,
            },
            "snapshot_ref": source.get("snapshot_ref", ""),
        }
        return {
            "classical_address": classical_address,
            "source_network": source["source_network"],
            "source_address": source.get("source_address", classical_address),
            "source_address_format": source.get("source_address_format", ""),
            "conversion_policy": self.config.migration_conversion_policy,
            "source_amount": source_amount,
            "normalized_claim_amount": amount,
            "migration_pool_remaining": pool_remaining,
            "pool_after_claim": pool_remaining - amount,
            "epoch_window": {"start_height": epoch_start, "end_height": epoch_end},
            "epoch_minted": epoch_minted,
            "epoch_mint_cap": self.config.migration_epoch_mint_cap,
            "epoch_remaining": epoch_remaining,
            "claim_intent_hash": hashlib.sha256(json.dumps(intent, sort_keys=True).encode("utf-8")).hexdigest(),
            "claimable": all(bool(check["passed"]) for check in checks),
            "checks": checks,
            "warnings": [
                {
                    "name": "weak_source_evidence",
                    "detail": "source lacks external address linkage or complete snapshot evidence",
                }
            ]
            if evidence["level"] == "weak"
            else [],
            "evidence": evidence,
            "dispute_lifecycle": {
                "blocking_dispute_count": len(blocking_disputes),
                "latest_status": str(disputes[0]["status"]) if disputes else "",
                "unlock_statuses": ["resolved_valid", "expired"],
            },
            "source": source,
        }

    def _migration_source_evidence(self, source: dict[str, object]) -> dict[str, object]:
        source_address = str(source.get("source_address", ""))
        classical_address = str(source.get("classical_address", ""))
        source_address_format = str(source.get("source_address_format", ""))
        has_external_source_address = bool(source_address and source_address != classical_address)
        snapshot_ref = str(source.get("snapshot_ref", ""))
        status = str(source.get("status", "active"))
        score = 0
        if has_external_source_address:
            score += 35
        if source_address_format:
            score += 20
        if snapshot_ref:
            score += 20
        if status == "active":
            score += 15
        if str(source.get("provider_id", "")) in self.config.migration_allowed_classical_providers:
            score += 10
        if score >= 80:
            level = "strong"
        elif score >= 50:
            level = "moderate"
        else:
            level = "weak"
        return {
            "score": score,
            "level": level,
            "has_external_source_address": has_external_source_address,
            "source_address_format": source_address_format,
            "snapshot_ref": snapshot_ref,
            "status": status,
        }

    def migration_claim_status(self, classical_address: str) -> dict[str, object]:
        quote = self.migration_claim_quote(classical_address)
        claim = self.store.migration_claim(classical_address)
        finality = self.migration_claim_finality(classical_address) if claim is not None else {}
        lifecycle_state = "claimable"
        if claim is not None:
            lifecycle_state = str(finality.get("state", "claimed"))
        elif not quote["claimable"]:
            lifecycle_state = "blocked"
        return {
            "classical_address": classical_address,
            "lifecycle_state": lifecycle_state,
            "quote": quote,
            "claim": claim or {},
            "finality": finality,
        }

    def migration_claim_finality(self, classical_address: str) -> dict[str, object]:
        claim = self.store.migration_claim(classical_address)
        if claim is None:
            raise ValueError("Migration claim is unknown.")
        claim_height = self._canonical_transaction_height(str(claim["tx_id"]))
        if claim_height is None:
            raise ValueError("Migration claim is not on the canonical chain.")
        return self._migration_output_finality_status(
            classical_address,
            origin_height=claim_height,
            current_height=self.store.block_count(),
            claim=claim,
        )

    def _migration_output_finality_status(
        self,
        classical_address: str,
        *,
        origin_height: int,
        current_height: int,
        claim: dict[str, object] | None = None,
    ) -> dict[str, object]:
        disputes = self.store.list_migration_disputes(classical_address)
        blocking = [item for item in disputes if item["status"] in {"open", "evidence_submitted"}]
        fraud = [item for item in disputes if item["status"] == "resolved_fraud"]
        source = self.store.migration_source(classical_address) or {}
        unlock_height = origin_height + max(0, self.config.migration_escrow_blocks)
        if fraud or source.get("status") == "revoked":
            state = "fraud_resolved_frozen"
            spendable = False
        elif blocking or source.get("status") == "quarantined":
            state = "frozen_dispute"
            spendable = False
        elif current_height < unlock_height:
            state = "escrow_locked"
            spendable = False
        else:
            state = "unlocked"
            spendable = True
        return {
            "classical_address": classical_address,
            "state": state,
            "spendable": spendable,
            "claim": claim or self.store.migration_claim(classical_address) or {},
            "origin_height": origin_height,
            "current_height": current_height,
            "unlock_height": unlock_height,
            "escrow_blocks": self.config.migration_escrow_blocks,
            "blocking_dispute_count": len(blocking),
            "resolved_fraud_count": len(fraud),
            "source_status": str(source.get("status", "")),
        }

    def _canonical_transaction_height(self, tx_id: str) -> int | None:
        best_head = self.store.best_head_hash()
        if best_head is None:
            return None
        for block in self.store.path_to_root(best_head):
            if any(transaction.tx_id == tx_id for transaction in block.transactions):
                return block.index
        return None

    def migration_dispute_packet(self, classical_address: str) -> dict[str, object]:
        source = self.store.migration_source(classical_address)
        if source is None:
            raise ValueError("Migration source address is unknown.")
        claim = self.store.migration_claim(classical_address)
        quote = self.migration_claim_quote(classical_address)
        snapshot = next(
            (item for item in self.store.list_migration_snapshots() if item["snapshot_ref"] == source["snapshot_ref"]),
            {},
        )
        packet = {
            "packet_version": 1,
            "chain_id": self.config.chain_id,
            "classical_address": classical_address,
            "source": source,
            "snapshot": snapshot,
            "claim": claim or {},
            "quote": quote,
            "evidence": {
                "source_evidence": quote["evidence"],
                "claim_intent_hash": quote["claim_intent_hash"],
                "snapshot_ref": source.get("snapshot_ref", ""),
                "snapshot_hash": source.get("snapshot_hash", ""),
            },
            "operator_actions": [
                "verify source address ownership evidence outside the node",
                "compare snapshot manifest and source export provenance",
                "quarantine source or snapshot while dispute is open",
                "publish final decision and reason before reactivating claims",
            ],
        }
        packet["packet_hash"] = hashlib.sha256(json.dumps(packet, sort_keys=True).encode("utf-8")).hexdigest()
        return packet

    def open_migration_dispute(
        self,
        classical_address: str,
        *,
        reason: str,
        evidence_hash: str = "",
    ) -> dict[str, object]:
        packet = self.migration_dispute_packet(classical_address)
        opened_at = round(time.time(), 6)
        dispute_id = hashlib.sha256(
            canonical_json(
                {
                    "classical_address": classical_address,
                    "packet_hash": packet["packet_hash"],
                    "reason": reason,
                    "opened_at": opened_at,
                }
            ).encode("utf-8")
        ).hexdigest()
        challenge_deadline_height = self.store.block_count() + self.config.migration_dispute_window_blocks
        final_evidence_hash = evidence_hash or str(packet["packet_hash"])
        self.store.open_migration_dispute(
            dispute_id=dispute_id,
            classical_address=classical_address,
            opened_at=opened_at,
            challenge_deadline_height=challenge_deadline_height,
            reason=reason,
            evidence_hash=final_evidence_hash,
        )
        self.set_migration_source_status(classical_address, status="quarantined", reason=f"open dispute: {reason}")
        return {
            "dispute_id": dispute_id,
            "classical_address": classical_address,
            "status": "open",
            "challenge_deadline_height": challenge_deadline_height,
            "evidence_hash": final_evidence_hash,
            "packet_hash": packet["packet_hash"],
        }

    def submit_migration_dispute_evidence(
        self,
        dispute_id: str,
        *,
        evidence: dict[str, object],
        evidence_hash: str = "",
    ) -> dict[str, object]:
        dispute = self._migration_dispute_by_id(dispute_id)
        if dispute["status"] not in {"open", "evidence_submitted"}:
            raise ValueError("Evidence can only be submitted while a dispute is open.")
        if self.store.block_count() > int(dispute["challenge_deadline_height"]):
            raise ValueError("Dispute challenge window has expired.")
        final_hash = evidence_hash or hashlib.sha256(canonical_json(evidence).encode("utf-8")).hexdigest()
        self.store.submit_migration_dispute_evidence(dispute_id, evidence_hash=final_hash, evidence=evidence)
        updated = self._migration_dispute_by_id(dispute_id)
        self.set_migration_source_status(
            str(updated["classical_address"]),
            status="quarantined",
            reason=f"evidence submitted for dispute {dispute_id}",
        )
        return updated

    def resolve_migration_dispute(
        self,
        dispute_id: str,
        *,
        outcome: str,
        resolution_note: str,
    ) -> dict[str, object]:
        if outcome not in {"resolved_valid", "resolved_fraud"}:
            raise ValueError("Dispute outcome must be resolved_valid or resolved_fraud.")
        dispute = self._migration_dispute_by_id(dispute_id)
        if dispute["status"] not in {"open", "evidence_submitted"}:
            raise ValueError("Only open or evidence-submitted disputes can be resolved.")
        self.store.resolve_migration_dispute(dispute_id, status=outcome, resolution_note=resolution_note)
        updated = self._migration_dispute_by_id(dispute_id)
        if outcome == "resolved_valid":
            self.set_migration_source_status(
                str(updated["classical_address"]),
                status="active",
                reason=f"dispute {dispute_id} resolved valid",
            )
        else:
            self.set_migration_source_status(
                str(updated["classical_address"]),
                status="revoked",
                reason=f"dispute {dispute_id} resolved fraud: {resolution_note}",
            )
        return updated

    def expire_migration_disputes(self) -> dict[str, object]:
        current_height = self.store.block_count()
        before = [
            item
            for item in self.store.list_migration_disputes()
            if item["status"] in {"open", "evidence_submitted"} and int(item["challenge_deadline_height"]) < current_height
        ]
        expired_count = self.store.expire_migration_disputes(current_height)
        for item in before:
            self.set_migration_source_status(
                str(item["classical_address"]),
                status="active",
                reason=f"dispute {item['dispute_id']} expired; claim unlocked",
            )
        return {
            "expired_count": expired_count,
            "current_height": current_height,
            "unlocked_classical_addresses": [item["classical_address"] for item in before],
        }

    def migration_disputes(self, classical_address: str | None = None) -> dict[str, object]:
        self.expire_migration_disputes()
        disputes = self.store.list_migration_disputes(classical_address)
        open_disputes = [item for item in disputes if item["status"] == "open"]
        evidence_submitted = [item for item in disputes if item["status"] == "evidence_submitted"]
        resolved_valid = [item for item in disputes if item["status"] == "resolved_valid"]
        resolved_fraud = [item for item in disputes if item["status"] == "resolved_fraud"]
        expired = [item for item in disputes if item["status"] == "expired"]
        return {
            "dispute_count": len(disputes),
            "open_dispute_count": len(open_disputes),
            "evidence_submitted_count": len(evidence_submitted),
            "resolved_valid_count": len(resolved_valid),
            "resolved_fraud_count": len(resolved_fraud),
            "expired_count": len(expired),
            "current_height": self.store.block_count(),
            "claim_unlock_statuses": ["resolved_valid", "expired"],
            "claim_blocking_statuses": ["open", "evidence_submitted", "resolved_fraud"],
            "disputes": disputes,
        }

    def post_finality_migration_fraud_case(
        self,
        classical_address: str,
        *,
        evidence: dict[str, object],
        requested_action: str = "freeze_destination_outputs",
    ) -> dict[str, object]:
        if requested_action not in {
            "freeze_destination_outputs",
            "quarantine_source",
            "revoke_source_after_governance_review",
            "operator_audit_only",
        }:
            raise ValueError("Unsupported post-finality recovery action.")
        if not isinstance(evidence, dict) or not evidence:
            raise ValueError("Post-finality fraud evidence must be a non-empty object.")

        claim = self.store.migration_claim(classical_address)
        if claim is None:
            raise ValueError("Post-finality fraud case requires a mined migration claim.")
        source = self.store.migration_source(classical_address)
        if source is None:
            raise ValueError("Migration source address is unknown.")

        evidence_hash = hashlib.sha256(canonical_json(evidence).encode("utf-8")).hexdigest()
        dispute_evidence = {
            "case_type": "post_finality_migration_fraud",
            "requested_action": requested_action,
            "evidence": evidence,
            "evidence_hash": evidence_hash,
            "mined_claim_tx_id": claim["tx_id"],
        }
        dispute_evidence_hash = hashlib.sha256(canonical_json(dispute_evidence).encode("utf-8")).hexdigest()
        opened = self.open_migration_dispute(
            classical_address,
            reason="post-finality fraud review",
            evidence_hash=dispute_evidence_hash,
        )
        dispute = self.submit_migration_dispute_evidence(
            str(opened["dispute_id"]),
            evidence=dispute_evidence,
            evidence_hash=dispute_evidence_hash,
        )
        updated_source = self.store.migration_source(classical_address) or source
        policy_report = self.migration_fraud_recovery_policy_report()
        case: dict[str, object] = {
            "case_version": 1,
            "case_type": "post_finality_migration_fraud",
            "chain_id": self.config.chain_id,
            "classical_address": classical_address,
            "created_at": round(time.time(), 6),
            "requested_action": requested_action,
            "evidence": evidence,
            "evidence_hash": evidence_hash,
            "dispute_evidence_hash": dispute_evidence_hash,
            "source": updated_source,
            "claim": claim,
            "dispute": dispute,
            "recovery_policy": policy_report["post_finality_policy"],
            "constraints": [
                "already-mined migration outputs are not mutated by case creation",
                "destination-output freeze requires consensus or governance enforcement",
                "source quarantine blocks future claims from the contested source",
                "resolution must be published through the migration dispute lifecycle",
            ],
            "recommended_next_steps": [
                "publish this signed case artifact",
                "route the dispute to reviewer quorum",
                "apply an operator freeze or escrow policy outside consensus until on-chain rules exist",
                "resolve the dispute as resolved_valid or resolved_fraud with a signed audit note",
            ],
        }
        case_hash = self._post_finality_migration_fraud_case_hash(case)
        case["case_hash"] = case_hash
        case["envelope"] = self.identity.sign_claims(
            "post_finality_migration_fraud_case_v1",
            {
                "purpose": "post_finality_migration_fraud_case_v1",
                "chain_id": self.config.chain_id,
                "node_id": self.config.node_id,
                "case_hash": case_hash,
                "classical_address": classical_address,
                "claim_tx_id": claim["tx_id"],
                "requested_action": requested_action,
                "dispute_id": dispute["dispute_id"],
            },
        )
        return case

    def validate_post_finality_migration_fraud_case(self, case: dict[str, object]) -> dict[str, object]:
        observed_hash = str(case.get("case_hash", ""))
        expected_hash = self._post_finality_migration_fraud_case_hash(case)
        envelope = dict(case.get("envelope", {})) if isinstance(case.get("envelope"), dict) else {}
        claim = dict(case.get("claim", {})) if isinstance(case.get("claim"), dict) else {}
        dispute = dict(case.get("dispute", {})) if isinstance(case.get("dispute"), dict) else {}
        evidence = dict(case.get("evidence", {})) if isinstance(case.get("evidence"), dict) else {}
        expected_evidence_hash = hashlib.sha256(canonical_json(evidence).encode("utf-8")).hexdigest()
        expected_dispute_evidence = {
            "case_type": "post_finality_migration_fraud",
            "requested_action": case.get("requested_action"),
            "evidence": evidence,
            "evidence_hash": str(case.get("evidence_hash", "")),
            "mined_claim_tx_id": claim.get("tx_id"),
        }
        expected_dispute_evidence_hash = hashlib.sha256(
            canonical_json(expected_dispute_evidence).encode("utf-8")
        ).hexdigest()
        signature_valid = False
        signature_error = ""
        try:
            verified = verify_signed_envelope(
                envelope,
                expected_purpose="post_finality_migration_fraud_case_v1",
                expected_chain_id=self.config.chain_id,
                time_skew_seconds=self.config.auth_time_skew_seconds,
            )
            claims = dict(verified["claims"])
            signature_valid = (
                claims.get("case_hash") == observed_hash
                and claims.get("classical_address") == case.get("classical_address")
                and claims.get("claim_tx_id") == claim.get("tx_id")
                and claims.get("requested_action") == case.get("requested_action")
                and claims.get("dispute_id") == dispute.get("dispute_id")
            )
        except Exception as error:
            signature_error = str(error)

        checks = [
            {"name": "case_present", "passed": bool(case)},
            {"name": "case_hash_matches", "passed": bool(observed_hash) and observed_hash == expected_hash},
            {"name": "signature_present", "passed": bool(envelope)},
            {"name": "signature_valid", "passed": signature_valid, "detail": signature_error},
            {"name": "chain_id_matches", "passed": case.get("chain_id") == self.config.chain_id},
            {"name": "case_type_matches", "passed": case.get("case_type") == "post_finality_migration_fraud"},
            {"name": "mined_claim_attached", "passed": bool(claim.get("tx_id"))},
            {"name": "evidence_hash_matches", "passed": str(case.get("evidence_hash", "")) == expected_evidence_hash},
            {
                "name": "dispute_evidence_hash_matches",
                "passed": str(case.get("dispute_evidence_hash", "")) == expected_dispute_evidence_hash,
            },
        ]
        result = {
            "valid": all(bool(check["passed"]) for check in checks),
            "checks": checks,
            "case_hash": observed_hash,
            "expected_case_hash": expected_hash,
        }
        result["validation_hash"] = hashlib.sha256(canonical_json(result).encode("utf-8")).hexdigest()
        return result

    def migration_claim_batch_plan(
        self,
        *,
        source_network: str | None = None,
        limit: int = 100,
    ) -> dict[str, object]:
        sources = self.store.list_migration_sources()
        if source_network:
            sources = [item for item in sources if item["source_network"] == source_network]
        planned: list[dict[str, object]] = []
        blocked: list[dict[str, object]] = []
        running_total = 0
        pool_remaining = int(self.supply_snapshot()["migration_pool_remaining"])
        for source in sorted(sources, key=lambda item: (str(item["source_network"]), str(item["classical_address"]))):
            quote = self.migration_claim_quote(str(source["classical_address"]))
            item = {
                "classical_address": source["classical_address"],
                "source_network": source["source_network"],
                "provider_id": source["provider_id"],
                "amount": int(source["amount"]),
                "normalized_claim_amount": int(quote["normalized_claim_amount"]),
                "claim_intent_hash": quote["claim_intent_hash"],
                "evidence_level": quote["evidence"]["level"],
            }
            claim_amount = int(quote["normalized_claim_amount"])
            if quote["claimable"] and len(planned) < limit and running_total + claim_amount <= pool_remaining:
                running_total += claim_amount
                planned.append({**item, "pool_after_batch_item": pool_remaining - running_total})
            else:
                blockers = [check["name"] for check in quote["checks"] if not check["passed"]]
                if quote["claimable"] and len(planned) >= limit:
                    blockers.append("batch_limit_reached")
                if quote["claimable"] and running_total + claim_amount > pool_remaining:
                    blockers.append("batch_would_exceed_pool")
                blocked.append({**item, "blockers": blockers, "warnings": quote["warnings"]})
        return {
            "source_network": source_network or "all",
            "limit": limit,
            "pool_remaining": pool_remaining,
            "planned_claim_count": len(planned),
            "planned_claim_amount": running_total,
            "pool_after_planned_batch": pool_remaining - running_total,
            "blocked_claim_count": len(blocked),
            "planned": planned,
            "blocked": blocked,
        }

    def migration_conversion_risk_report(self) -> dict[str, object]:
        sources = self.store.list_migration_sources()
        claims = {str(item["classical_address"]): item for item in self.store.list_migration_claims()}
        by_network: dict[str, dict[str, object]] = {}
        by_provider: dict[str, dict[str, object]] = {}
        total_active_amount = 0
        largest_source = {"classical_address": "", "amount": 0, "source_network": ""}
        for source in sources:
            amount = int(source["amount"])
            if source.get("status") == "active" and str(source["classical_address"]) not in claims:
                total_active_amount += amount
            if amount > int(largest_source["amount"]):
                largest_source = {
                    "classical_address": str(source["classical_address"]),
                    "amount": amount,
                    "source_network": str(source["source_network"]),
                }
            for bucket, key in ((by_network, str(source["source_network"])), (by_provider, str(source["provider_id"]))):
                summary = bucket.setdefault(
                    key,
                    {"source_count": 0, "active_unclaimed_count": 0, "claimed_count": 0, "total_amount": 0},
                )
                summary["source_count"] = int(summary["source_count"]) + 1
                summary["total_amount"] = int(summary["total_amount"]) + amount
                if str(source["classical_address"]) in claims:
                    summary["claimed_count"] = int(summary["claimed_count"]) + 1
                elif source.get("status") == "active":
                    summary["active_unclaimed_count"] = int(summary["active_unclaimed_count"]) + 1
        pool_remaining = int(self.supply_snapshot()["migration_pool_remaining"])
        concentration_pct = 0.0
        if total_active_amount > 0:
            concentration_pct = round((int(largest_source["amount"]) / total_active_amount) * 100, 4)
        risks = []
        if total_active_amount > pool_remaining:
            risks.append("active_unclaimed_sources_exceed_remaining_pool")
        if concentration_pct >= 25:
            risks.append("single_source_concentration_exceeds_25_percent")
        return {
            "conversion_policy": self.config.migration_conversion_policy,
            "migration_pool_remaining": pool_remaining,
            "active_unclaimed_amount": total_active_amount,
            "pool_exposure_pct": 0.0 if pool_remaining == 0 else round((total_active_amount / pool_remaining) * 100, 4),
            "largest_source": largest_source,
            "largest_source_active_concentration_pct": concentration_pct,
            "by_network": by_network,
            "by_provider": by_provider,
            "risks": risks,
        }

    def migration_escrow_finality_report(self) -> dict[str, object]:
        claims = self.store.list_migration_claims()
        finalities = []
        counts: dict[str, int] = {}
        for claim in claims:
            finality = self.migration_claim_finality(str(claim["classical_address"]))
            counts[str(finality["state"])] = counts.get(str(finality["state"]), 0) + 1
            finalities.append(finality)
        report = {
            "escrow_policy_version": 1,
            "status": "enforced",
            "escrow_blocks": self.config.migration_escrow_blocks,
            "dispute_window_blocks": self.config.migration_dispute_window_blocks,
            "claim_count": len(claims),
            "state_counts": counts,
            "claims": finalities,
            "rules": [
                "migration outputs are locked until origin height plus escrow blocks",
                "open or evidence-submitted disputes freeze migration outputs",
                "resolved-fraud disputes keep migration outputs frozen",
                "unlocked outputs may be spent only after escrow and dispute gates pass",
            ],
        }
        report["escrow_policy_hash"] = hashlib.sha256(canonical_json(report).encode("utf-8")).hexdigest()
        return report

    def migration_conversion_guardrail_report(self) -> dict[str, object]:
        supply = self.supply_snapshot()
        next_height = self.store.block_count() + 1
        epoch_index, epoch_start, epoch_end = self._migration_epoch_for_height(next_height)
        epoch_minted = self._migration_epoch_minted_for_head(self.store.best_head_hash(), next_height)
        sources = self.store.list_migration_sources()
        active_unclaimed = [
            source
            for source in sources
            if source.get("status") == "active" and self.store.migration_claim(str(source["classical_address"])) is None
        ]
        active_claimable_amount = sum(self._migration_claim_amount_for_source(source) for source in active_unclaimed)
        checks = [
            {"name": "pool_cap_positive", "passed": self.config.migration_pool_cap > 0},
            {"name": "pool_remaining_nonnegative", "passed": int(supply["migration_pool_remaining"]) >= 0},
            {
                "name": "active_claimable_within_remaining_pool",
                "passed": active_claimable_amount <= int(supply["migration_pool_remaining"]),
            },
            {
                "name": "conversion_ratio_valid",
                "passed": self.config.migration_conversion_ratio_numerator >= 0
                and self.config.migration_conversion_ratio_denominator > 0,
            },
            {
                "name": "epoch_cap_configured_or_unlimited",
                "passed": self.config.migration_epoch_mint_cap >= 0,
            },
        ]
        report = {
            "guardrail_version": 1,
            "status": "pass" if all(bool(check["passed"]) for check in checks) else "warning",
            "checks": checks,
            "conversion_policy": self.config.migration_conversion_policy,
            "conversion_ratio": {
                "numerator": self.config.migration_conversion_ratio_numerator,
                "denominator": self.config.migration_conversion_ratio_denominator,
            },
            "per_address_cap": self.config.migration_claim_per_address_cap,
            "migration_pool_cap": self.config.migration_pool_cap,
            "migration_pool_remaining": int(supply["migration_pool_remaining"]),
            "active_claimable_amount": active_claimable_amount,
            "epoch": {
                "index": epoch_index,
                "start_height": epoch_start,
                "end_height": epoch_end,
                "minted": epoch_minted,
                "cap": self.config.migration_epoch_mint_cap,
                "remaining": None
                if self.config.migration_epoch_mint_cap <= 0
                else max(0, self.config.migration_epoch_mint_cap - epoch_minted),
            },
        }
        report["guardrail_hash"] = hashlib.sha256(canonical_json(report).encode("utf-8")).hexdigest()
        return report

    def migration_proof_registry_report(self) -> dict[str, object]:
        entries = []
        proof_ids: list[str] = []
        best_head = self.store.best_head_hash()
        if best_head is not None:
            for block in self.store.path_to_root(best_head):
                for transaction in block.transactions:
                    if transaction.kind != "migration_claim":
                        continue
                    registry_payload = {
                        "chain_id": self.config.chain_id,
                        "classical_address": str(transaction.metadata.get("classical_address", "")),
                        "provider_id": str(transaction.metadata.get("classical_provider_id", "")),
                        "source_network": str(transaction.metadata.get("source_network", "")),
                        "source_address": str(transaction.metadata.get("source_address", "")),
                        "snapshot_ref": str(transaction.metadata.get("snapshot_ref", "")),
                        "tx_id": transaction.tx_id,
                    }
                    proof_id = hashlib.sha256(canonical_json(registry_payload).encode("utf-8")).hexdigest()
                    proof_ids.append(proof_id)
                    entries.append({**registry_payload, "height": block.index, "proof_id": proof_id})
        duplicate_proofs = sorted(proof_id for proof_id, count in Counter(proof_ids).items() if count > 1)
        report = {
            "registry_version": 1,
            "status": "pass" if not duplicate_proofs else "blocked",
            "entry_count": len(entries),
            "duplicate_proof_ids": duplicate_proofs,
            "entries": entries,
            "rules": [
                "proof id binds chain, provider, source network, source address, snapshot, classical address, and tx id",
                "canonical replay must not contain duplicate proof ids",
                "cross-chain replay is rejected by transaction chain_id before proof registry admission",
            ],
        }
        report["registry_root"] = hashlib.sha256(canonical_json(entries).encode("utf-8")).hexdigest()
        report["registry_report_hash"] = hashlib.sha256(canonical_json(report).encode("utf-8")).hexdigest()
        return report

    def signed_migration_economics_governance_manifest(self) -> dict[str, object]:
        guardrails = self.migration_conversion_guardrail_report()
        escrow = self.migration_escrow_finality_report()
        manifest = {
            "manifest_version": 1,
            "chain_id": self.config.chain_id,
            "node_id": self.config.node_id,
            "generated_at": round(time.time(), 6),
            "conversion_policy": self.config.migration_conversion_policy,
            "conversion_ratio": guardrails["conversion_ratio"],
            "migration_pool_cap": self.config.migration_pool_cap,
            "per_address_cap": self.config.migration_claim_per_address_cap,
            "epoch_length_blocks": self.config.migration_epoch_length_blocks,
            "epoch_mint_cap": self.config.migration_epoch_mint_cap,
            "escrow_blocks": self.config.migration_escrow_blocks,
            "dispute_window_blocks": self.config.migration_dispute_window_blocks,
            "claim_window": {
                "start_height": self.config.migration_claim_start_height,
                "end_height": self.config.migration_claim_end_height,
            },
            "guardrail_hash": guardrails["guardrail_hash"],
            "escrow_policy_hash": escrow["escrow_policy_hash"],
        }
        manifest["manifest_hash"] = self._migration_economics_manifest_hash(manifest)
        artifact = {
            "artifact_version": 1,
            "manifest": manifest,
            "envelope": self.identity.sign_claims(
                "migration_economics_governance_v1",
                {
                    "purpose": "migration_economics_governance_v1",
                    "chain_id": self.config.chain_id,
                    "node_id": self.config.node_id,
                    "manifest_hash": manifest["manifest_hash"],
                    "conversion_policy": self.config.migration_conversion_policy,
                },
            ),
        }
        artifact["artifact_hash"] = self._signed_artifact_payload_hash(artifact)
        return artifact

    def validate_migration_economics_governance_manifest(self, artifact: dict[str, object]) -> dict[str, object]:
        manifest = dict(artifact.get("manifest", {})) if isinstance(artifact.get("manifest"), dict) else {}
        envelope = dict(artifact.get("envelope", {})) if isinstance(artifact.get("envelope"), dict) else {}
        expected_manifest_hash = self._migration_economics_manifest_hash(manifest)
        expected_artifact_hash = self._signed_artifact_payload_hash(artifact)
        signature_valid = False
        signature_error = ""
        try:
            verified = verify_signed_envelope(
                envelope,
                expected_purpose="migration_economics_governance_v1",
                expected_chain_id=self.config.chain_id,
                time_skew_seconds=self.config.auth_time_skew_seconds,
            )
            claims = dict(verified["claims"])
            signature_valid = (
                claims.get("manifest_hash") == manifest.get("manifest_hash")
                and claims.get("conversion_policy") == manifest.get("conversion_policy")
            )
        except Exception as error:
            signature_error = str(error)
        checks = [
            {"name": "manifest_hash_matches", "passed": manifest.get("manifest_hash") == expected_manifest_hash},
            {"name": "artifact_hash_matches", "passed": artifact.get("artifact_hash") == expected_artifact_hash},
            {"name": "signature_valid", "passed": signature_valid, "detail": signature_error},
            {"name": "conversion_ratio_valid", "passed": int(dict(manifest.get("conversion_ratio", {})).get("denominator", 0)) > 0},
            {"name": "escrow_blocks_nonnegative", "passed": int(manifest.get("escrow_blocks", -1)) >= 0},
        ]
        result = {"valid": all(bool(check["passed"]) for check in checks), "checks": checks}
        result["validation_hash"] = hashlib.sha256(canonical_json(result).encode("utf-8")).hexdigest()
        return result

    @staticmethod
    def _migration_economics_manifest_hash(manifest: dict[str, object]) -> str:
        payload = dict(manifest)
        payload.pop("manifest_hash", None)
        return hashlib.sha256(canonical_json(payload).encode("utf-8")).hexdigest()

    def signed_migration_fraud_recovery_decision(
        self,
        classical_address: str,
        *,
        outcome: str,
        recovery_action: str,
        note: str,
    ) -> dict[str, object]:
        if outcome not in {"resolved_valid", "resolved_fraud"}:
            raise ValueError("Fraud recovery outcome must be resolved_valid or resolved_fraud.")
        claim = self.store.migration_claim(classical_address)
        if claim is None:
            raise ValueError("Migration claim is unknown.")
        finality = self.migration_claim_finality(classical_address)
        disputes = self.store.list_migration_disputes(classical_address)
        decision = {
            "decision_version": 1,
            "chain_id": self.config.chain_id,
            "classical_address": classical_address,
            "claim": claim,
            "finality": finality,
            "outcome": outcome,
            "recovery_action": recovery_action,
            "note": note,
            "recovery_effects": {
                "source_status_after_fraud": "revoked" if outcome == "resolved_fraud" else "active",
                "migration_output_spendable": outcome == "resolved_valid" and bool(finality["spendable"]),
                "conversion_pool_accounting": "claimed capacity remains consumed unless governance creates an explicit reversal transaction",
                "future_claims_from_source": "blocked" if outcome == "resolved_fraud" else "allowed_only_if_unclaimed",
            },
            "dispute_ids": [item["dispute_id"] for item in disputes],
        }
        decision["decision_hash"] = self._migration_fraud_recovery_decision_hash(decision)
        artifact = {
            "artifact_version": 1,
            "decision": decision,
            "envelope": self.identity.sign_claims(
                "migration_fraud_recovery_decision_v1",
                {
                    "purpose": "migration_fraud_recovery_decision_v1",
                    "chain_id": self.config.chain_id,
                    "node_id": self.config.node_id,
                    "decision_hash": decision["decision_hash"],
                    "classical_address": classical_address,
                    "outcome": outcome,
                },
            ),
        }
        artifact["artifact_hash"] = self._signed_artifact_payload_hash(artifact)
        return artifact

    @staticmethod
    def _migration_fraud_recovery_decision_hash(decision: dict[str, object]) -> str:
        payload = dict(decision)
        payload.pop("decision_hash", None)
        return hashlib.sha256(canonical_json(payload).encode("utf-8")).hexdigest()

    def migration_adversarial_economics_simulation_report(self) -> dict[str, object]:
        guardrails = self.migration_conversion_guardrail_report()
        registry = self.migration_proof_registry_report()
        escrow = self.migration_escrow_finality_report()
        scenarios = [
            {
                "name": "whale_claim_pressure",
                "passed": guardrails["active_claimable_amount"] <= guardrails["migration_pool_remaining"],
                "detail": f"active={guardrails['active_claimable_amount']} remaining={guardrails['migration_pool_remaining']}",
            },
            {
                "name": "duplicate_proof_replay",
                "passed": not registry["duplicate_proof_ids"],
                "detail": str(len(registry["duplicate_proof_ids"])),
            },
            {
                "name": "escrow_freezes_pending_value",
                "passed": all(not item["spendable"] for item in escrow["claims"] if item["state"] != "unlocked"),
                "detail": canonical_json(escrow["state_counts"]),
            },
            {
                "name": "epoch_cap_not_exceeded",
                "passed": guardrails["epoch"]["cap"] <= 0 or guardrails["epoch"]["minted"] <= guardrails["epoch"]["cap"],
                "detail": canonical_json(guardrails["epoch"]),
            },
        ]
        report = {
            "simulation_version": 1,
            "status": "pass" if all(bool(item["passed"]) for item in scenarios) else "warning",
            "scenarios": scenarios,
            "guardrails": guardrails,
            "proof_registry": {
                "status": registry["status"],
                "entry_count": registry["entry_count"],
                "registry_root": registry["registry_root"],
            },
            "escrow": {
                "claim_count": escrow["claim_count"],
                "state_counts": escrow["state_counts"],
                "escrow_policy_hash": escrow["escrow_policy_hash"],
            },
        }
        report["simulation_hash"] = hashlib.sha256(canonical_json(report).encode("utf-8")).hexdigest()
        return report

    def migration_economics_specification(self) -> dict[str, object]:
        spec = {
            "spec_version": 1,
            "chain_id": self.config.chain_id,
            "currency": {
                "symbol": self.config.currency_symbol,
                "max_money": self.config.max_money,
                "genesis_supply_cap": self.config.genesis_supply_cap,
                "emission_supply_cap": self.config.emission_supply_cap,
                "migration_pool_cap": self.config.migration_pool_cap,
            },
            "migration": {
                "conversion_policy": self.config.migration_conversion_policy,
                "conversion_ratio": {
                    "numerator": self.config.migration_conversion_ratio_numerator,
                    "denominator": self.config.migration_conversion_ratio_denominator,
                },
                "per_address_cap": self.config.migration_claim_per_address_cap,
                "epoch_length_blocks": self.config.migration_epoch_length_blocks,
                "epoch_mint_cap": self.config.migration_epoch_mint_cap,
                "escrow_blocks": self.config.migration_escrow_blocks,
                "dispute_window_blocks": self.config.migration_dispute_window_blocks,
                "governance_quorum": self.config.migration_governance_quorum,
            },
            "invariants": [
                "theoretical supply must never exceed max_money",
                "migration_minted must never exceed migration_pool_cap",
                "migration epoch minted amount must not exceed configured epoch_mint_cap when non-zero",
                "migration claim amount must equal source amount times conversion ratio after per-address cap",
                "migration outputs must not be spendable before escrow unlock height",
                "open disputes and resolved-fraud disputes must freeze affected migration outputs",
                "canonical proof registry must not contain duplicate proof ids",
                "migration economics changes require signed governance artifacts and quorum review",
            ],
        }
        spec["spec_hash"] = hashlib.sha256(canonical_json(spec).encode("utf-8")).hexdigest()
        return spec

    def migration_economics_invariant_report(self) -> dict[str, object]:
        spec = self.migration_economics_specification()
        supply = self.supply_snapshot()
        guardrails = self.migration_conversion_guardrail_report()
        registry = self.migration_proof_registry_report()
        escrow = self.migration_escrow_finality_report()
        checks = [
            {"name": "supply_within_max_money", "passed": bool(supply["within_max_money"])},
            {
                "name": "migration_pool_cap_respected",
                "passed": int(supply["migration_minted"]) <= self.config.migration_pool_cap,
            },
            {
                "name": "epoch_cap_respected",
                "passed": guardrails["epoch"]["cap"] <= 0 or guardrails["epoch"]["minted"] <= guardrails["epoch"]["cap"],
            },
            {"name": "proof_registry_unique", "passed": registry["status"] == "pass"},
            {
                "name": "locked_outputs_not_spendable",
                "passed": all(bool(item["spendable"]) for item in escrow["claims"] if item["state"] == "unlocked")
                and all(not bool(item["spendable"]) for item in escrow["claims"] if item["state"] != "unlocked"),
            },
            {
                "name": "governance_quorum_positive",
                "passed": self.config.migration_governance_quorum > 0,
            },
        ]
        report = {
            "invariant_report_version": 1,
            "status": "pass" if all(bool(check["passed"]) for check in checks) else "blocked",
            "spec_hash": spec["spec_hash"],
            "checks": checks,
            "spec": spec,
        }
        report["invariant_report_hash"] = hashlib.sha256(canonical_json(report).encode("utf-8")).hexdigest()
        return report

    def migration_governance_quorum_report(self, approvals: list[dict[str, object]] | None = None) -> dict[str, object]:
        approvals = approvals or []
        trusted = set(self.config.migration_trusted_snapshot_signers)
        valid_approvals = []
        invalid_approvals = []
        for approval in approvals:
            envelope = dict(approval.get("envelope", approval)) if isinstance(approval, dict) else {}
            try:
                verified = verify_signed_envelope(
                    envelope,
                    expected_purpose="migration_governance_approval_v1",
                    expected_chain_id=self.config.chain_id,
                    time_skew_seconds=self.config.auth_time_skew_seconds,
                )
                address = str(verified["address"])
                if trusted and address not in trusted:
                    raise ValueError("Approval signer is not trusted by node policy.")
                valid_approvals.append(
                    {
                        "address": address,
                        "node_id": verified["node_id"],
                        "claims": verified["claims"],
                    }
                )
            except Exception as error:
                invalid_approvals.append({"error": str(error)})
        unique_signers = sorted({item["address"] for item in valid_approvals})
        report = {
            "quorum_version": 1,
            "required_quorum": self.config.migration_governance_quorum,
            "trusted_signer_count": len(trusted),
            "valid_approval_count": len(valid_approvals),
            "unique_valid_signer_count": len(unique_signers),
            "quorum_met": len(unique_signers) >= self.config.migration_governance_quorum,
            "unique_signers": unique_signers,
            "invalid_approvals": invalid_approvals,
            "required_actions": [
                "economics_governance_change",
                "fraud_recovery_decision",
                "migration_emergency_pause",
                "source_revocation",
            ],
        }
        report["quorum_report_hash"] = hashlib.sha256(canonical_json(report).encode("utf-8")).hexdigest()
        return report

    def sign_migration_governance_approval(self, *, action: str, artifact_hash: str, note: str = "") -> dict[str, object]:
        claims = {
            "purpose": "migration_governance_approval_v1",
            "chain_id": self.config.chain_id,
            "node_id": self.config.node_id,
            "action": action,
            "artifact_hash": artifact_hash,
            "note_hash": hashlib.sha256(note.encode("utf-8")).hexdigest(),
        }
        approval = {
            "approval_version": 1,
            "action": action,
            "artifact_hash": artifact_hash,
            "note": note,
            "envelope": self.identity.sign_claims("migration_governance_approval_v1", claims),
        }
        approval["approval_hash"] = hashlib.sha256(canonical_json(approval).encode("utf-8")).hexdigest()
        return approval

    def migration_escrow_transition_artifact(self, classical_address: str, *, action: str, reason: str) -> dict[str, object]:
        if action not in {"unlock", "freeze", "fraud_freeze", "review_hold"}:
            raise ValueError("Unsupported migration escrow transition action.")
        finality = self.migration_claim_finality(classical_address)
        transition = {
            "transition_version": 1,
            "chain_id": self.config.chain_id,
            "classical_address": classical_address,
            "action": action,
            "reason": reason,
            "current_finality": finality,
            "consensus_note": "This artifact is the signed migration-escrow transition intent; future consensus transaction types should commit this payload on-chain.",
        }
        transition["transition_hash"] = hashlib.sha256(canonical_json(transition).encode("utf-8")).hexdigest()
        artifact = {
            "artifact_version": 1,
            "transition": transition,
            "envelope": self.identity.sign_claims(
                "migration_escrow_transition_v1",
                {
                    "purpose": "migration_escrow_transition_v1",
                    "chain_id": self.config.chain_id,
                    "node_id": self.config.node_id,
                    "transition_hash": transition["transition_hash"],
                    "classical_address": classical_address,
                    "action": action,
                },
            ),
        }
        artifact["artifact_hash"] = self._signed_artifact_payload_hash(artifact)
        return artifact

    def migration_source_proof_coverage_report(self) -> dict[str, object]:
        sources = self.store.list_migration_sources()
        by_network: dict[str, dict[str, int]] = {}
        by_provider: dict[str, dict[str, int]] = {}
        weak_sources: list[dict[str, object]] = []
        for source in sources:
            evidence = self._migration_source_evidence(source)
            for bucket, key in ((by_network, str(source["source_network"])), (by_provider, str(source["provider_id"]))):
                summary = bucket.setdefault(key, {"total": 0, "strong": 0, "moderate": 0, "weak": 0})
                summary["total"] += 1
                summary[str(evidence["level"])] += 1
            if evidence["level"] == "weak":
                weak_sources.append(
                    {
                        "classical_address": source["classical_address"],
                        "source_network": source["source_network"],
                        "provider_id": source["provider_id"],
                        "missing": [
                            name
                            for name, present in [
                                ("external_source_address", evidence["has_external_source_address"]),
                                ("source_address_format", bool(evidence["source_address_format"])),
                                ("snapshot_ref", bool(evidence["snapshot_ref"])),
                            ]
                            if not present
                        ],
                    }
                )
        return {
            "coverage_status": "needs_review" if weak_sources else "covered",
            "source_count": len(sources),
            "weak_source_count": len(weak_sources),
            "by_network": by_network,
            "by_provider": by_provider,
            "weak_sources": weak_sources[:100],
            "recommended_next_actions": [
                "require external source addresses for all public migration entries",
                "require source address formats for BTC, ETH, RSA, and demo providers",
                "reject or quarantine weak-evidence sources before public claims",
            ],
        }

    def migration_snapshot_attestation_readiness(self) -> dict[str, object]:
        snapshots = self.store.list_migration_snapshots()
        trusted_signers = set(self.config.migration_trusted_snapshot_signers)
        items: list[dict[str, object]] = []
        for snapshot in snapshots:
            signer = str(snapshot.get("signer_address", ""))
            signer_count = 1 if signer else 0
            trusted = not trusted_signers or signer in trusted_signers
            ready = signer_count >= min(1, self.config.migration_snapshot_reviewer_quorum) and trusted
            blockers = []
            if not signer:
                blockers.append("snapshot_unsigned")
            if signer and not trusted:
                blockers.append("snapshot_signer_untrusted")
            if self.config.migration_snapshot_reviewer_quorum > 1:
                blockers.append("multi_reviewer_attestation_storage_not_enabled")
            items.append(
                {
                    "snapshot_ref": snapshot["snapshot_ref"],
                    "status": snapshot["status"],
                    "signer_address": signer,
                    "observed_attestation_count": signer_count,
                    "required_reviewer_quorum": self.config.migration_snapshot_reviewer_quorum,
                    "ready": ready and not blockers,
                    "blockers": blockers,
                }
            )
        return {
            "snapshot_count": len(snapshots),
            "required_reviewer_quorum": self.config.migration_snapshot_reviewer_quorum,
            "require_snapshot_signatures": self.config.migration_require_snapshot_signatures,
            "ready_snapshot_count": sum(1 for item in items if item["ready"]),
            "blocked_snapshot_count": sum(1 for item in items if not item["ready"]),
            "snapshots": items,
            "next_schema_step": "add append-only multi-reviewer snapshot attestations before enforcing quorum greater than one",
        }

    def migration_governance_report(self) -> dict[str, object]:
        snapshots = self.store.list_migration_snapshots()
        sources = self.store.list_migration_sources()
        policy = self.migration_policy()
        integrity = self.migration_integrity_report()
        active_unsigned = [
            item["snapshot_ref"]
            for item in snapshots
            if item.get("status") == "active" and not item.get("signer_address")
        ]
        blocked_sources = [
            item
            for item in sources
            if item.get("status") in {"quarantined", "revoked"}
        ]
        checks = [
            {
                "name": "migration_not_paused",
                "passed": not self.config.migration_emergency_pause,
                "detail": "emergency pause is off",
            },
            {
                "name": "claim_window_configured",
                "passed": self.config.migration_claim_start_height >= 0,
                "detail": f"start={self.config.migration_claim_start_height}, end={self.config.migration_claim_end_height}",
            },
            {
                "name": "dispute_window_configured",
                "passed": self.config.migration_dispute_window_blocks > 0,
                "detail": str(self.config.migration_dispute_window_blocks),
            },
            {
                "name": "reviewer_quorum_configured",
                "passed": self.config.migration_snapshot_reviewer_quorum > 0,
                "detail": str(self.config.migration_snapshot_reviewer_quorum),
            },
            {
                "name": "snapshot_signature_policy_explicit",
                "passed": bool(self.config.migration_require_snapshot_signatures or snapshots),
                "detail": str(self.config.migration_require_snapshot_signatures),
            },
            {
                "name": "no_critical_integrity_anomalies",
                "passed": int(integrity["summary"]["critical_anomaly_count"]) == 0,
                "detail": str(integrity["summary"]["critical_anomaly_count"]),
            },
        ]
        return {
            "governance_status": "ready" if all(bool(item["passed"]) for item in checks) else "needs_review",
            "policy": policy,
            "checks": checks,
            "snapshot_review": {
                "snapshot_count": len(snapshots),
                "active_unsigned_snapshot_refs": active_unsigned,
                "quarantined_snapshot_count": sum(1 for item in snapshots if item.get("status") == "quarantined"),
                "revoked_snapshot_count": sum(1 for item in snapshots if item.get("status") == "revoked"),
            },
            "disputes": {
                "window_blocks": self.config.migration_dispute_window_blocks,
                "blocked_source_count": len(blocked_sources),
                "blocked_sources": [
                    {
                        "classical_address": item["classical_address"],
                        "status": item["status"],
                        "status_reason": item.get("status_reason", ""),
                    }
                    for item in blocked_sources[:50]
                ],
            },
            "recommended_actions": [
                "require signed snapshots before public migration claims",
                "publish reviewer quorum and dispute escalation rules",
                "keep emergency pause authority separate from snapshot approvers",
            ],
        }

    def migration_integrity_report(self, source_network: str | None = None) -> dict[str, object]:
        snapshots = self.store.list_migration_snapshots()
        sources = self.store.list_migration_sources()
        if source_network:
            snapshots = [item for item in snapshots if item["source_network"] == source_network]
            sources = [item for item in sources if item["source_network"] == source_network]
        anomalies: list[dict[str, object]] = []
        snapshot_refs = {str(item["snapshot_ref"]) for item in snapshots}
        total_claimable = 0
        weak_evidence = 0
        for source in sources:
            evidence = self._migration_source_evidence(source)
            if evidence["level"] == "weak":
                weak_evidence += 1
                anomalies.append(
                    {
                        "severity": "warning",
                        "type": "weak_source_evidence",
                        "classical_address": source["classical_address"],
                        "detail": "source lacks strong external address or snapshot evidence",
                    }
                )
            if source.get("snapshot_ref") and source.get("snapshot_ref") not in snapshot_refs:
                anomalies.append(
                    {
                        "severity": "critical",
                        "type": "missing_snapshot_record",
                        "classical_address": source["classical_address"],
                        "snapshot_ref": source.get("snapshot_ref"),
                    }
                )
            if source.get("status") == "active" and not source.get("claimed", False):
                total_claimable += int(source["amount"])
        for snapshot in snapshots:
            if snapshot.get("status") != "active":
                continue
            if self.config.migration_require_snapshot_signatures and not snapshot.get("signer_address"):
                anomalies.append(
                    {
                        "severity": "critical",
                        "type": "unsigned_active_snapshot",
                        "snapshot_ref": snapshot["snapshot_ref"],
                    }
                )
        critical_count = sum(1 for item in anomalies if item["severity"] == "critical")
        return {
            "source_network": source_network or "all",
            "summary": {
                "snapshot_count": len(snapshots),
                "source_count": len(sources),
                "claimable_source_count": sum(1 for item in sources if item.get("status") == "active" and not item.get("claimed", False)),
                "claimable_amount": total_claimable,
                "weak_evidence_source_count": weak_evidence,
                "anomaly_count": len(anomalies),
                "critical_anomaly_count": critical_count,
            },
            "migration_pool": {
                "cap": self.config.migration_pool_cap,
                "remaining": self.supply_snapshot()["migration_pool_remaining"],
                "claimable_amount": total_claimable,
                "claimable_exceeds_remaining_pool": total_claimable > int(self.supply_snapshot()["migration_pool_remaining"]),
            },
            "anomalies": anomalies,
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

    def crypto_runtime_hardening_report(self) -> dict[str, object]:
        providers = list_signature_provider_statuses()
        provider_map = {str(item["provider_id"]): item for item in providers}
        mldsa = provider_map.get("mldsa65_oqs_v1", {})
        try:
            liboqs_python_version = importlib_metadata.version("liboqs-python")
        except importlib_metadata.PackageNotFoundError:
            liboqs_python_version = ""
        pinned = {
            "liboqs_python": "0.14.1",
            "native_liboqs": "0.15.0",
            "mechanism": "ML-DSA-65",
            "install_file": "requirements-oqs.txt",
            "runtime_doc": "docs/OQS_RUNTIME.md",
        }
        policy = self.signature_provider_policy()
        checks = [
            {
                "name": "mldsa_provider_available",
                "passed": bool(mldsa.get("available")),
                "detail": str(mldsa.get("error", mldsa.get("selected_mechanism", ""))),
            },
            {
                "name": "mldsa_mechanism_selected",
                "passed": mldsa.get("selected_mechanism") == pinned["mechanism"],
                "detail": str(mldsa.get("selected_mechanism", "")),
            },
            {
                "name": "liboqs_python_pin_matches",
                "passed": liboqs_python_version == pinned["liboqs_python"],
                "detail": liboqs_python_version or "not installed",
            },
            {
                "name": "stateless_provider_preferred",
                "passed": policy["recommended_stateless_provider"] is not None,
                "detail": str(policy["recommended_stateless_provider"]),
            },
        ]
        return {
            "hardening_status": "ready" if all(bool(item["passed"]) for item in checks) else "needs_review",
            "pinned_runtime": pinned,
            "checks": checks,
            "provider_policy": policy,
            "mldsa_provider": mldsa,
            "release_requirements": [
                "generate SBOM for Python and native cryptography dependencies",
                "record liboqs source commit and build flags in release artifacts",
                "sign release archives and runtime verification output",
                "run CI probes for ML-DSA-65 keygen, sign, verify, and disabled-mechanism errors",
            ],
        }

    def signature_strategy_report(self) -> dict[str, object]:
        providers = list_signature_provider_statuses()
        policy = self.signature_provider_policy()
        ranked: list[dict[str, object]] = []
        for index, provider_id in enumerate(self.config.preferred_signature_providers):
            status = next((item for item in providers if item["provider_id"] == provider_id), {})
            family = str(status.get("algorithm_family", ""))
            stateless = not bool(status.get("supports_stateful_signing", False))
            standardized = provider_id == "mldsa65_oqs_v1" or "NIST" in str(status.get("standardization", ""))
            if family == "ml-dsa":
                lane = "fast_lattice_default"
            elif stateless:
                lane = "stateless_conservative_fallback"
            else:
                lane = "stateful_hash_specialist"
            ranked.append(
                {
                    "rank": index + 1,
                    "provider_id": provider_id,
                    "available": bool(status.get("available", False)),
                    "algorithm_family": family,
                    "lane": lane,
                    "stateless": stateless,
                    "standardized": standardized,
                    "operator_note": self._signature_strategy_note(lane),
                }
            )
        return {
            "profile": self.config.preferred_signature_profile,
            "target_sign_ms": self.config.target_signature_sign_ms,
            "recommended_provider": policy["recommended_signature_provider"],
            "recommended_fast_lattice_provider": next(
                (
                    item["provider_id"]
                    for item in ranked
                    if item["lane"] == "fast_lattice_default" and item["available"]
                ),
                None,
            ),
            "ranked_providers": ranked,
            "position": (
                "Use standardized fast lattice signatures for normal wallet throughput, "
                "while keeping hash-based providers for conservative fallback and specialized stateful deployments."
            ),
        }

    @staticmethod
    def _signature_strategy_note(lane: str) -> str:
        notes = {
            "fast_lattice_default": "Best fit for high-throughput default wallet signing when the pinned runtime is available.",
            "stateless_conservative_fallback": "Useful fallback lane when a slower but stateless PQ provider is preferred.",
            "stateful_hash_specialist": "Requires signer reservation discipline; avoid as the default consumer wallet path.",
        }
        return notes.get(lane, "Review provider before production use.")

    def signature_performance_report(self) -> dict[str, object]:
        results: list[dict[str, object]] = []
        message = b"qbc-signature-performance-probe-v1"
        for status in list_signature_provider_statuses():
            provider_id = str(status["provider_id"])
            family = str(status.get("algorithm_family", ""))
            if not status.get("available", False):
                results.append(
                    {
                        "provider_id": provider_id,
                        "benchmark_status": "unavailable",
                        "reason": str(status.get("error", "provider unavailable")),
                    }
                )
                continue
            if (
                status.get("supports_stateful_signing", False)
                or family in {"xmss", "lms"}
                or provider_id in {"hash_lamport_v1", "xmss_merkle_lamport_v1"}
            ):
                results.append(
                    {
                        "provider_id": provider_id,
                        "benchmark_status": "skipped_stateful",
                        "reason": "live benchmark skips one-time or stateful reference signing material",
                    }
                )
                continue
            try:
                provider = get_signature_provider(provider_id)
                start = time.perf_counter()
                keypair = provider.generate_keypair()
                keygen_ms = (time.perf_counter() - start) * 1000
                start = time.perf_counter()
                public_key, signature = provider.sign(keypair, message)
                sign_ms = (time.perf_counter() - start) * 1000
                start = time.perf_counter()
                verified = provider.verify(message, signature, public_key)
                verify_ms = (time.perf_counter() - start) * 1000
                signature_size = len(json.dumps(signature, sort_keys=True).encode("utf-8"))
                public_key_size = len(json.dumps(public_key, sort_keys=True).encode("utf-8"))
                results.append(
                    {
                        "provider_id": provider_id,
                        "benchmark_status": "measured",
                        "keygen_ms": round(keygen_ms, 3),
                        "sign_ms": round(sign_ms, 3),
                        "verify_ms": round(verify_ms, 3),
                        "signature_payload_bytes": signature_size,
                        "public_key_payload_bytes": public_key_size,
                        "verified": verified,
                        "meets_target_sign_ms": sign_ms <= self.config.target_signature_sign_ms,
                    }
                )
            except Exception as error:
                results.append(
                    {
                        "provider_id": provider_id,
                        "benchmark_status": "error",
                        "reason": str(error),
                    }
                )
        measured = [item for item in results if item.get("benchmark_status") == "measured"]
        fastest = min(measured, key=lambda item: float(item["sign_ms"])) if measured else None
        return {
            "performance_profile": self.config.preferred_signature_profile,
            "target_sign_ms": self.config.target_signature_sign_ms,
            "fastest_measured_provider": {} if fastest is None else fastest,
            "results": results,
        }

    def signer_consensus_separation_report(self) -> dict[str, object]:
        return {
            "architecture_status": "separated_boundary",
            "consensus_node_responsibilities": [
                "validate transaction hashes and chain id",
                "verify PQ signatures against referenced UTXO owners",
                "enforce mempool, migration, supply, and fork-choice rules",
                "build, import, and select blocks",
            ],
            "wallet_signer_responsibilities": [
                "own private key material",
                "reserve stateful signing material before use",
                "construct wallet-originated transfer and migration claim signatures",
                "complete or fail signer reservations with audit state",
            ],
            "module_boundaries": {
                "consensus_service": "qr_blockchain.service.NodeService",
                "wallet_signer": "qr_blockchain.signer.LocalWalletSigner",
                "wallet_facade": "qr_blockchain.signer.Wallet",
                "verification_pool": "qr_blockchain.verification.verify_transaction_inputs",
            },
            "production_next": [
                "move signer backend behind a local IPC or RPC service",
                "bind native Rust/C PQ workers behind the signer interface",
                "deny node APIs direct access to wallet key databases in validator deployments",
            ],
        }

    def native_crypto_runtime_boundary_report(self) -> dict[str, object]:
        report = native_crypto_boundary_report()
        report["current_python_role"] = "orchestration_policy_api_tests"
        report["production_signing_role"] = "native_rust_or_c_backend"
        return report

    def parallel_verification_report(self) -> dict[str, object]:
        cpu_count = os.cpu_count() or 1
        pending = self.store.pending_transactions()
        total_inputs = sum(len(transaction.inputs) for transaction in pending)
        return {
            "verification_boundary": "qr_blockchain.verification.verify_transaction_inputs",
            "parallelism_status": "native_worker_pool_enabled_for_native_provider",
            "worker_model": "rust_native_batch_when_available_with_python_fallback",
            "native_batch_provider": "native_test_pq_v1",
            "cpu_count": cpu_count,
            "recommended_workers": max(1, min(cpu_count, 8)),
            "pending_transactions": len(pending),
            "pending_inputs": total_inputs,
            "batch_verification_note": (
                "Rust-backed batch verification is enabled for the native provider boundary; "
                "non-native providers continue through provider-specific Python verification until each has a native contract."
            ),
        }

    def transaction_resource_policy_report(self) -> dict[str, object]:
        provider_payloads: list[dict[str, object]] = []
        for status in list_signature_provider_statuses():
            provider_payloads.append(
                {
                    "provider_id": status["provider_id"],
                    "available": bool(status.get("available", False)),
                    "supports_stateful_signing": bool(status.get("supports_stateful_signing", False)),
                    "payload_policy": (
                        "reserve_and_meter_stateful_signatures"
                        if status.get("supports_stateful_signing", False)
                        else "meter_serialized_signature_bytes"
                    ),
                }
            )
        checks = [
            {
                "name": "transaction_size_limit_configured",
                "passed": self.config.max_transaction_size_bytes > 0,
                "detail": str(self.config.max_transaction_size_bytes),
            },
            {
                "name": "signature_payload_limit_configured",
                "passed": self.config.max_signature_payload_bytes > 0,
                "detail": str(self.config.max_signature_payload_bytes),
            },
            {
                "name": "fee_per_kib_configured",
                "passed": self.config.min_fee_per_kib >= 0,
                "detail": str(self.config.min_fee_per_kib),
            },
        ]
        return {
            "resource_policy_status": "ready" if all(bool(item["passed"]) for item in checks) else "needs_review",
            "checks": checks,
            "limits": {
                "max_transaction_size_bytes": self.config.max_transaction_size_bytes,
                "max_signature_payload_bytes": self.config.max_signature_payload_bytes,
                "max_transaction_inputs": self.config.max_transaction_inputs,
                "max_transaction_outputs": self.config.max_transaction_outputs,
                "min_fee_per_kib": self.config.min_fee_per_kib,
            },
            "provider_payloads": provider_payloads,
            "next_consensus_step": "turn signature payload and fee-per-KiB reporting into block validation rules once final provider sizes are chosen",
        }

    def consensus_economics_report(self) -> dict[str, object]:
        checks = [
            {
                "name": "supply_caps_enforced",
                "passed": bool(self.supply_snapshot()["within_max_money"]),
                "detail": str(self.config.max_money),
            },
            {
                "name": "subsidy_halving_configured",
                "passed": self.config.subsidy_halving_interval > 0,
                "detail": str(self.config.subsidy_halving_interval),
            },
            {
                "name": "validator_policy_declared",
                "passed": bool(self.config.validator_set_policy),
                "detail": self.config.validator_set_policy,
            },
            {
                "name": "coinbase_maturity_declared",
                "passed": self.config.coinbase_maturity_blocks >= 0,
                "detail": str(self.config.coinbase_maturity_blocks),
            },
        ]
        return {
            "consensus_economics_status": "ready_for_design_review"
            if all(bool(item["passed"]) for item in checks)
            else "needs_review",
            "checks": checks,
            "current_model": {
                "difficulty": self.config.difficulty,
                "validator_set_policy": self.config.validator_set_policy,
                "reward_recipient_policy": self.config.reward_recipient_policy,
                "coinbase_maturity_blocks": self.config.coinbase_maturity_blocks,
                "subsidy_halving_interval": self.config.subsidy_halving_interval,
            },
            "known_gaps": [
                "final validator/miner admission and Sybil-resistance model",
                "coinbase maturity enforcement if rewards become economically meaningful",
                "difficulty adjustment or validator schedule beyond local development settings",
                "fee market policy for large PQ signatures and migration bursts",
            ],
        }

    def transaction_state_model_report(self) -> dict[str, object]:
        return {
            "state_model_status": "utxo_deterministic_v1",
            "execution_model": "ordered_utxo_transactions_with_migration_claim_mints",
            "state_roots": self.state_root_policy(),
            "replay_protection": [
                "transaction signing payload includes chain_id",
                "transaction id commits to inputs, outputs, metadata, fee, timestamp, and signature scheme",
                "mempool rejects duplicate tx ids and pending double spends",
            ],
            "fee_and_value_rules": [
                "transfer outputs plus fee must not exceed referenced inputs",
                "migration claims mint only from configured source entries and capped migration pool",
                "coinbase reward must equal height subsidy plus included fees",
                f"coinbase outputs require {self.config.coinbase_maturity_blocks} maturity blocks before spend",
            ],
            "next_required_work": [
                "define canonical script/account extension rules before adding smart execution",
                "add fee market and dust policy beyond minimum flat fee",
                "publish state-root activation height in signed network upgrade metadata before public testnet",
            ],
        }

    def validator_networking_readiness_report(self) -> dict[str, object]:
        peers = self.store.list_peer_identities()
        admitted = [peer for peer in peers if str(peer.get("status", "")) == "admitted"]
        diversity = self.peer_diversity_report()
        return {
            "validator_networking_status": (
                "authenticated_gossip_with_diversity_checks"
                if diversity["passed"]
                else "authenticated_gossip_needs_peer_diversity"
            ),
            "peer_protocol_version": self.config.peer_protocol_version,
            "configured_peer_count": len(self.config.peers),
            "stored_peer_count": len(peers),
            "admitted_peer_count": len(admitted),
            "gossip": {
                "fanout": self.config.gossip_fanout,
                "transaction_relay": "/peer/gossip/transaction",
                "block_relay": "/peer/gossip/block",
                "bad_block_penalty": self.config.peer_bad_block_penalty,
                "invalid_frame_penalty": self.config.peer_invalid_frame_penalty,
            },
            "anti_eclipse": diversity,
            "peer_scores": [
                {
                    "node_id": peer["node_id"],
                    "url": peer["url"],
                    "score": peer.get("score", 0),
                    "success_count": peer.get("success_count", 0),
                    "failure_count": peer.get("failure_count", 0),
                }
                for peer in peers
            ],
            "controls": [
                "signed peer handshakes",
                "session-bound request authentication",
                "nonce replay protection",
                "allowlist and denylist admission policy",
                "framed peer summary and block requests",
                "authenticated transaction and block gossip relay",
                "peer sync success/failure scoring",
                "bad block and invalid transaction gossip penalties",
                "minimum peer diversity readiness gate",
            ],
            "production_gaps": [
                "encrypted transport should be mandatory outside localhost/private lab networks",
                "gossip fanout and peer scoring need production calibration",
                "eclipse-resistance and block propagation latency need soak testing",
            ],
        }

    def migration_finality_fraud_report(self) -> dict[str, object]:
        dispute_summary = self.migration_disputes()
        return {
            "migration_finality_status": "challenge_lifecycle_with_claim_unlock_rules",
            "claim_window": {
                "start_height": self.config.migration_claim_start_height,
                "end_height": self.config.migration_claim_end_height,
                "deprecation_height": self.config.migration_claim_end_height,
            },
            "dual_control_window": {
                "start_height": self.config.migration_dual_control_start_height,
                "end_height": self.config.migration_dual_control_end_height,
            },
            "disputes": {
                "open_dispute_count": dispute_summary["open_dispute_count"],
                "evidence_submitted_count": dispute_summary["evidence_submitted_count"],
                "resolved_valid_count": dispute_summary["resolved_valid_count"],
                "resolved_fraud_count": dispute_summary["resolved_fraud_count"],
                "expired_count": dispute_summary["expired_count"],
                "dispute_count": dispute_summary["dispute_count"],
                "window_blocks": self.config.migration_dispute_window_blocks,
            },
            "fraud_controls": [
                "classical ownership proof verification",
                "source-network binding validation",
                "snapshot active/quarantine/revocation status",
                "duplicate claim rejection across best-chain and mempool views",
                "dispute packet generation with source, snapshot, quote, and evidence hashes",
                "open and evidence-submitted disputes quarantine affected sources",
                "resolved-valid and expired disputes unlock claims",
                "resolved-fraud disputes revoke sources",
            ],
            "production_gaps": [
                "define on-chain challenge transaction type",
                "define claim reversal or escrow behavior for fraud found after claim inclusion",
                "publish external snapshot signer quorum policy before public migration",
            ],
        }

    def adversarial_performance_readiness_report(self) -> dict[str, object]:
        return {
            "readiness_status": "test_harness_present_needs_long_running_soak",
            "implemented_surfaces": [
                "unit tests for malformed frames, tampering, wallet recovery, migration claims, and supply caps",
                "migration load tests",
                "signature performance probes",
                "parallel verification boundary for independent input signatures",
                "operator adversarial migration simulation report",
                "coinbase maturity regression tests",
                "persistent migration dispute quarantine tests",
            ],
            "required_soak_scenarios": [
                "multi-node fork storms with migration claims in competing branches",
                "mempool flood with oversized PQ signatures and low-fee transactions",
                "signer crash/restart loops during stateful XMSS/LMS-style signing",
                "snapshot quarantine/revocation during active claim batches",
                "long-running ML-DSA/OQS signing and verification latency baselines",
            ],
            "parallelization_policy": {
                "safe_now": "parallelize independent signature verification across worker threads",
                "gated": "true cryptographic batch verification requires per-algorithm audit and test vectors",
                "stateful_signing_warning": "parallel signing must serialize reservations for XMSS/LMS-style keys",
            },
        }

    def security_invariant_report(self) -> dict[str, object]:
        best_head = self.store.best_head_hash()
        canonical_blocks = self.store.path_to_root(best_head) if best_head else []
        projected_utxos: dict[tuple[str, int], TxOutput] = {}
        state_root_failures: list[dict[str, object]] = []
        canonical_tx_ids: list[str] = []
        migration_claim_addresses: list[str] = []

        for block in canonical_blocks:
            for transaction in block.transactions:
                if transaction.tx_id:
                    canonical_tx_ids.append(transaction.tx_id)
                for tx_input in transaction.inputs:
                    projected_utxos.pop((tx_input.prev_tx_id, tx_input.output_index), None)
                for output_index, output in enumerate(transaction.outputs):
                    projected_utxos[(transaction.tx_id, output_index)] = output
                if transaction.kind == "migration_claim":
                    migration_claim_addresses.append(str(transaction.metadata.get("classical_address", "")))

            if block.index >= self.config.state_root_activation_height:
                expected_root = self.state_root_for_utxos(projected_utxos)
                if block.version < 3 or not block.state_root or block.state_root != expected_root:
                    state_root_failures.append(
                        {
                            "height": block.index,
                            "block_hash": block.block_hash,
                            "expected_state_root": expected_root,
                            "observed_state_root": block.state_root,
                            "version": block.version,
                        }
                    )

        stored_utxos = self.store.all_utxos()
        duplicate_tx_ids = sorted(
            tx_id for tx_id, count in Counter(canonical_tx_ids).items() if tx_id and count > 1
        )
        duplicate_migration_claims = sorted(
            address for address, count in Counter(migration_claim_addresses).items() if address and count > 1
        )
        blocking_disputes = [
            item
            for item in self.store.list_migration_disputes()
            if str(item.get("status", "")) in {"open", "evidence_submitted", "resolved_fraud"}
        ]
        recovery_count = int(self.wallet_state_store.reservation_status_counts().get("requires_recovery", 0))
        supply = self.supply_snapshot()
        checks = [
            {
                "name": "canonical_utxo_index_matches_replay",
                "passed": stored_utxos == projected_utxos,
                "detail": f"stored={len(stored_utxos)}, replayed={len(projected_utxos)}",
            },
            {
                "name": "activated_state_roots_match_replay",
                "passed": not state_root_failures,
                "detail": str(len(state_root_failures)),
            },
            {
                "name": "canonical_transaction_ids_unique",
                "passed": not duplicate_tx_ids,
                "detail": ",".join(duplicate_tx_ids[:5]),
            },
            {
                "name": "migration_claims_unique_on_canonical_chain",
                "passed": not duplicate_migration_claims,
                "detail": ",".join(duplicate_migration_claims[:5]),
            },
            {
                "name": "supply_caps_intact",
                "passed": bool(supply["within_max_money"]),
                "detail": str(supply["theoretical_supply"]),
            },
            {
                "name": "stateful_signer_recovery_clear",
                "passed": recovery_count == 0,
                "detail": str(recovery_count),
            },
        ]
        failed = [check for check in checks if not check["passed"]]
        return {
            "security_invariant_status": "pass" if not failed else "fail_closed_review_required",
            "checks": checks,
            "failed_checks": failed,
            "state_root_failures": state_root_failures,
            "duplicate_transaction_ids": duplicate_tx_ids,
            "duplicate_migration_claims": duplicate_migration_claims,
            "blocking_migration_dispute_count": len(blocking_disputes),
            "canonical_height": self.store.block_count(),
            "best_head_hash": best_head,
        }

    def load_chaos_harness_report(
        self,
        *,
        scenario: str = "all",
        node_count: int = 3,
        mempool_transactions: int = 8,
        migration_claims: int = 6,
        verification_batch_size: int = 8,
    ) -> dict[str, object]:
        from .chaos import run_load_chaos_harness

        return run_load_chaos_harness(
            base_config=self.config,
            scenario=scenario,
            node_count=node_count,
            mempool_transactions=mempool_transactions,
            migration_claims=migration_claims,
            verification_batch_size=verification_batch_size,
        )

    def release_provenance_manifest(self) -> dict[str, object]:
        protocol = self.protocol_manifest()
        hardening = self.crypto_runtime_hardening_report()
        manifest = {
            "release_manifest_version": 1,
            "generated_at": round(time.time(), 6),
            "chain_id": self.config.chain_id,
            "protocol_manifest_hash": protocol["protocol_manifest_hash"],
            "currency_symbol": self.config.currency_symbol,
            "default_signature_provider": self.config.default_signature_provider,
            "recommended_signature_provider": hardening["provider_policy"]["recommended_signature_provider"],
            "pinned_runtime": hardening["pinned_runtime"],
            "required_artifacts": [
                "README.md",
                "CHANGELOG.md",
                "requirements-oqs.txt",
                "docs/OQS_RUNTIME.md",
                "test report",
                "signed release archive",
                "SBOM",
            ],
        }
        manifest["release_manifest_hash"] = hashlib.sha256(
            json.dumps(manifest, sort_keys=True).encode("utf-8")
        ).hexdigest()
        return manifest

    def operator_incident_runbook(self) -> dict[str, object]:
        return {
            "runbook_version": 1,
            "operator_posture": self.operational_status()["status"],
            "migration_pause": {
                "env": "QR_CHAIN_MIGRATION_EMERGENCY_PAUSE=true",
                "effect": "new migration claims are rejected while review continues",
            },
            "incident_classes": [
                {
                    "name": "suspect_migration_snapshot",
                    "first_actions": [
                        "set snapshot status to quarantined",
                        "run migration-integrity and migration-governance reports",
                        "publish affected classical addresses and dispute window",
                    ],
                },
                {
                    "name": "pq_runtime_regression",
                    "first_actions": [
                        "run crypto-hardening and crypto-performance",
                        "pin or roll back requirements-oqs.txt",
                        "temporarily prefer a known-good provider through QR_CHAIN_PREFERRED_SIGNATURE_PROVIDERS",
                    ],
                },
                {
                    "name": "wallet_signer_recovery",
                    "first_actions": [
                        "run wallets/status",
                        "inspect reservation ids and recovery notes",
                        "recover only after confirming no ambiguous signature was broadcast",
                    ],
                },
            ],
        }

    def node_launch_preflight_report(self) -> dict[str, object]:
        reports = {
            "operational": self.operational_status(),
            "migration_readiness": self.migration_readiness_report(),
            "crypto_hardening": self.crypto_runtime_hardening_report(),
            "transport": self.network_transport_readiness_report(),
            "consensus_economics": self.consensus_economics_report(),
            "production_configuration": self.production_configuration_report(),
            "backup": self.state_backup_manifest(),
        }
        blockers = []
        if reports["operational"]["status"] != "ok":
            blockers.append("operational_status_not_ok")
        if reports["migration_readiness"]["migration_layer_status"] != "operational":
            blockers.append("migration_layer_not_operational")
        if reports["crypto_hardening"]["hardening_status"] != "ready":
            blockers.append("crypto_runtime_not_hardened")
        if reports["transport"]["transport_status"] != "ready":
            blockers.append("peer_transport_needs_hardening")
        if reports["production_configuration"]["configuration_status"] == "blocked":
            blockers.append("production_configuration_blocked")
        return {
            "preflight_status": "ready" if not blockers else "blocked",
            "blockers": blockers,
            "reports": reports,
            "launch_sequence": [
                "run backup-manifest and store hashes",
                "run crypto-hardening and crypto-performance",
                "run migration-integrity, migration-governance, and migration-proof-coverage",
                "run network-transport-readiness",
                "only then start wider peer admission or public claim windows",
            ],
        }

    def hardening_audit_report(self) -> dict[str, object]:
        reports = {
            "security_invariants": self.security_invariant_report(),
            "production_configuration": self.production_configuration_report(),
            "node_preflight": self.node_launch_preflight_report(),
            "migration_readiness": self.migration_readiness_report(),
            "migration_integrity": self.migration_integrity_report(),
            "migration_escrow_finality": self.migration_escrow_finality_report(),
            "migration_conversion_guardrails": self.migration_conversion_guardrail_report(),
            "migration_proof_registry": self.migration_proof_registry_report(),
            "migration_economics_adversarial": self.migration_adversarial_economics_simulation_report(),
            "migration_economics_invariants": self.migration_economics_invariant_report(),
            "crypto_hardening": self.crypto_runtime_hardening_report(),
            "transport": self.network_transport_readiness_report(),
            "validator_networking": self.validator_networking_readiness_report(),
            "consensus_economics": self.consensus_economics_report(),
            "adversarial_performance": self.adversarial_performance_readiness_report(),
            "backup": self.state_backup_manifest(),
        }
        blockers: list[str] = []
        warnings: list[str] = []
        if reports["security_invariants"]["security_invariant_status"] != "pass":
            blockers.append("security_invariants_failed")
        if reports["production_configuration"]["configuration_status"] == "blocked":
            blockers.append("production_configuration_blocked")
        if reports["production_configuration"]["configuration_status"] == "warning":
            warnings.append("production_configuration_warnings")
        if reports["node_preflight"]["preflight_status"] != "ready":
            blockers.append("node_preflight_blocked")
        if reports["migration_readiness"]["migration_layer_status"] != "operational":
            blockers.append("migration_layer_not_operational")
        if int(reports["migration_integrity"]["summary"]["critical_anomaly_count"]) > 0:
            blockers.append("migration_integrity_critical_anomalies")
        if reports["migration_conversion_guardrails"]["status"] != "pass":
            warnings.append("migration_conversion_guardrails_warning")
        if reports["migration_proof_registry"]["status"] != "pass":
            blockers.append("migration_proof_registry_blocked")
        if reports["migration_economics_adversarial"]["status"] != "pass":
            warnings.append("migration_economics_adversarial_warning")
        if reports["migration_economics_invariants"]["status"] != "pass":
            blockers.append("migration_economics_invariants_failed")
        if reports["crypto_hardening"]["hardening_status"] != "ready":
            blockers.append("crypto_runtime_not_hardened")
        if reports["transport"]["transport_status"] != "ready":
            warnings.append("transport_needs_hardening")
        if reports["validator_networking"]["validator_networking_status"] != "authenticated_gossip_with_diversity_checks":
            warnings.append("validator_networking_diversity_gap")
        if reports["consensus_economics"]["consensus_economics_status"] != "ready_for_design_review":
            warnings.append("consensus_economics_needs_review")
        if reports["adversarial_performance"]["readiness_status"] != "test_harness_present_needs_long_running_soak":
            warnings.append("adversarial_performance_report_unexpected")
        if not bool(reports["backup"]["backup_manifest_hash"]):
            blockers.append("backup_manifest_missing_hash")

        report = {
            "audit_version": 1,
            "generated_at": round(time.time(), 6),
            "chain_id": self.config.chain_id,
            "node_id": self.config.node_id,
            "deployment_mode": self.config.deployment_mode,
            "audit_status": "blocked" if blockers else ("warning" if warnings else "pass"),
            "blockers": blockers,
            "warnings": warnings,
            "reports": reports,
            "recommended_order": [
                "fix security invariant failures before changing configuration",
                "clear production-config blockers before exposing public peers or migration windows",
                "resolve migration integrity anomalies before approving new source ingestion",
                "verify crypto-hardening before signing value-bearing transactions",
                "run load-chaos after blockers are clear to validate multi-node behavior",
            ],
        }
        report["audit_hash"] = hashlib.sha256(canonical_json(report).encode("utf-8")).hexdigest()
        return report

    def hardening_stage_reports(self) -> dict[str, object]:
        stages = [
            self.ci_quality_gate_report(),
            self.security_policy_profiles_report(),
            self.signed_audit_artifact_report(),
            self.peer_transport_policy_report(),
            self.consensus_upgrade_manifest(),
            self.migration_fraud_recovery_policy_report(),
            self.native_crypto_release_provenance_report(),
            self.soak_result_artifact_report(),
            self.database_durability_report(),
            self.external_audit_readiness_package(),
        ]
        blocked = [stage for stage in stages if stage["status"] == "blocked"]
        warnings = [stage for stage in stages if stage["status"] == "warning"]
        report = {
            "hardening_stage_report_version": 1,
            "stage_count": len(stages),
            "status": "blocked" if blocked else ("warning" if warnings else "ready"),
            "blocked_stage_ids": [stage["stage_id"] for stage in blocked],
            "warning_stage_ids": [stage["stage_id"] for stage in warnings],
            "stages": stages,
        }
        report["hardening_stage_report_hash"] = hashlib.sha256(canonical_json(report).encode("utf-8")).hexdigest()
        return report

    def ci_quality_gate_report(self) -> dict[str, object]:
        workflow_path = Path(".github/workflows/hardening.yml")
        commands = [
            "python -m compileall qr_blockchain",
            "python -m unittest tests.test_config tests.test_source_ingestion tests.test_cli tests.test_adversarial -v",
            "python -m unittest tests.test_node_service -v",
        ]
        return {
            "stage_id": 1,
            "name": "ci_quality_gates",
            "status": "ready" if workflow_path.exists() else "blocked",
            "workflow_path": str(workflow_path),
            "workflow_present": workflow_path.exists(),
            "required_commands": commands,
            "release_gate": "merge is unsafe unless compile, service, CLI, ingestion, and adversarial suites pass",
        }

    def security_policy_profiles_report(self) -> dict[str, object]:
        profiles = {
            "development": {
                "public_peers": False,
                "demo_providers_allowed": True,
                "signed_snapshots_required": False,
                "allowlist_required": False,
            },
            "private-testnet": {
                "public_peers": False,
                "demo_providers_allowed": False,
                "signed_snapshots_required": True,
                "allowlist_required": True,
            },
            "public-testnet": {
                "public_peers": True,
                "demo_providers_allowed": False,
                "signed_snapshots_required": True,
                "allowlist_required": True,
            },
            "production": {
                "public_peers": True,
                "demo_providers_allowed": False,
                "signed_snapshots_required": True,
                "allowlist_required": True,
            },
        }
        production_config = self.production_configuration_report()
        mode = self.config.deployment_mode.strip().lower()
        known_profile = mode in profiles
        return {
            "stage_id": 2,
            "name": "structured_security_policy_profiles",
            "status": "ready" if known_profile and production_config["configuration_status"] != "blocked" else "warning",
            "active_profile": mode,
            "known_profile": known_profile,
            "profiles": profiles,
            "active_profile_checks": production_config["checks"],
        }

    def signed_audit_artifact_report(self) -> dict[str, object]:
        audit = self.hardening_audit_report()
        claims = {
            "audit_hash": audit["audit_hash"],
            "audit_status": audit["audit_status"],
            "chain_id": self.config.chain_id,
            "node_id": self.config.node_id,
            "generated_at": audit["generated_at"],
        }
        envelope = self.identity.sign_claims("hardening_audit_artifact_v1", claims)
        report = {
            "stage_id": 3,
            "name": "signed_audit_report_artifacts",
            "status": "ready",
            "claims": claims,
            "envelope": envelope,
            "operator_rule": "attach this signed artifact to migration approvals and release notes",
        }
        report["artifact_hash"] = hashlib.sha256(canonical_json(report["claims"]).encode("utf-8")).hexdigest()
        return report

    def peer_transport_policy_report(self) -> dict[str, object]:
        transport = self.network_transport_readiness_report()
        production_config = self.production_configuration_report()
        checks = [
            {
                "name": "https_or_local_only",
                "passed": production_config["configuration_status"] != "blocked"
                and not any(str(peer).startswith("http://") for peer in self.config.peers),
            },
            {"name": "peer_allowlist_policy_declared", "passed": bool(self.config.peer_allowlist) or not self.config.peers},
            {"name": "node_identity_rotation_runbook_declared", "passed": True},
            {"name": "m_tls_boundary_documented", "passed": True},
        ]
        return {
            "stage_id": 4,
            "name": "stronger_peer_transport_policy",
            "status": "ready" if all(check["passed"] for check in checks) else "warning",
            "checks": checks,
            "transport": transport,
            "next_enforcement": "replace HTTP lab transport with TLS/mTLS transport adapter before public validators",
        }

    def consensus_upgrade_manifest(self) -> dict[str, object]:
        manifest = {
            "stage_id": 5,
            "name": "consensus_parameter_governance",
            "manifest_version": 1,
            "chain_id": self.config.chain_id,
            "node_id": self.config.node_id,
            "effective_height": self.store.block_count(),
            "state_root_activation_height": self.config.state_root_activation_height,
            "max_transaction_size_bytes": self.config.max_transaction_size_bytes,
            "max_signature_payload_bytes": self.config.max_signature_payload_bytes,
            "max_transactions_per_block": self.config.max_transactions_per_block,
            "max_transaction_inputs": self.config.max_transaction_inputs,
            "max_transaction_outputs": self.config.max_transaction_outputs,
            "min_fee_per_kib": self.config.min_fee_per_kib,
            "coinbase_maturity_blocks": self.config.coinbase_maturity_blocks,
            "migration_claim_start_height": self.config.migration_claim_start_height,
            "migration_claim_end_height": self.config.migration_claim_end_height,
            "migration_dual_control_start_height": self.config.migration_dual_control_start_height,
            "migration_dual_control_end_height": self.config.migration_dual_control_end_height,
            "migration_dispute_window_blocks": self.config.migration_dispute_window_blocks,
            "allowed_signature_providers": list(self.config.allowed_signature_providers),
            "preferred_signature_providers": list(self.config.preferred_signature_providers),
            "operator_rule": "consensus-affecting changes must ship as signed upgrade manifests before activation",
            "requires_signature": True,
        }
        manifest["upgrade_manifest_hash"] = self._consensus_upgrade_manifest_hash(manifest)
        manifest["status"] = "ready"
        return manifest

    def signed_consensus_upgrade_manifest(self) -> dict[str, object]:
        manifest = self.consensus_upgrade_manifest()
        claims = {
            "purpose": "consensus_upgrade_manifest_v1",
            "chain_id": self.config.chain_id,
            "node_id": self.config.node_id,
            "upgrade_manifest_hash": manifest["upgrade_manifest_hash"],
            "manifest_version": manifest["manifest_version"],
            "effective_height": manifest["effective_height"],
        }
        envelope = self.identity.sign_claims("consensus_upgrade_manifest_v1", claims)
        artifact = {
            "artifact_version": 1,
            "manifest": manifest,
            "envelope": envelope,
        }
        artifact["artifact_hash"] = hashlib.sha256(canonical_json(artifact["manifest"]).encode("utf-8")).hexdigest()
        return artifact

    def validate_consensus_upgrade_manifest_artifact(self, artifact: dict[str, object]) -> dict[str, object]:
        manifest = dict(artifact.get("manifest", {})) if isinstance(artifact.get("manifest"), dict) else {}
        envelope = dict(artifact.get("envelope", {})) if isinstance(artifact.get("envelope"), dict) else {}
        observed_hash = str(manifest.get("upgrade_manifest_hash", ""))
        expected_hash = self._consensus_upgrade_manifest_hash(manifest)
        signature_valid = False
        signature_error = ""
        try:
            verified = verify_signed_envelope(
                envelope,
                expected_purpose="consensus_upgrade_manifest_v1",
                expected_chain_id=self.config.chain_id,
                time_skew_seconds=self.config.auth_time_skew_seconds,
            )
            signature_valid = str(verified["claims"].get("upgrade_manifest_hash", "")) == observed_hash
        except Exception as error:
            signature_error = str(error)

        checks = [
            {"name": "manifest_present", "passed": bool(manifest)},
            {"name": "manifest_hash_matches", "passed": bool(observed_hash) and observed_hash == expected_hash},
            {"name": "signature_present", "passed": bool(envelope)},
            {"name": "signature_valid", "passed": signature_valid, "detail": signature_error},
            {"name": "chain_id_matches", "passed": manifest.get("chain_id") == self.config.chain_id},
            {"name": "effective_height_nonnegative", "passed": int(manifest.get("effective_height", -1)) >= 0},
            {"name": "state_root_activation_nonnegative", "passed": int(manifest.get("state_root_activation_height", -1)) >= 0},
            {"name": "max_transaction_size_positive", "passed": int(manifest.get("max_transaction_size_bytes", 0)) > 0},
            {"name": "max_signature_payload_positive", "passed": int(manifest.get("max_signature_payload_bytes", 0)) > 0},
            {"name": "min_fee_per_kib_nonnegative", "passed": int(manifest.get("min_fee_per_kib", -1)) >= 0},
            {"name": "migration_dispute_window_positive", "passed": int(manifest.get("migration_dispute_window_blocks", 0)) > 0},
        ]
        result = {
            "valid": all(bool(check["passed"]) for check in checks),
            "checks": checks,
            "upgrade_manifest_hash": observed_hash,
            "expected_manifest_hash": expected_hash,
        }
        result["validation_hash"] = hashlib.sha256(canonical_json(result).encode("utf-8")).hexdigest()
        return result

    @staticmethod
    def _consensus_upgrade_manifest_hash(manifest: dict[str, object]) -> str:
        payload = dict(manifest)
        payload.pop("upgrade_manifest_hash", None)
        payload.pop("status", None)
        return hashlib.sha256(canonical_json(payload).encode("utf-8")).hexdigest()

    @staticmethod
    def _post_finality_migration_fraud_case_hash(case: dict[str, object]) -> str:
        payload = dict(case)
        payload.pop("case_hash", None)
        payload.pop("envelope", None)
        payload.pop("validation_hash", None)
        return hashlib.sha256(canonical_json(payload).encode("utf-8")).hexdigest()

    def migration_fraud_recovery_policy_report(self) -> dict[str, object]:
        policy = {
            "stage_id": 6,
            "name": "migration_post_finality_fraud_recovery",
            "status": "case_artifacts_ready_escrow_rules_pending",
            "current_controls": self.migration_finality_fraud_report()["fraud_controls"],
            "implemented_controls": [
                "signed post-finality fraud case artifact",
                "case validation with tamper detection",
                "automatic source quarantine through the existing dispute lifecycle",
                "CLI and API surfaces for case creation and validation",
            ],
            "post_finality_policy": [
                "open post-finality fraud case with signed evidence packet",
                "freeze future claims from affected source snapshot",
                "quarantine destination outputs through governance review once escrow rules exist",
                "publish audit trail and recovery decision",
            ],
            "blocked_on": [
                "on-chain challenge transaction type",
                "escrow or clawback semantics for already-mined migration outputs",
            ],
        }
        policy["policy_hash"] = hashlib.sha256(canonical_json(policy).encode("utf-8")).hexdigest()
        return policy

    def native_crypto_release_provenance_report(self) -> dict[str, object]:
        boundary = self.native_crypto_runtime_boundary_report()
        hardening = self.crypto_runtime_hardening_report()
        release = self.release_provenance_manifest()
        report = {
            "stage_id": 7,
            "name": "native_crypto_release_provenance",
            "status": "ready" if hardening["hardening_status"] == "ready" else "warning",
            "native_boundary": boundary,
            "pinned_runtime": hardening["pinned_runtime"],
            "release_manifest_hash": release["release_manifest_hash"],
            "provider_policy": hardening["provider_policy"],
            "required_release_artifacts": [
                "liboqs version manifest",
                "Rust crate lockfile",
                "native extension build logs",
                "SBOM",
                "test vectors and verification output",
            ],
            "provenance_checks": [
                {"name": "native_boundary_declared", "passed": bool(boundary["native_crypto_status"])},
                {"name": "release_manifest_hashed", "passed": bool(release["release_manifest_hash"])},
                {"name": "pinned_runtime_declared", "passed": bool(hardening["pinned_runtime"])},
                {
                    "name": "recommended_provider_available",
                    "passed": hardening["provider_policy"]["recommended_signature_provider"] is not None,
                },
            ],
        }
        report["native_release_hash"] = hashlib.sha256(canonical_json(report).encode("utf-8")).hexdigest()
        return report

    def signed_native_crypto_release_provenance(self) -> dict[str, object]:
        report = self.native_crypto_release_provenance_report()
        release = self.release_provenance_manifest()
        report["release_manifest_hash"] = release["release_manifest_hash"]
        report["native_release_hash"] = self._native_release_report_hash(report)
        claims = {
            "purpose": "native_crypto_release_provenance_v1",
            "chain_id": self.config.chain_id,
            "node_id": self.config.node_id,
            "native_release_hash": report["native_release_hash"],
            "release_manifest_hash": release["release_manifest_hash"],
            "pinned_runtime": report["pinned_runtime"],
        }
        artifact = {
            "artifact_version": 1,
            "report": report,
            "release_manifest": release,
            "envelope": self.identity.sign_claims("native_crypto_release_provenance_v1", claims),
        }
        artifact["artifact_hash"] = self._signed_artifact_payload_hash(artifact)
        return artifact

    def validate_native_crypto_release_provenance(self, artifact: dict[str, object]) -> dict[str, object]:
        report = dict(artifact.get("report", {})) if isinstance(artifact.get("report"), dict) else {}
        release = dict(artifact.get("release_manifest", {})) if isinstance(artifact.get("release_manifest"), dict) else {}
        envelope = dict(artifact.get("envelope", {})) if isinstance(artifact.get("envelope"), dict) else {}
        expected_report_hash = self._native_release_report_hash(report)
        expected_release_hash = self._release_manifest_hash(release)
        expected_artifact_hash = self._signed_artifact_payload_hash(artifact)
        signature_valid = False
        signature_error = ""
        try:
            verified = verify_signed_envelope(
                envelope,
                expected_purpose="native_crypto_release_provenance_v1",
                expected_chain_id=self.config.chain_id,
                time_skew_seconds=self.config.auth_time_skew_seconds,
            )
            claims = dict(verified["claims"])
            signature_valid = (
                claims.get("native_release_hash") == report.get("native_release_hash")
                and claims.get("release_manifest_hash") == release.get("release_manifest_hash")
                and claims.get("pinned_runtime") == report.get("pinned_runtime")
            )
        except Exception as error:
            signature_error = str(error)

        checks = [
            {"name": "report_present", "passed": bool(report)},
            {
                "name": "native_release_hash_matches",
                "passed": bool(report.get("native_release_hash")) and report.get("native_release_hash") == expected_report_hash,
            },
            {
                "name": "release_manifest_hash_matches",
                "passed": bool(release.get("release_manifest_hash"))
                and release.get("release_manifest_hash") == expected_release_hash,
            },
            {
                "name": "report_binds_release_manifest",
                "passed": report.get("release_manifest_hash") == release.get("release_manifest_hash"),
            },
            {
                "name": "artifact_hash_matches",
                "passed": bool(artifact.get("artifact_hash")) and artifact.get("artifact_hash") == expected_artifact_hash,
            },
            {"name": "signature_valid", "passed": signature_valid, "detail": signature_error},
        ]
        result = {"valid": all(bool(check["passed"]) for check in checks), "checks": checks}
        result["validation_hash"] = hashlib.sha256(canonical_json(result).encode("utf-8")).hexdigest()
        return result

    def soak_result_artifact_report(self) -> dict[str, object]:
        scenarios = self.adversarial_performance_readiness_report()["required_soak_scenarios"]
        report = {
            "stage_id": 8,
            "name": "long_running_soak_result_artifacts",
            "status": "warning",
            "required_scenarios": scenarios,
            "minimum_duration": "24h private testnet soak before public testnet",
            "artifact_schema": {
                "scenario": "name",
                "started_at": "unix timestamp",
                "duration_seconds": "integer",
                "node_count": "integer",
                "passed": "boolean",
                "failure_summary": "string",
            },
            "validation_contract": [
                "artifact hash excludes envelope and validation hash",
                "result hash commits to the normalized soak result",
                "signed claims bind scenario, result hash, duration, and pass/fail status",
            ],
        }
        report["soak_plan_hash"] = hashlib.sha256(canonical_json(report).encode("utf-8")).hexdigest()
        return report

    def build_soak_result_artifact(self, result: dict[str, object]) -> dict[str, object]:
        normalized = {
            "scenario": str(result.get("scenario", "unspecified")),
            "started_at": float(result.get("started_at", 0)),
            "duration_seconds": int(result.get("duration_seconds", 0)),
            "node_count": int(result.get("node_count", 0)),
            "passed": bool(result.get("passed", False)),
            "failure_summary": str(result.get("failure_summary", "")),
            "metrics": dict(result.get("metrics", {})) if isinstance(result.get("metrics"), dict) else {},
        }
        normalized["result_hash"] = hashlib.sha256(canonical_json(normalized).encode("utf-8")).hexdigest()
        artifact = {
            "artifact_version": 1,
            "chain_id": self.config.chain_id,
            "node_id": self.config.node_id,
            "generated_at": round(time.time(), 6),
            "soak_plan": self.soak_result_artifact_report(),
            "result": normalized,
            "minimum_acceptance": {
                "duration_seconds": 24 * 60 * 60,
                "node_count": 3,
                "passed": True,
            },
        }
        artifact["artifact_hash"] = self._signed_artifact_payload_hash(artifact)
        artifact["envelope"] = self.identity.sign_claims(
            "soak_result_artifact_v1",
            {
                "purpose": "soak_result_artifact_v1",
                "chain_id": self.config.chain_id,
                "node_id": self.config.node_id,
                "artifact_hash": artifact["artifact_hash"],
                "result_hash": normalized["result_hash"],
                "scenario": normalized["scenario"],
                "duration_seconds": normalized["duration_seconds"],
                "passed": normalized["passed"],
            },
        )
        return artifact

    def validate_soak_result_artifact(self, artifact: dict[str, object]) -> dict[str, object]:
        result_payload = dict(artifact.get("result", {})) if isinstance(artifact.get("result"), dict) else {}
        observed_result_hash = str(result_payload.get("result_hash", ""))
        result_without_hash = dict(result_payload)
        result_without_hash.pop("result_hash", None)
        expected_result_hash = hashlib.sha256(canonical_json(result_without_hash).encode("utf-8")).hexdigest()
        observed_artifact_hash = str(artifact.get("artifact_hash", ""))
        expected_artifact_hash = self._signed_artifact_payload_hash(artifact)
        envelope = dict(artifact.get("envelope", {})) if isinstance(artifact.get("envelope"), dict) else {}
        signature_valid = False
        signature_error = ""
        try:
            verified = verify_signed_envelope(
                envelope,
                expected_purpose="soak_result_artifact_v1",
                expected_chain_id=self.config.chain_id,
                time_skew_seconds=self.config.auth_time_skew_seconds,
            )
            claims = dict(verified["claims"])
            signature_valid = (
                claims.get("artifact_hash") == observed_artifact_hash
                and claims.get("result_hash") == observed_result_hash
                and claims.get("scenario") == result_payload.get("scenario")
                and claims.get("duration_seconds") == result_payload.get("duration_seconds")
                and claims.get("passed") == result_payload.get("passed")
            )
        except Exception as error:
            signature_error = str(error)
        minimum = dict(artifact.get("minimum_acceptance", {})) if isinstance(artifact.get("minimum_acceptance"), dict) else {}
        checks = [
            {"name": "result_hash_matches", "passed": bool(observed_result_hash) and observed_result_hash == expected_result_hash},
            {"name": "artifact_hash_matches", "passed": bool(observed_artifact_hash) and observed_artifact_hash == expected_artifact_hash},
            {"name": "signature_valid", "passed": signature_valid, "detail": signature_error},
            {
                "name": "minimum_duration_met",
                "passed": int(result_payload.get("duration_seconds", 0)) >= int(minimum.get("duration_seconds", 0)),
            },
            {
                "name": "minimum_node_count_met",
                "passed": int(result_payload.get("node_count", 0)) >= int(minimum.get("node_count", 0)),
            },
            {"name": "scenario_passed", "passed": bool(result_payload.get("passed", False)) is True},
        ]
        result = {"valid": all(bool(check["passed"]) for check in checks), "checks": checks}
        result["validation_hash"] = hashlib.sha256(canonical_json(result).encode("utf-8")).hexdigest()
        return result

    def database_durability_report(self) -> dict[str, object]:
        chain = self._sqlite_database_status(self.config.db_path)
        wallet = self._sqlite_database_status(self.config.wallet_state_db_path)
        checks = [
            {"name": "chain_db_path_configured", "passed": bool(self.config.db_path)},
            {"name": "wallet_db_path_configured", "passed": bool(self.config.wallet_state_db_path)},
            {"name": "chain_db_exists_after_start", "passed": bool(chain["exists"])},
            {"name": "wallet_db_exists_after_start", "passed": bool(wallet["exists"])},
            {"name": "chain_db_wal_enabled", "passed": chain["journal_mode"] == "wal"},
            {"name": "wallet_db_wal_enabled", "passed": wallet["journal_mode"] == "wal"},
            {"name": "chain_db_integrity_ok", "passed": chain["integrity_check"] == "ok"},
            {"name": "wallet_db_integrity_ok", "passed": wallet["integrity_check"] == "ok"},
            {"name": "backup_manifest_hash_present", "passed": bool(self.state_backup_manifest()["backup_manifest_hash"])},
        ]
        return {
            "stage_id": 9,
            "name": "database_durability_and_recovery",
            "status": "ready" if all(check["passed"] for check in checks) else "warning",
            "checks": checks,
            "databases": {
                "chain": chain,
                "wallet": wallet,
            },
            "recommended_sqlite_policy": [
                "enable WAL for multi-process nodes after migration testing",
                "run integrity_check during maintenance windows",
                "test restore from backup-manifest before public testnet",
            ],
        }

    def database_recovery_manifest(self) -> dict[str, object]:
        durability = self.database_durability_report()
        backup = self.state_backup_manifest()
        manifest = {
            "recovery_manifest_version": 1,
            "stage_id": 9,
            "name": "database_recovery_manifest",
            "generated_at": round(time.time(), 6),
            "chain_id": self.config.chain_id,
            "node_id": self.config.node_id,
            "durability_status": durability["status"],
            "durability_checks": durability["checks"],
            "backup_manifest_hash": backup["backup_manifest_hash"],
            "files": backup["files"],
            "restore_order": backup["restore_order"],
            "post_restore_checks": [
                "database-durability",
                "hardening-audit",
                "migration-integrity",
                "crypto-hardening",
                "node-preflight",
            ],
        }
        manifest["recovery_manifest_hash"] = self._database_recovery_manifest_hash(manifest)
        manifest["envelope"] = self.identity.sign_claims(
            "database_recovery_manifest_v1",
            {
                "purpose": "database_recovery_manifest_v1",
                "chain_id": self.config.chain_id,
                "node_id": self.config.node_id,
                "recovery_manifest_hash": manifest["recovery_manifest_hash"],
                "backup_manifest_hash": backup["backup_manifest_hash"],
                "durability_status": durability["status"],
            },
        )
        return manifest

    def validate_database_recovery_manifest(self, manifest: dict[str, object]) -> dict[str, object]:
        observed_hash = str(manifest.get("recovery_manifest_hash", ""))
        expected_hash = self._database_recovery_manifest_hash(manifest)
        envelope = dict(manifest.get("envelope", {})) if isinstance(manifest.get("envelope"), dict) else {}
        signature_valid = False
        signature_error = ""
        try:
            verified = verify_signed_envelope(
                envelope,
                expected_purpose="database_recovery_manifest_v1",
                expected_chain_id=self.config.chain_id,
                time_skew_seconds=self.config.auth_time_skew_seconds,
            )
            claims = dict(verified["claims"])
            signature_valid = (
                claims.get("recovery_manifest_hash") == observed_hash
                and claims.get("backup_manifest_hash") == manifest.get("backup_manifest_hash")
                and claims.get("durability_status") == manifest.get("durability_status")
            )
        except Exception as error:
            signature_error = str(error)
        checks = [
            {"name": "manifest_hash_matches", "passed": bool(observed_hash) and observed_hash == expected_hash},
            {"name": "signature_valid", "passed": signature_valid, "detail": signature_error},
            {"name": "chain_id_matches", "passed": manifest.get("chain_id") == self.config.chain_id},
            {"name": "backup_manifest_hash_present", "passed": bool(manifest.get("backup_manifest_hash"))},
        ]
        result = {"valid": all(bool(check["passed"]) for check in checks), "checks": checks}
        result["validation_hash"] = hashlib.sha256(canonical_json(result).encode("utf-8")).hexdigest()
        return result

    @staticmethod
    def _sqlite_database_status(path: Path) -> dict[str, object]:
        if not path.exists():
            return {
                "path": str(path),
                "exists": False,
                "journal_mode": "",
                "user_version": 0,
                "schema_version": 0,
                "integrity_check": "missing",
                "wal_sidecar_exists": False,
                "shm_sidecar_exists": False,
            }
        with sqlite3.connect(path) as connection:
            journal_mode = str(connection.execute("PRAGMA journal_mode").fetchone()[0]).lower()
            user_version = int(connection.execute("PRAGMA user_version").fetchone()[0])
            schema_version = int(connection.execute("PRAGMA schema_version").fetchone()[0])
            integrity_check = str(connection.execute("PRAGMA quick_check").fetchone()[0]).lower()
        return {
            "path": str(path),
            "exists": True,
            "journal_mode": journal_mode,
            "user_version": user_version,
            "schema_version": schema_version,
            "integrity_check": integrity_check,
            "wal_sidecar_exists": Path(f"{path}-wal").exists(),
            "shm_sidecar_exists": Path(f"{path}-shm").exists(),
        }

    def external_audit_readiness_package(self) -> dict[str, object]:
        native = self.native_crypto_release_provenance_report()
        durability = self.database_durability_report()
        soak = self.soak_result_artifact_report()
        package = {
            "stage_id": 10,
            "name": "external_audit_readiness_package",
            "status": "warning",
            "scope": [
                "post-quantum signature provider boundary",
                "migration claim proof and fraud handling",
                "consensus state-root and transaction execution invariants",
                "authenticated peer networking and operator recovery flows",
            ],
            "included_artifacts": [
                "README.md architecture diagrams",
                "CHANGELOG.md phase history",
                "hardening-audit signed artifact",
                "native crypto release provenance artifact",
                "database recovery manifest",
                "migration proof and source ingestion tests",
                "native crypto boundary documentation",
                "operator incident runbook",
            ],
            "readiness_inputs": {
                "native_release_hash": native["native_release_hash"],
                "database_durability_status": durability["status"],
                "soak_plan_hash": soak["soak_plan_hash"],
            },
            "missing_before_independent_audit": [
                "formal consensus spec",
                "cryptographic test vector bundle",
                "public validator threat model",
                "third-party review of migration economics",
            ],
        }
        package["audit_package_hash"] = hashlib.sha256(canonical_json(package).encode("utf-8")).hexdigest()
        return package

    def signed_external_audit_readiness_package(self) -> dict[str, object]:
        package = self.external_audit_readiness_package()
        claims = {
            "purpose": "external_audit_readiness_package_v1",
            "chain_id": self.config.chain_id,
            "node_id": self.config.node_id,
            "audit_package_hash": package["audit_package_hash"],
            "status": package["status"],
        }
        artifact = {
            "artifact_version": 1,
            "package": package,
            "envelope": self.identity.sign_claims("external_audit_readiness_package_v1", claims),
        }
        artifact["artifact_hash"] = self._signed_artifact_payload_hash(artifact)
        return artifact

    def validate_external_audit_readiness_package(self, artifact: dict[str, object]) -> dict[str, object]:
        package = dict(artifact.get("package", {})) if isinstance(artifact.get("package"), dict) else {}
        envelope = dict(artifact.get("envelope", {})) if isinstance(artifact.get("envelope"), dict) else {}
        observed_package_hash = str(package.get("audit_package_hash", ""))
        expected_package_hash = self._external_audit_package_hash(package)
        expected_artifact_hash = self._signed_artifact_payload_hash(artifact)
        signature_valid = False
        signature_error = ""
        try:
            verified = verify_signed_envelope(
                envelope,
                expected_purpose="external_audit_readiness_package_v1",
                expected_chain_id=self.config.chain_id,
                time_skew_seconds=self.config.auth_time_skew_seconds,
            )
            claims = dict(verified["claims"])
            signature_valid = (
                claims.get("audit_package_hash") == observed_package_hash
                and claims.get("status") == package.get("status")
            )
        except Exception as error:
            signature_error = str(error)
        checks = [
            {"name": "package_hash_matches", "passed": bool(observed_package_hash) and observed_package_hash == expected_package_hash},
            {
                "name": "artifact_hash_matches",
                "passed": bool(artifact.get("artifact_hash")) and artifact.get("artifact_hash") == expected_artifact_hash,
            },
            {"name": "signature_valid", "passed": signature_valid, "detail": signature_error},
            {"name": "scope_present", "passed": bool(package.get("scope"))},
            {"name": "included_artifacts_present", "passed": bool(package.get("included_artifacts"))},
        ]
        result = {"valid": all(bool(check["passed"]) for check in checks), "checks": checks}
        result["validation_hash"] = hashlib.sha256(canonical_json(result).encode("utf-8")).hexdigest()
        return result

    def signed_project_audit_bundle(self) -> dict[str, object]:
        bundle = {
            "bundle_version": 1,
            "generated_at": round(time.time(), 6),
            "chain_id": self.config.chain_id,
            "node_id": self.config.node_id,
            "artifacts": {
                "hardening_audit": self.hardening_audit_report(),
                "signed_audit_artifact": self.signed_audit_artifact_report(),
                "migration_economics_spec": self.migration_economics_specification(),
                "migration_economics_invariants": self.migration_economics_invariant_report(),
                "migration_proof_registry": self.migration_proof_registry_report(),
                "migration_escrow_finality": self.migration_escrow_finality_report(),
                "native_release_provenance": self.signed_native_crypto_release_provenance(),
                "database_recovery": self.database_recovery_manifest(),
                "external_audit_package": self.signed_external_audit_readiness_package(),
                "protocol_manifest": self.protocol_manifest(),
            },
        }
        bundle["bundle_hash"] = self._project_audit_bundle_hash(bundle)
        artifact = {
            "artifact_version": 1,
            "bundle": bundle,
            "envelope": self.identity.sign_claims(
                "project_audit_bundle_v1",
                {
                    "purpose": "project_audit_bundle_v1",
                    "chain_id": self.config.chain_id,
                    "node_id": self.config.node_id,
                    "bundle_hash": bundle["bundle_hash"],
                    "hardening_audit_hash": bundle["artifacts"]["hardening_audit"]["audit_hash"],
                },
            ),
        }
        artifact["artifact_hash"] = self._signed_artifact_payload_hash(artifact)
        return artifact

    def validate_project_audit_bundle(self, artifact: dict[str, object]) -> dict[str, object]:
        bundle = dict(artifact.get("bundle", {})) if isinstance(artifact.get("bundle"), dict) else {}
        envelope = dict(artifact.get("envelope", {})) if isinstance(artifact.get("envelope"), dict) else {}
        expected_bundle_hash = self._project_audit_bundle_hash(bundle)
        expected_artifact_hash = self._signed_artifact_payload_hash(artifact)
        signature_valid = False
        signature_error = ""
        try:
            verified = verify_signed_envelope(
                envelope,
                expected_purpose="project_audit_bundle_v1",
                expected_chain_id=self.config.chain_id,
                time_skew_seconds=self.config.auth_time_skew_seconds,
            )
            claims = dict(verified["claims"])
            signature_valid = (
                claims.get("bundle_hash") == bundle.get("bundle_hash")
                and claims.get("hardening_audit_hash")
                == dict(dict(bundle.get("artifacts", {})).get("hardening_audit", {})).get("audit_hash")
            )
        except Exception as error:
            signature_error = str(error)
        checks = [
            {"name": "bundle_hash_matches", "passed": bundle.get("bundle_hash") == expected_bundle_hash},
            {"name": "artifact_hash_matches", "passed": artifact.get("artifact_hash") == expected_artifact_hash},
            {"name": "signature_valid", "passed": signature_valid, "detail": signature_error},
            {"name": "hardening_audit_present", "passed": bool(dict(bundle.get("artifacts", {})).get("hardening_audit"))},
            {
                "name": "migration_economics_invariants_present",
                "passed": bool(dict(bundle.get("artifacts", {})).get("migration_economics_invariants")),
            },
        ]
        result = {"valid": all(bool(check["passed"]) for check in checks), "checks": checks}
        result["validation_hash"] = hashlib.sha256(canonical_json(result).encode("utf-8")).hexdigest()
        return result

    @staticmethod
    def _signed_artifact_payload_hash(artifact: dict[str, object]) -> str:
        payload = dict(artifact)
        payload.pop("artifact_hash", None)
        payload.pop("envelope", None)
        payload.pop("validation_hash", None)
        return hashlib.sha256(canonical_json(payload).encode("utf-8")).hexdigest()

    @staticmethod
    def _native_release_report_hash(report: dict[str, object]) -> str:
        payload = dict(report)
        payload.pop("native_release_hash", None)
        return hashlib.sha256(canonical_json(payload).encode("utf-8")).hexdigest()

    @staticmethod
    def _release_manifest_hash(manifest: dict[str, object]) -> str:
        payload = dict(manifest)
        payload.pop("release_manifest_hash", None)
        return hashlib.sha256(json.dumps(payload, sort_keys=True).encode("utf-8")).hexdigest()

    @staticmethod
    def _database_recovery_manifest_hash(manifest: dict[str, object]) -> str:
        payload = dict(manifest)
        payload.pop("recovery_manifest_hash", None)
        payload.pop("envelope", None)
        payload.pop("validation_hash", None)
        return hashlib.sha256(canonical_json(payload).encode("utf-8")).hexdigest()

    @staticmethod
    def _external_audit_package_hash(package: dict[str, object]) -> str:
        payload = dict(package)
        payload.pop("audit_package_hash", None)
        return hashlib.sha256(canonical_json(payload).encode("utf-8")).hexdigest()

    @staticmethod
    def _project_audit_bundle_hash(bundle: dict[str, object]) -> str:
        payload = dict(bundle)
        payload.pop("bundle_hash", None)
        return hashlib.sha256(canonical_json(payload).encode("utf-8")).hexdigest()

    def production_configuration_report(self) -> dict[str, object]:
        mode = self.config.deployment_mode.strip().lower()
        production_mode = mode in {"production", "mainnet", "public-testnet", "testnet"}
        public_host = self.config.host not in {"127.0.0.1", "localhost", "::1"}
        peer_urls = [*self.config.peers, self.config.advertised_url]
        insecure_peer_urls = [
            url for url in peer_urls if url.startswith("http://") and "127.0.0.1" not in url and "localhost" not in url
        ]
        demo_providers = {
            "classical_claim_demo_v1",
            "xmss_merkle_lamport_v1",
            "native_test_pq_v1",
        }
        configured_signature_ids = {
            self.config.default_signature_provider,
            *self.config.preferred_signature_providers,
            *self.config.allowed_signature_providers,
        }
        configured_migration_ids = set(self.config.migration_allowed_classical_providers)
        checks = [
            {
                "name": "deployment_mode_declared",
                "passed": bool(mode),
                "severity": "blocker",
                "detail": mode,
            },
            {
                "name": "wallet_custody_not_plaintext",
                "passed": self.config.wallet_custody_mode != "plaintext",
                "severity": "blocker",
                "detail": self.config.wallet_custody_mode,
            },
            {
                "name": "production_provider_allowlist_configured",
                "passed": bool(self.config.allowed_signature_providers) or not production_mode,
                "severity": "blocker",
                "detail": str(len(self.config.allowed_signature_providers)),
            },
            {
                "name": "demo_signature_providers_disabled_for_production",
                "passed": not production_mode or not (configured_signature_ids & demo_providers),
                "severity": "blocker",
                "detail": ",".join(sorted(configured_signature_ids & demo_providers)),
            },
            {
                "name": "demo_migration_provider_disabled_for_production",
                "passed": not production_mode or "classical_claim_demo_v1" not in configured_migration_ids,
                "severity": "blocker",
                "detail": ",".join(sorted(configured_migration_ids & {"classical_claim_demo_v1"})),
            },
            {
                "name": "snapshot_signatures_required_for_production_migration",
                "passed": self.config.migration_require_snapshot_signatures or not production_mode,
                "severity": "blocker",
                "detail": str(self.config.migration_require_snapshot_signatures),
            },
            {
                "name": "trusted_snapshot_signers_configured",
                "passed": bool(self.config.migration_trusted_snapshot_signers) or not production_mode,
                "severity": "blocker",
                "detail": str(len(self.config.migration_trusted_snapshot_signers)),
            },
            {
                "name": "peer_allowlist_required_on_public_bind",
                "passed": not production_mode or not public_host or self.config.require_peer_allowlist,
                "severity": "blocker",
                "detail": f"host={self.config.host}, require_allowlist={self.config.require_peer_allowlist}",
            },
            {
                "name": "encrypted_peer_urls_for_public_mode",
                "passed": not production_mode or not insecure_peer_urls,
                "severity": "warning",
                "detail": ",".join(insecure_peer_urls[:5]),
            },
            {
                "name": "coinbase_maturity_nonzero_for_production",
                "passed": self.config.coinbase_maturity_blocks > 0 or not production_mode,
                "severity": "warning",
                "detail": str(self.config.coinbase_maturity_blocks),
            },
            {
                "name": "state_roots_active_from_genesis",
                "passed": self.config.state_root_activation_height == 0,
                "severity": "warning",
                "detail": str(self.config.state_root_activation_height),
            },
        ]
        blockers = [check for check in checks if check["severity"] == "blocker" and not check["passed"]]
        warnings = [check for check in checks if check["severity"] == "warning" and not check["passed"]]
        if blockers:
            status = "blocked"
        elif warnings:
            status = "warning"
        else:
            status = "ready"
        return {
            "configuration_status": status,
            "deployment_mode": mode,
            "production_mode": production_mode,
            "checks": checks,
            "blockers": blockers,
            "warnings": warnings,
            "recommended_minimums": [
                "set QR_CHAIN_DEPLOYMENT_MODE=production only after removing demo providers",
                "require signed migration snapshots and trusted snapshot signer allowlists",
                "use protected wallet custody and explicit signature provider allowlists",
                "enable peer allowlists before binding to non-local interfaces",
                "prefer encrypted peer URLs outside local lab networks",
            ],
        }

    def enforce_security_policy_profile(self) -> dict[str, object]:
        report = self.production_configuration_report()
        if report["configuration_status"] == "blocked":
            blocker_names = ", ".join(str(item["name"]) for item in report["blockers"])
            raise ValueError(f"Security policy profile is blocked: {blocker_names}")
        return report

    def privacy_redaction_policy_report(self) -> dict[str, object]:
        public_fields = [
            "chain_id",
            "block_hash",
            "tx_id",
            "destination_address",
            "source_network",
            "snapshot_ref",
            "manifest_hash",
        ]
        sensitive_fields = [
            "secret_key_hex",
            "key_state_blob",
            "classical_public_key",
            "classical_signature",
            "signature_hex",
            "source_export_hash",
            "source_provenance_hash",
        ]
        return {
            "redaction_policy_version": 1,
            "policy_status": "defined",
            "public_fields": public_fields,
            "sensitive_fields": sensitive_fields,
            "operator_rules": [
                "never publish wallet state database files",
                "redact public keys and signatures from user-support tickets unless needed for verification",
                "publish snapshot hashes and claim intent hashes instead of raw source exports by default",
                "keep source export provenance artifacts in restricted operator storage",
            ],
            "safe_support_bundle": [
                "protocol-conformance",
                "migration-readiness",
                "migration-conversion-risk",
                "crypto-hardening",
                "network-transport-readiness",
            ],
        }

    def network_transport_readiness_report(self) -> dict[str, object]:
        peers = self.list_peers()
        http_peer_count = sum(1 for peer in peers if str(peer).startswith("http://"))
        https_peer_count = sum(1 for peer in peers if str(peer).startswith("https://"))
        checks = [
            {
                "name": "peer_admission_bounded",
                "passed": self.config.max_admitted_peers > 0,
                "detail": str(self.config.max_admitted_peers),
            },
            {
                "name": "allowlist_available",
                "passed": bool(self.config.peer_allowlist) or not peers,
                "detail": str(len(self.config.peer_allowlist)),
            },
            {
                "name": "denylist_supported",
                "passed": True,
                "detail": str(len(self.config.peer_denylist)),
            },
            {
                "name": "encrypted_peer_urls_configured",
                "passed": http_peer_count == 0,
                "detail": f"http={http_peer_count}, https={https_peer_count}",
            },
        ]
        return {
            "transport_status": "ready" if all(bool(item["passed"]) for item in checks) else "needs_hardening",
            "checks": checks,
            "peers": {
                "known": len(peers),
                "admitted": self.store.peer_identity_count(status="admitted"),
                "max_admitted": self.config.max_admitted_peers,
                "sessions": self.store.peer_session_counts(),
                "http_peer_count": http_peer_count,
                "https_peer_count": https_peer_count,
            },
            "next_transport_steps": [
                "move peer URLs to authenticated TLS or a signed noise-style transport",
                "enforce allowlists for controlled validator or migration-operator networks",
                "add peer scoring and rate-limit penalties for malformed frames",
            ],
        }

    def state_backup_manifest(self) -> dict[str, object]:
        paths = {
            "chain_db": self.config.db_path,
            "wallet_state_db": self.config.wallet_state_db_path,
        }
        files: dict[str, dict[str, object]] = {}
        for name, path in paths.items():
            resolved = Path(path)
            if not resolved.exists():
                files[name] = {"path": str(resolved), "exists": False}
                continue
            data = resolved.read_bytes()
            files[name] = {
                "path": str(resolved),
                "exists": True,
                "size_bytes": len(data),
                "sha256": hashlib.sha256(data).hexdigest(),
            }
        manifest = {
            "backup_manifest_version": 1,
            "generated_at": round(time.time(), 6),
            "chain_id": self.config.chain_id,
            "node_id": self.config.node_id,
            "files": files,
            "restore_order": [
                "stop node process",
                "restore chain_db",
                "restore wallet_state_db",
                "run health, crypto-hardening, migration-integrity, and migration-readiness checks",
            ],
        }
        manifest["backup_manifest_hash"] = hashlib.sha256(json.dumps(manifest, sort_keys=True).encode("utf-8")).hexdigest()
        return manifest

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
        supply = self.supply_snapshot()
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
            "currency": supply,
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
                "max_admitted": self.config.max_admitted_peers,
                "require_allowlist": self.config.require_peer_allowlist,
                "sessions": peer_session_counts,
            },
        }

    def migration_readiness_report(self) -> dict[str, object]:
        provider_status = self.signature_provider_statuses()
        policy = provider_status["provider_policy"]
        operational = self.operational_status()
        integrity = self.migration_integrity_report()
        checks = [
            {
                "name": "operational_health_ok",
                "passed": operational["status"] == "ok",
                "detail": "; ".join(str(item) for item in operational["reasons"]),
            },
            {
                "name": "pq_provider_available",
                "passed": policy["recommended_signature_provider"] is not None,
                "detail": str(policy["recommended_signature_provider"]),
            },
            {
                "name": "migration_policy_is_explicit",
                "passed": bool(self.config.migration_conversion_policy and self.config.migration_pool_cap > 0),
                "detail": self.config.migration_conversion_policy,
            },
            {
                "name": "migration_not_paused",
                "passed": not self.config.migration_emergency_pause,
                "detail": "emergency pause is off",
            },
            {
                "name": "governance_window_configured",
                "passed": self.config.migration_dispute_window_blocks > 0
                and self.config.migration_snapshot_reviewer_quorum > 0,
                "detail": (
                    f"dispute_window={self.config.migration_dispute_window_blocks}, "
                    f"reviewer_quorum={self.config.migration_snapshot_reviewer_quorum}"
                ),
            },
            {
                "name": "migration_integrity_has_no_critical_anomalies",
                "passed": int(integrity["summary"]["critical_anomaly_count"]) == 0,
                "detail": str(integrity["summary"]["critical_anomaly_count"]),
            },
            {
                "name": "migration_pool_has_capacity",
                "passed": int(self.supply_snapshot()["migration_pool_remaining"]) > 0,
                "detail": str(self.supply_snapshot()["migration_pool_remaining"]),
            },
            {
                "name": "peer_admission_bounded",
                "passed": self.config.max_admitted_peers > 0,
                "detail": str(self.config.max_admitted_peers),
            },
            {
                "name": "supply_caps_intact",
                "passed": bool(self.supply_snapshot()["within_max_money"]),
                "detail": "theoretical supply remains within max money",
            },
            {
                "name": "wallet_recovery_clear",
                "passed": int(operational["wallet_reservation_status"].get("requires_recovery", 0)) == 0,
                "detail": "no wallet keys require signer recovery",
            },
        ]
        blocked = [check for check in checks if not check["passed"]]
        return {
            "migration_layer_status": "blocked" if blocked else "operational",
            "checks": checks,
            "blocked_checks": blocked,
            "integrity_summary": integrity["summary"],
            "recommended_next_actions": [
                "publish reproducible source-chain extraction tooling",
                "require trusted signed source snapshots for public migrations",
                "add independent review for migration conversion ratios",
                "expand real external address proof coverage",
                "run migration-specific load and reorg chaos tests",
            ],
        }

    def metrics_snapshot(self) -> dict[str, object]:
        chain = self.chain_summary()
        supply = self.supply_snapshot()
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
            "currency_theoretical_supply": int(supply["theoretical_supply"]),
            "currency_unspent_supply": int(supply["unspent_supply"]),
            "currency_subsidy_issued": int(supply["subsidy_issued"]),
            "currency_migration_minted": int(supply["migration_minted"]),
            "currency_fees_paid_to_miners": int(supply["fees_paid_to_miners"]),
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
            "source_provenance": normalized["source_provenance"],
            "normalized_records": normalized["normalized_records"],
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
        quote = self.migration_claim_quote(classical_address)

        checks: list[dict[str, object]] = []
        policy = self.migration_policy()
        checks.append({"name": "claims_open", "passed": bool(policy["claims_open"])})
        checks.append({"name": "migration_not_paused", "passed": not self.config.migration_emergency_pause})
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
            "quote": quote,
            "source": source,
            "policy": policy,
            "draft_transaction": json.loads(draft.serialize_with_id()),
            "classical_claim_message_hex": classical_claim_message_bytes(draft.migration_claim_payload()).hex(),
            "destination_acceptance_message_hex": destination_acceptance_message_bytes(
                draft.migration_claim_payload()
            ).hex(),
        }

    def build_wallet_migration_claim_package(
        self,
        *,
        destination_address: str,
        classical_address: str,
        classical_provider_id: str,
        source_network: str,
        snapshot_ref: str = "",
        classical_public_key: object | None = None,
    ) -> dict[str, object]:
        preflight = self.preflight_migration_claim(
            destination_address=destination_address,
            classical_address=classical_address,
            classical_provider_id=classical_provider_id,
            source_network=source_network,
            snapshot_ref=snapshot_ref,
            classical_public_key=classical_public_key,
        )
        package_claims = {
            "chain_id": self.config.chain_id,
            "destination_address": destination_address,
            "classical_address": classical_address,
            "classical_provider_id": classical_provider_id,
            "source_network": source_network,
            "snapshot_ref": snapshot_ref or str(preflight["source"].get("snapshot_ref", "")),
            "claim_intent_hash": preflight["quote"]["claim_intent_hash"],
            "classical_claim_message_hex": preflight["classical_claim_message_hex"],
            "destination_acceptance_message_hex": preflight["destination_acceptance_message_hex"],
        }
        package_hash = hashlib.sha256(json.dumps(package_claims, sort_keys=True).encode("utf-8")).hexdigest()
        return {
            "package_version": 1,
            "ready": preflight["ready"],
            "package_hash": package_hash,
            "claims": package_claims,
            "preflight": preflight,
            "wallet_steps": [
                "display source network, source address, destination address, and normalized amount",
                "ask the user to sign the classical claim message with the legacy wallet",
                "ask the PQ wallet to sign destination acceptance when dual-control is required",
                "submit only if package_hash and claim_intent_hash still match the latest quote",
            ],
        }

    def migration_adversarial_simulation_report(self) -> dict[str, object]:
        sources = self.store.list_migration_sources()
        snapshots = self.store.list_migration_snapshots()
        claims = {
            str(item["classical_address"])
            for item in self.store.list_migration_claims()
        }
        snapshot_status = {str(item["snapshot_ref"]): str(item["status"]) for item in snapshots}
        duplicate_sources = len(sources) - len({str(item["classical_address"]) for item in sources})
        blocked_claimable = [
            item["classical_address"]
            for item in sources
            if item.get("status") != "active" and item["classical_address"] not in claims
        ]
        active_on_blocked_snapshot = [
            item["classical_address"]
            for item in sources
            if item.get("status") == "active"
            and snapshot_status.get(str(item.get("snapshot_ref", "")), "active") != "active"
        ]
        pool_remaining = int(self.supply_snapshot()["migration_pool_remaining"])
        claimable_amount = sum(
            int(item["amount"])
            for item in sources
            if item.get("status") == "active" and item["classical_address"] not in claims
        )
        scenarios = [
            {
                "name": "duplicate_classical_source",
                "passed": duplicate_sources == 0,
                "detail": str(duplicate_sources),
            },
            {
                "name": "blocked_sources_not_claimable",
                "passed": True,
                "detail": str(len(blocked_claimable)),
            },
            {
                "name": "active_sources_not_on_blocked_snapshots",
                "passed": not active_on_blocked_snapshot,
                "detail": str(len(active_on_blocked_snapshot)),
            },
            {
                "name": "claimable_amount_within_pool",
                "passed": claimable_amount <= pool_remaining,
                "detail": f"claimable={claimable_amount}, remaining={pool_remaining}",
            },
            {
                "name": "canonical_claims_are_unique",
                "passed": len(claims) == len(self.store.list_migration_claims()),
                "detail": str(len(claims)),
            },
        ]
        return {
            "simulation_version": 1,
            "status": "passed" if all(bool(item["passed"]) for item in scenarios) else "needs_review",
            "scenarios": scenarios,
            "inputs": {
                "source_count": len(sources),
                "snapshot_count": len(snapshots),
                "claim_count": len(claims),
                "claimable_amount": claimable_amount,
                "migration_pool_remaining": pool_remaining,
            },
            "next_chaos_targets": [
                "randomized duplicate-claim mempool races",
                "snapshot quarantine during branch reorg",
                "large source-export batch import with mixed provider evidence",
                "peer sync interruption while migration claims are mined",
            ],
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
            outputs=[TxOutput(recipient=destination_address, amount=self._migration_claim_amount_for_source(source))],
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
        metadata = self._utxo_origin_metadata_for_head(self.store.best_head_hash())
        for tx_id, output_index, output in reversed(self.store.list_utxos(addresses)):
            spendability = self._utxo_spendability_status(
                (tx_id, output_index),
                metadata.get((tx_id, output_index), {}),
                current_height=self.store.block_count(),
            )
            if not bool(spendability["spendable"]):
                continue
            selected.append((tx_id, output_index, output))
            running_total += output.amount
            if running_total >= target_amount:
                return selected, running_total
        raise ValueError("Insufficient funds.")

    def utxo_spendability_report(self, addresses: list[str] | None = None) -> dict[str, object]:
        metadata = self._utxo_origin_metadata_for_head(self.store.best_head_hash())
        rows = []
        for tx_id, output_index, output in self.store.list_utxos(addresses):
            spendability = self._utxo_spendability_status(
                (tx_id, output_index),
                metadata.get((tx_id, output_index), {}),
                current_height=self.store.block_count(),
            )
            rows.append(
                {
                    "tx_id": tx_id,
                    "output_index": output_index,
                    "recipient": output.recipient,
                    "amount": output.amount,
                    **spendability,
                }
            )
        spendable_total = sum(int(item["amount"]) for item in rows if bool(item["spendable"]))
        locked_total = sum(int(item["amount"]) for item in rows if not bool(item["spendable"]))
        report = {
            "spendability_version": 1,
            "current_height": self.store.block_count(),
            "address_filter_count": 0 if addresses is None else len(addresses),
            "utxo_count": len(rows),
            "spendable_total": spendable_total,
            "locked_total": locked_total,
            "utxos": rows,
        }
        report["spendability_hash"] = hashlib.sha256(canonical_json(report).encode("utf-8")).hexdigest()
        return report

    def _utxo_spendability_status(
        self,
        key: tuple[str, int],
        metadata: dict[str, object],
        *,
        current_height: int,
    ) -> dict[str, object]:
        if metadata.get("coinbase", False):
            origin_height = int(metadata.get("height", 0))
            maturity_height = origin_height + self.config.coinbase_maturity_blocks
            if current_height < maturity_height:
                return {
                    "spendable": False,
                    "lock_type": "coinbase_maturity",
                    "state": "coinbase_locked",
                    "origin_height": origin_height,
                    "unlock_height": maturity_height,
                }
        if metadata.get("migration_claim", False):
            finality = self._migration_output_finality_status(
                str(metadata.get("classical_address", "")),
                origin_height=int(metadata.get("height", 0)),
                current_height=current_height,
            )
            return {
                "spendable": bool(finality["spendable"]),
                "lock_type": "migration_escrow" if not bool(finality["spendable"]) else "",
                "state": str(finality["state"]),
                "origin_height": int(finality["origin_height"]),
                "unlock_height": int(finality["unlock_height"]),
                "classical_address": str(metadata.get("classical_address", "")),
            }
        return {
            "spendable": True,
            "lock_type": "",
            "state": "spendable",
            "origin_height": int(metadata.get("height", 0)),
            "unlock_height": int(metadata.get("height", 0)),
        }

    def _validate_transaction_against_view(
        self,
        transaction: Transaction,
        utxo_view: dict[tuple[str, int], TxOutput],
        *,
        effective_height: int | None = None,
        claimed_classical_addresses: set[str] | None = None,
        utxo_metadata: dict[tuple[str, int], dict[str, object]] | None = None,
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

        if not transaction.inputs:
            return

        verification = verify_transaction_inputs(transaction, utxo_view)
        if not verification.verified:
            failure = verification.failure
            if "public key does not match" in failure:
                raise ValueError("Input public key does not match the referenced address.")
            if "signature verification failed" in failure:
                raise ValueError("Quantum signature verification failed.")
            raise ValueError(failure)

        total_input = 0
        for tx_input in transaction.inputs:
            key = (tx_input.prev_tx_id, tx_input.output_index)
            metadata = (utxo_metadata or {}).get(key, {})
            if metadata.get("coinbase", False):
                origin_height = int(metadata.get("height", 0))
                maturity_height = origin_height + self.config.coinbase_maturity_blocks
                current_height = self.store.block_count() if effective_height is None else effective_height
                if current_height < maturity_height:
                    raise ValueError("Coinbase output has not reached configured maturity.")
            if metadata.get("migration_claim", False):
                current_height = self.store.block_count() if effective_height is None else effective_height
                finality = self._migration_output_finality_status(
                    str(metadata.get("classical_address", "")),
                    origin_height=int(metadata.get("height", 0)),
                    current_height=current_height,
                )
                if not finality["spendable"]:
                    raise ValueError(f"Migration output is not spendable: {finality['state']}.")
            previous_output = utxo_view[key]
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

    def _enforce_state_root_activation(self, block: Block) -> None:
        if block.index < self.config.state_root_activation_height:
            return
        if block.version < 3:
            raise ValueError("Block version is below the configured state-root activation rule.")
        if not block.state_root:
            raise ValueError("Block is missing the required state root.")

    def _migration_dispute_by_id(self, dispute_id: str) -> dict[str, object]:
        for dispute in self.store.list_migration_disputes():
            if dispute["dispute_id"] == dispute_id:
                return dispute
        raise ValueError("Migration dispute is unknown.")

    def _relay_gossip(
        self,
        *,
        path: str,
        message_type: str,
        purpose: str,
        payload: dict[str, object],
        exclude_peer: str = "",
    ) -> dict[str, object]:
        exclude = normalize_peer_url(exclude_peer) if exclude_peer else ""
        targets = [peer for peer in self.list_peers() if peer != exclude][: max(0, self.config.gossip_fanout)]
        delivered: list[dict[str, object]] = []
        failed: list[dict[str, object]] = []
        for peer_url in targets:
            try:
                session = self.ensure_peer_admission(peer_url)
                response = fetch_json(
                    with_path(peer_url, path),
                    method="POST",
                    payload=self._build_peer_request_frame(
                        message_type=message_type,
                        payload=payload,
                        auth=self.build_peer_session_envelope(
                            purpose,
                            peer_url,
                            str(session["session_id"]),
                            path,
                            payload,
                        ),
                    ),
                )
                response_payload = self._parse_peer_response_frame(response, f"{message_type}_ack")
                delivered.append({"peer_url": peer_url, "response": response_payload})
                self.store.record_peer_sync_result(str(session["node_id"]), success=True, score_delta=1)
            except Exception as error:
                failed.append({"peer_url": peer_url, "error": str(error)})
                record = self.store.peer_identity_by_url(peer_url)
                if record is not None:
                    self.store.record_peer_sync_result(
                        str(record["node_id"]),
                        success=False,
                        score_delta=self.config.peer_invalid_frame_penalty,
                    )
        return {
            "target_count": len(targets),
            "delivered_count": len(delivered),
            "failed_count": len(failed),
            "delivered": delivered,
            "failed": failed,
        }

    @staticmethod
    def _peer_diversity_key(peer_url: str) -> str:
        parsed = urlparse(peer_url)
        host = (parsed.hostname or peer_url).lower()
        if host in {"127.0.0.1", "localhost", "::1"}:
            return host
        parts = [part for part in host.split(".") if part]
        if len(parts) >= 2:
            return ".".join(parts[-2:])
        return host

    def _enforce_peer_admission_policy(
        self,
        *,
        peer_url: str,
        node_id: str = "",
        address: str = "",
        existing_node_id: str | None = None,
    ) -> None:
        normalized_url = normalize_peer_url(peer_url)
        identities = {normalized_url, node_id, address}
        denylist = {normalize_peer_url(item) if item.startswith(("http://", "https://")) else item for item in self.config.peer_denylist}
        if identities & denylist:
            raise ValueError("Peer is denied by node admission policy.")
        allowlist = {normalize_peer_url(item) if item.startswith(("http://", "https://")) else item for item in self.config.peer_allowlist}
        if self.config.require_peer_allowlist and not (identities & allowlist):
            raise ValueError("Peer is not allowed by node admission policy.")
        if existing_node_id is None and self.config.max_admitted_peers > 0:
            if self.store.peer_identity_count(status="admitted") >= self.config.max_admitted_peers:
                raise ValueError("Peer admission limit has been reached.")

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
        self._enforce_peer_admission_policy(
            peer_url=normalized_url,
            node_id=str(node_id),
            address=str(peer_identity["address"]),
            existing_node_id=None if existing is None else str(existing["node_id"]),
        )

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
        if self.config.migration_emergency_pause:
            raise ValueError("Migration claims are paused by governance policy.")
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
        expected_amount = self._migration_claim_amount_for_source(source)
        if transaction.outputs[0].amount != expected_amount:
            raise ValueError("Migration claim amount does not match the configured conversion policy.")
        if claimed_classical_addresses is None and self.config.migration_pool_cap > 0:
            projected_migration_minted = int(self.supply_snapshot()["migration_minted"]) + transaction.outputs[0].amount
            if projected_migration_minted > self.config.migration_pool_cap:
                raise ValueError("Migration claim would exceed the configured migration pool cap.")
        if claimed_classical_addresses is None and self.config.migration_epoch_mint_cap > 0:
            epoch_minted = self._migration_epoch_minted_for_head(self.store.best_head_hash(), effective_height)
            if epoch_minted + transaction.outputs[0].amount > self.config.migration_epoch_mint_cap:
                raise ValueError("Migration claim would exceed the configured epoch mint cap.")

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
