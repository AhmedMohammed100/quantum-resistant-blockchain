from __future__ import annotations

import hashlib
from pathlib import Path
import sqlite3
import secrets
import time

from .auth import NodeIdentityManager, request_claims_digest, verify_signed_envelope
from .config import NodeConfig
from .crypto import get_signature_provider, get_signature_verifier
from .models import Block, Transaction, TxInput, TxOutput
from .network import fetch_json, normalize_peer_url, with_path
from .storage import SQLiteChainStore
from .wallet_store import SQLiteWalletStateStore


class NodeService:
    def __init__(self, config: NodeConfig):
        self.config = config
        self.store = SQLiteChainStore(config.db_path)
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
        self._validate_transaction_against_view(transaction, self.store.all_utxos())
        self._check_pending_double_spends(transaction)
        self.store.save_pending_transaction(transaction)

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
                self._validate_transaction_against_view(transaction, {})
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
        spent_in_block: set[tuple[str, int]] = set()
        fee_total = 0

        for index, transaction in enumerate(block.transactions):
            self._validate_transaction_against_view(transaction, utxo_view)
            if index == 0:
                continue
            fee_total += transaction.fee
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
            payload={
                "auth": self.build_peer_session_envelope(
                    "peer_summary_v2",
                    normalized,
                    session["session_id"],
                    "/peer/summary",
                )
            },
        )
        remote_height = int(summary.get("height", 0))
        local_height = self.store.block_count()
        imported = 0
        if remote_height <= local_height:
            self.store.add_peer(normalized)
            return imported

        response = fetch_json(
            with_path(normalized, "/peer/blocks"),
            method="POST",
            payload={
                "start_height": local_height,
                "auth": self.build_peer_session_envelope(
                    "peer_blocks_v2",
                    normalized,
                    session["session_id"],
                    "/peer/blocks",
                    {"start_height": local_height},
                ),
            },
        )
        for item in response.get("blocks", []):
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
            payload={"auth": request_envelope},
        )
        response_envelope = response.get("auth", {})
        peer_identity = verify_signed_envelope(
            response_envelope,
            expected_purpose="peer_handshake_ack_v2",
            expected_chain_id=self.config.chain_id,
            time_skew_seconds=self.config.auth_time_skew_seconds,
        )
        claims = peer_identity["claims"]
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
        return {
            "auth": self.build_signed_envelope(
                "peer_handshake_ack_v2",
                {
                    "target_url": peer_identity["advertised_url"],
                    "session_id": session["session_id"],
                    "session_expires_at": int(session["expires_at"]),
                },
            )
        }

    def authenticated_chain_summary(self, envelope: dict[str, object]) -> dict[str, object]:
        self._authenticate_peer_envelope(
            envelope,
            expected_purpose="peer_summary_v2",
            request_path="/peer/summary",
        )
        return self.chain_summary()

    def authenticated_blocks(self, envelope: dict[str, object], start_height: int) -> dict[str, object]:
        self._authenticate_peer_envelope(
            envelope,
            expected_purpose="peer_blocks_v2",
            request_path="/peer/blocks",
            request_claims={"start_height": start_height},
        )
        return {"blocks": [block.to_dict() for block in self.get_blocks_from_height(start_height)]}

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
    ) -> None:
        if not transaction.tx_id:
            transaction.finalize()
        expected_tx_id = hashlib.sha256(transaction.serialize().encode("utf-8")).hexdigest()
        if transaction.tx_id != expected_tx_id:
            raise ValueError("Transaction hash mismatch.")
        if transaction.chain_id != self.config.chain_id:
            raise ValueError("Transaction belongs to a different chain.")
        if not transaction.outputs:
            raise ValueError("Transaction must include at least one output.")
        if any(output.amount <= 0 for output in transaction.outputs):
            raise ValueError("All outputs must be positive.")
        if transaction.fee < 0:
            raise ValueError("Transaction fee cannot be negative.")

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
        candidate_inputs = {(item.prev_tx_id, item.output_index) for item in candidate.inputs}
        if not candidate_inputs:
            return
        for pending in self.store.pending_transactions():
            pending_inputs = {(item.prev_tx_id, item.output_index) for item in pending.inputs}
            if candidate_inputs & pending_inputs:
                raise ValueError("Transaction conflicts with a pending spend.")

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


class Wallet:
    def __init__(
        self,
        label: str,
        signature_provider: str = "xmss_merkle_lamport_v1",
        state_db_path: Path | None = None,
    ):
        self.label = label
        self.signature_provider = signature_provider
        self._provider = get_signature_provider(signature_provider)
        self._state_store = None if state_db_path is None else SQLiteWalletStateStore(Path(state_db_path))
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

    def _reserve_key_usage(self, address: str) -> tuple[object, object]:
        if self._state_store is None:
            keypair = self._keys[address]
            reservation = self._provider.reserve_signing_material(keypair)
            return keypair, reservation

        def reserve_fn(current_state: object) -> tuple[object, object]:
            keypair = self._provider.deserialize_keypair(current_state)
            reservation = self._provider.reserve_signing_material(keypair)
            return self._provider.serialize_keypair(keypair), reservation

        next_state, reservation = self._state_store.reserve_wallet_key_state(
            self.label,
            address,
            self.signature_provider,
            reserve_fn,
        )
        keypair = self._provider.deserialize_keypair(next_state)
        self._keys[address] = keypair
        return keypair, reservation

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
            keypair, reservation = self._reserve_key_usage(address)
            if reservation is not None:
                tx_input.public_key, tx_input.signature = self._provider.sign_with_reservation(
                    keypair, signing_payload, reservation
                )
            else:
                tx_input.public_key, tx_input.signature = self._provider.sign(keypair, signing_payload)
                self._persist_key(address)
        transaction.finalize()
        return transaction
