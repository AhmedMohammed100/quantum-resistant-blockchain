"""Isolated v2 test-network consensus engine; never used by the v0.1 node path."""

from __future__ import annotations

import sqlite3
from contextlib import closing
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any

from .portable_encoding import canonical_json_v1, hash_canonical_v1
from .protocol_v2 import (
    MAX_I64,
    V2SchemaError,
    _integer,
    _string,
    _validate_transaction_with_owners_v2,
    apply_transfer_v2,
    validate_block_context_v2,
    validate_state_utxos_v2,
)
from .protocol_v2_manifest import validate_v2_network_manifest

ZERO_HASH = "0" * 64
GENESIS_MINER = "qbc-genesis"
_GENESIS_FIELDS = {
    "version", "chain_id", "height", "previous_hash", "timestamp_us",
    "difficulty", "nonce", "miner", "transactions", "state_root", "block_hash",
}


def genesis_state_v2(
    chain_id: str, allocations: list[dict[str, Any]], *,
    address_validator: Callable[[str], bool], max_supply: int,
) -> dict[tuple[str, int], dict[str, Any]]:
    """Derive the immutable v2 genesis UTXOs from manifest-pinned allocations."""
    if not allocations:
        raise V2SchemaError("genesis_allocations must be non-empty")
    state: dict[tuple[str, int], dict[str, Any]] = {}
    previous = ""
    total = 0
    for index, allocation in enumerate(allocations):
        if not isinstance(allocation, dict) or set(allocation) != {"recipient", "amount"}:
            raise V2SchemaError("genesis allocation fields mismatch")
        recipient = _string(allocation["recipient"], "genesis recipient", limit=256)
        if not address_validator(recipient):
            raise V2SchemaError("genesis recipient address is invalid")
        if recipient <= previous:
            raise V2SchemaError("genesis allocations must be sorted by unique recipient")
        previous = recipient
        amount = _integer(allocation["amount"], "genesis allocation amount", minimum=1)
        total += amount
        if total > MAX_I64:
            raise V2SchemaError("genesis allocation sum overflows signed 64-bit range")
        allocation_id = hash_canonical_v1(
            "genesis-allocation-v2",
            {"version": 2, "chain_id": chain_id, "allocation_index": index,
             "recipient": recipient, "amount": amount},
        )
        state[(allocation_id, 0)] = {
            "tx_id": allocation_id, "output_index": 0,
            "recipient": recipient, "amount": amount,
        }
    if total != max_supply:
        raise V2SchemaError("genesis allocation sum must equal the manifest max_supply")
    return state


def _ordered_utxos(state: Mapping[tuple[str, int], Mapping[str, Any]]) -> list[dict[str, Any]]:
    return [dict(state[key]) for key in sorted(state)]


def create_genesis_block_v2(
    *, chain_id: str, timestamp_us: int, allocations: list[dict[str, Any]],
    max_supply: int, address_validator: Callable[[str], bool],
) -> tuple[dict[str, Any], dict[tuple[str, int], dict[str, Any]]]:
    """Create the deterministic genesis block for a new v2 test network."""
    state = genesis_state_v2(
        chain_id, allocations, address_validator=address_validator, max_supply=max_supply,
    )
    root = validate_state_utxos_v2(_ordered_utxos(state), address_validator=address_validator)
    block: dict[str, Any] = {
        "version": 2, "chain_id": chain_id, "height": 0,
        "previous_hash": ZERO_HASH, "timestamp_us": _integer(timestamp_us, "genesis_timestamp_us"),
        "difficulty": 0, "nonce": 0, "miner": GENESIS_MINER,
        "transactions": [], "state_root": root,
    }
    block["block_hash"] = hash_canonical_v1("block-v2", block)
    return block, state


class V2ConsensusNode:
    """Small deterministic node engine for isolated v2 conformance networks.

    The engine stores competing valid branches, verifies each block against its
    parent state, and selects the greatest-work branch. Its message methods are
    deliberately distinct from NodeService and the live v0.1 P2P transport.
    """

    def __init__(
        self, *, manifest: Mapping[str, Any], genesis_block: Mapping[str, Any],
        expected_chain_id: str,
        supported_kinds: set[str],
        provider_profiles: Mapping[tuple[str, str], Callable[[dict[str, Any]], None]],
        consensus_profiles: Mapping[tuple[str, str], Callable[[dict[str, Any]], None]],
        providers: Mapping[str, Callable[[Any, Any, bytes], str]],
        address_validator: Callable[[str], bool],
        database_path: str | Path | None = None,
    ) -> None:
        self.manifest = dict(manifest)
        self.chain_id = expected_chain_id
        self.address_validator = address_validator
        self.providers = dict(providers)
        self.database_path = Path(database_path) if database_path is not None else None
        self.manifest_digest = validate_v2_network_manifest(
            self.manifest, expected_chain_id=expected_chain_id,
            expected_genesis_hash=str(genesis_block.get("block_hash", "")),
            supported_kinds=supported_kinds, provider_profiles=provider_profiles,
            consensus_profiles=consensus_profiles,
        )
        profile = self.manifest["consensus_profile"]
        if profile.get("profile_id") != "qbc-pow-fixed" or profile.get("profile_version") != "1":
            raise V2SchemaError("v2 consensus node requires qbc-pow-fixed profile version 1")
        params = profile["parameters"]
        if set(params) != {
            "difficulty_bits", "max_timestamp_step_us", "max_supply",
            "genesis_timestamp_us", "genesis_allocations",
        }:
            raise V2SchemaError("qbc-pow-fixed profile parameters fields mismatch")
        self.difficulty_bits = _integer(params["difficulty_bits"], "difficulty_bits", minimum=1)
        if self.difficulty_bits > 16:
            raise V2SchemaError("difficulty_bits must be at most 16 in the fixed-work profile")
        self.max_timestamp_step_us = _integer(
            params["max_timestamp_step_us"], "max_timestamp_step_us", minimum=1,
        )
        if self.max_timestamp_step_us > 120_000_000:
            raise V2SchemaError("max_timestamp_step_us exceeds the fixed-work profile ceiling")
        self.max_supply = _integer(params["max_supply"], "max_supply", minimum=1)
        self.genesis_timestamp_us = _integer(params["genesis_timestamp_us"], "genesis_timestamp_us")
        self.genesis_allocations = params["genesis_allocations"]
        if not isinstance(self.genesis_allocations, list) or len(self.genesis_allocations) > 100_000:
            raise V2SchemaError("genesis_allocations must contain at most 100000 entries")
        self.provider_modes = {
            entry["provider_id"]: (entry["signing_mode"], entry.get("signing_domain"))
            for entry in self.manifest["signature_providers"]
        }
        self.blocks: dict[str, dict[str, Any]] = {}
        self.states: dict[str, dict[tuple[str, int], dict[str, Any]]] = {}
        self.branch_txids: dict[str, frozenset[str]] = {}
        self.work: dict[str, int] = {}
        self.tip_hash = ""
        self._initialize_genesis(dict(genesis_block))
        if self.database_path is not None:
            self._open_store_and_replay()

    @property
    def genesis_hash(self) -> str:
        return str(self.manifest["genesis_hash"])

    def handshake(self) -> dict[str, Any]:
        return {
            "protocol_version": 2, "chain_id": self.chain_id,
            "manifest_digest": self.manifest_digest, "genesis_hash": self.genesis_hash,
        }

    def _initialize_genesis(self, block: dict[str, Any]) -> None:
        if set(block) != _GENESIS_FIELDS:
            raise V2SchemaError("genesis block fields mismatch")
        if (type(block["version"]) is not int or block["version"] != 2
                or block["chain_id"] != self.chain_id
                or type(block["height"]) is not int or block["height"] != 0
                or block["previous_hash"] != ZERO_HASH
                or type(block["timestamp_us"]) is not int
                or type(block["difficulty"]) is not int or block["difficulty"] != 0
                or type(block["nonce"]) is not int or block["nonce"] != 0
                or block["miner"] != GENESIS_MINER or block["transactions"] != []):
            raise V2SchemaError("genesis block fields do not match the v2 genesis rule")
        state = genesis_state_v2(
            self.chain_id, self.genesis_allocations,
            address_validator=self.address_validator, max_supply=self.max_supply,
        )
        expected_root = validate_state_utxos_v2(
            _ordered_utxos(state), address_validator=self.address_validator,
        )
        if block["state_root"] != expected_root:
            raise V2SchemaError("genesis state_root does not match manifest allocations")
        preimage = {key: block[key] for key in block if key != "block_hash"}
        expected_hash = hash_canonical_v1("block-v2", preimage)
        if block["block_hash"] != expected_hash or expected_hash != self.genesis_hash:
            raise V2SchemaError("genesis block hash does not match manifest genesis_hash")
        if block["timestamp_us"] != self.genesis_timestamp_us:
            raise V2SchemaError("genesis timestamp does not match manifest parameters")
        self.blocks[expected_hash] = block
        self.states[expected_hash] = state
        self.branch_txids[expected_hash] = frozenset()
        self.work[expected_hash] = 0
        self.tip_hash = expected_hash

    def _open_store_and_replay(self) -> None:
        assert self.database_path is not None
        self.database_path.parent.mkdir(parents=True, exist_ok=True)
        with closing(sqlite3.connect(self.database_path)) as database:
            with database:
                database.execute(
                    "CREATE TABLE IF NOT EXISTS v2_blocks (block_hash TEXT PRIMARY KEY, payload BLOB NOT NULL)"
                )
                rows = database.execute("SELECT payload FROM v2_blocks").fetchall()
                if not rows:
                    database.execute(
                        "INSERT INTO v2_blocks(block_hash, payload) VALUES (?, ?)",
                        (self.genesis_hash, canonical_json_v1(self.blocks[self.genesis_hash])),
                    )
                    return
                loaded: list[dict[str, Any]] = []
                for (payload,) in rows:
                    from .protocol_v2 import parse_canonical_v2
                    item = parse_canonical_v2(bytes(payload), maximum=4 << 20)
                    if not isinstance(item, dict):
                        raise V2SchemaError("persisted v2 block is not an object")
                    loaded.append(item)
                loaded.sort(key=lambda item: item.get("height", -1))
                if not any(item.get("block_hash") == self.genesis_hash for item in loaded):
                    raise V2SchemaError("persistent v2 database is missing configured genesis")
                for item in loaded:
                    if item.get("block_hash") == self.genesis_hash:
                        continue
                    self.accept_block(item, persist=False)

    def _store_block(self, block: Mapping[str, Any]) -> None:
        if self.database_path is None:
            return
        with closing(sqlite3.connect(self.database_path)) as database:
            with database:
                database.execute(
                    "INSERT OR IGNORE INTO v2_blocks(block_hash, payload) VALUES (?, ?)",
                    (block["block_hash"], canonical_json_v1(dict(block))),
                )

    def canonical_blocks(self) -> list[dict[str, Any]]:
        reverse: list[dict[str, Any]] = []
        current = self.tip_hash
        while current:
            block = self.blocks[current]
            reverse.append(block)
            if block["height"] == 0:
                break
            current = block["previous_hash"]
        return list(reversed(reverse))

    def canonical_state(self) -> list[dict[str, Any]]:
        return _ordered_utxos(self.states[self.tip_hash])

    def accept_block(self, candidate: Mapping[str, Any], *, persist: bool = True) -> bool:
        block = dict(candidate)
        if set(block) != _GENESIS_FIELDS:
            raise V2SchemaError("block fields mismatch")
        parent_hash = block.get("previous_hash")
        parent = self.blocks.get(parent_hash)
        if parent is None:
            raise V2SchemaError("block parent is unknown")
        transaction_ids: list[str] = []
        state = self.states[parent_hash]
        branch_txids = self.branch_txids[parent_hash]
        for tx in block["transactions"] if isinstance(block["transactions"], list) else []:
            txid, owners = _validate_transaction_with_owners_v2(
                tx, chain_id=self.chain_id,
                kinds={"transfer": lambda metadata: None}, providers=self.providers,
                provider_modes=self.provider_modes, address_validator=self.address_validator,
            )
            if txid in branch_txids or txid in transaction_ids:
                raise V2SchemaError("transaction ID is already present on this branch")
            transaction_ids.append(txid)
            state = apply_transfer_v2(tx, tx_id=txid, input_owners=owners, utxos=state)
        state_total = sum(item["amount"] for item in state.values())
        if state_total > self.max_supply:
            raise V2SchemaError("post-block state exceeds the manifest max_supply")
        computed_root = validate_state_utxos_v2(
            _ordered_utxos(state), address_validator=self.address_validator,
        )
        if block.get("state_root") != computed_root:
            raise V2SchemaError("state_root does not match the block state transition")
        block_hash = validate_block_context_v2(
            block, parent=parent, chain_id=self.chain_id,
            transaction_ids=transaction_ids, difficulty_bits=self.difficulty_bits,
            max_timestamp_step_us=self.max_timestamp_step_us,
            address_validator=self.address_validator,
        )
        if block_hash in self.blocks:
            return False
        self.blocks[block_hash] = block
        self.states[block_hash] = state
        self.branch_txids[block_hash] = branch_txids.union(transaction_ids)
        self.work[block_hash] = self.work[parent_hash] + (1 << self.difficulty_bits)
        if self._wins_over_tip(block_hash):
            self.tip_hash = block_hash
        if persist:
            self._store_block(block)
        return True

    def _wins_over_tip(self, candidate_hash: str) -> bool:
        candidate_work, current_work = self.work[candidate_hash], self.work[self.tip_hash]
        return candidate_work > current_work or (
            candidate_work == current_work and candidate_hash < self.tip_hash
        )

    def sync_from(self, peer: Any) -> None:
        remote = peer.handshake()
        if remote != self.handshake():
            raise V2SchemaError("peer v2 handshake does not match configured network")
        remote_blocks = peer.canonical_blocks()
        if (not isinstance(remote_blocks, list) or not remote_blocks
                or not isinstance(remote_blocks[0], dict)
                or remote_blocks[0].get("block_hash") != self.genesis_hash):
            raise V2SchemaError("peer chain has a different genesis")
        for block in remote_blocks[1:]:
            self.accept_block(block)

