"""Opt-in structural validators for the QBC v2 candidate schemas.

These helpers are deliberately separate from the v0.1 consensus path. Network
specific kinds, metadata, address rules, and provider payloads must be supplied
by a manifest; this module does not guess those rules.
"""

from __future__ import annotations

import json
import re
from collections.abc import Callable, Mapping, Sequence
from typing import Any

from .portable_encoding import canonical_json_v1, hash_canonical_v1

MAX_I64 = (1 << 63) - 1
MAX_TX_BYTES = 1 << 20
MAX_BLOCK_BYTES = 4 << 20
MAX_METADATA_BYTES = 16 << 10
_HEX64 = re.compile(r"[0-9a-f]{64}\Z")
_PROVIDER_ID = re.compile(r"[a-z0-9]{1,64}\Z")


class V2SchemaError(ValueError):
    """A v2 object violates its explicit schema or manifest rules."""


def _object(value: Any, fields: set[str], name: str) -> dict[str, Any]:
    if not isinstance(value, dict) or any(not isinstance(k, str) for k in value):
        raise V2SchemaError(f"{name} must be an object")
    if set(value) != fields:
        missing, unknown = fields - set(value), set(value) - fields
        raise V2SchemaError(f"{name} fields mismatch (missing={sorted(missing)}, unknown={sorted(unknown)})")
    return value


def _integer(value: Any, name: str, *, minimum: int = 0) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= MAX_I64:
        raise V2SchemaError(f"{name} must be an integer in [{minimum}, {MAX_I64}]")
    return value


def _string(value: Any, name: str, *, limit: int | None = None, ascii_only: bool = False) -> str:
    if not isinstance(value, str) or not value:
        raise V2SchemaError(f"{name} must be a non-empty string")
    encoded = value.encode("utf-8")
    if limit is not None and len(encoded) > limit:
        raise V2SchemaError(f"{name} exceeds {limit} UTF-8 bytes")
    if ascii_only and not value.isascii():
        raise V2SchemaError(f"{name} must contain ASCII only")
    return value


def _digest(value: Any, name: str) -> str:
    if not isinstance(value, str) or not _HEX64.fullmatch(value):
        raise V2SchemaError(f"{name} must be 64 lowercase hexadecimal characters")
    return value


def _canonical_size(value: Any, maximum: int, name: str) -> None:
    try:
        encoded = canonical_json_v1(value)
    except (TypeError, ValueError, OverflowError) as exc:
        raise V2SchemaError(f"{name} is not QBC-CJSON-V1 encodable: {exc}") from exc
    if len(encoded) > maximum:
        raise V2SchemaError(f"{name} exceeds {maximum} canonical bytes")


def parse_canonical_v2(data: bytes, *, maximum: int) -> Any:
    """Parse strict UTF-8 JSON, rejecting duplicate keys and noncanonical bytes."""
    if not isinstance(data, bytes) or len(data) > maximum:
        raise V2SchemaError(f"encoded object exceeds {maximum} bytes")
    def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in items:
            if key in result:
                raise V2SchemaError(f"duplicate object key: {key}")
            result[key] = value
        return result
    def reject_constant(value: str) -> None:
        raise V2SchemaError(f"unsupported JSON constant: {value}")
    try:
        value = json.loads(data.decode("utf-8", "strict"), object_pairs_hook=pairs,
                           parse_float=lambda _: (_ for _ in ()).throw(V2SchemaError("floats are forbidden")),
                           parse_constant=reject_constant)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise V2SchemaError("invalid UTF-8 JSON") from exc
    def check_ints(node: Any) -> None:
        if isinstance(node, bool) or node is None or isinstance(node, str):
            return
        if isinstance(node, int):
            if not -(1 << 63) <= node <= MAX_I64:
                raise V2SchemaError("integer is outside signed 64-bit range")
        elif isinstance(node, list):
            for child in node: check_ints(child)
        elif isinstance(node, dict):
            for child in node.values(): check_ints(child)
    check_ints(value)
    if canonical_json_v1(value) != data:
        raise V2SchemaError("JSON bytes are not canonical QBC-CJSON-V1")
    return value


def validate_transaction_v2(
    tx: Any, *, chain_id: str, kinds: Mapping[str, Callable[[dict[str, Any]], None]],
    providers: Mapping[str, Callable[[Any, Any], None]],
    address_validator: Callable[[str], bool],
) -> str:
    """Validate a manifest-defined signed transaction and return recomputed tx_id.

    `kinds[kind]` validates kind-specific metadata and semantics. Provider
    callbacks validate each (public_key, signature) payload pair. No signature
    cryptography or live consensus operation is performed here.
    """
    fields = {"version", "chain_id", "kind", "timestamp_us", "fee", "inputs", "outputs", "metadata", "signature_scheme", "tx_id"}
    tx = _object(tx, fields, "transaction")
    if type(tx["version"]) is not int or tx["version"] != 2: raise V2SchemaError("version must be integer 2")
    if tx["chain_id"] != chain_id: raise V2SchemaError("chain_id does not match configured network")
    _string(tx["chain_id"], "chain_id", limit=64, ascii_only=True)
    kind = _string(tx["kind"], "kind")
    if not isinstance(tx["signature_scheme"], str): raise V2SchemaError("signature_scheme must be a string")
    if kind not in kinds: raise V2SchemaError("transaction kind is not registered by the manifest")
    _integer(tx["timestamp_us"], "timestamp_us"); _integer(tx["fee"], "fee")
    inputs, outputs = tx["inputs"], tx["outputs"]
    if not isinstance(inputs, list) or not 1 <= len(inputs) <= 256: raise V2SchemaError("transfer inputs must contain 1–256 entries")
    if not isinstance(outputs, list) or not 1 <= len(outputs) <= 256: raise V2SchemaError("outputs must contain 1–256 entries")
    seen: set[tuple[str, int]] = set()
    for item in inputs:
        item = _object(item, {"prev_tx_id", "output_index", "public_key", "signature"}, "input")
        outpoint = (_digest(item["prev_tx_id"], "prev_tx_id"), _integer(item["output_index"], "output_index"))
        if outpoint in seen: raise V2SchemaError("duplicate input outpoint")
        seen.add(outpoint)
        provider = tx["signature_scheme"]
        if provider not in providers: raise V2SchemaError("signature provider is not registered by the manifest")
        providers[provider](item["public_key"], item["signature"])
    for item in outputs:
        item = _object(item, {"recipient", "amount"}, "output")
        recipient = _string(item["recipient"], "recipient", limit=256)
        if not address_validator(recipient): raise V2SchemaError("recipient address is invalid")
        _integer(item["amount"], "amount", minimum=1)
    metadata = _object(tx["metadata"], set(tx["metadata"]) if isinstance(tx["metadata"], dict) else set(), "metadata")
    _canonical_size(metadata, MAX_METADATA_BYTES, "metadata")
    scheme = _string(tx["signature_scheme"], "signature_scheme", limit=64, ascii_only=True)
    if not _PROVIDER_ID.fullmatch(scheme): raise V2SchemaError("signature_scheme must be lowercase ASCII provider ID")
    kinds[kind](metadata)
    _canonical_size(tx, MAX_TX_BYTES, "signed transaction")
    preimage = {k: v for k, v in tx.items() if k != "tx_id"}
    tx_id = hash_canonical_v1("transaction-v2", preimage)
    if _digest(tx["tx_id"], "tx_id") != tx_id: raise V2SchemaError("tx_id does not match transaction preimage")
    return tx_id


def validate_state_utxos_v2(utxos: Any, *, address_validator: Callable[[str], bool]) -> str:
    if not isinstance(utxos, list): raise V2SchemaError("state-root preimage must be an array")
    seen: set[tuple[str, int]] = set(); previous: tuple[str, int] | None = None
    for item in utxos:
        item = _object(item, {"tx_id", "output_index", "recipient", "amount"}, "UTXO")
        key = (_digest(item["tx_id"], "tx_id"), _integer(item["output_index"], "output_index"))
        if previous is not None and key <= previous: raise V2SchemaError("UTXOs must be sorted by tx_id bytes then numeric output_index")
        if key in seen: raise V2SchemaError("duplicate UTXO outpoint")
        previous = key; seen.add(key)
        recipient = _string(item["recipient"], "recipient", limit=256)
        if not address_validator(recipient): raise V2SchemaError("UTXO address is invalid")
        _integer(item["amount"], "amount", minimum=1)
    return hash_canonical_v1("state-root-v2", utxos)


def validate_block_header_v2(
    block: Any, *, chain_id: str, transaction_ids: Sequence[str],
    address_validator: Callable[[str], bool],
) -> str:
    """Validate block fields after validating its complete transactions.

    `transaction_ids` must be the corresponding recomputed IDs from strict
    transaction validation. The wire block retains transaction objects; only
    the block-hash preimage replaces them with the ordered ID strings.
    """
    fields = {"version", "chain_id", "height", "previous_hash", "timestamp_us", "difficulty", "nonce", "miner", "transactions", "state_root", "block_hash"}
    block = _object(block, fields, "block")
    if type(block["version"]) is not int or block["version"] != 2: raise V2SchemaError("version must be integer 2")
    if block["chain_id"] != chain_id: raise V2SchemaError("chain_id does not match configured network")
    _string(block["chain_id"], "chain_id", limit=64, ascii_only=True)
    _integer(block["height"], "height"); _digest(block["previous_hash"], "previous_hash")
    _integer(block["timestamp_us"], "timestamp_us"); _integer(block["difficulty"], "difficulty", minimum=1); _integer(block["nonce"], "nonce")
    miner = _string(block["miner"], "miner", limit=256)
    if not address_validator(miner): raise V2SchemaError("miner address is invalid for this network")
    _digest(block["state_root"], "state_root")
    if not isinstance(block["transactions"], list) or len(block["transactions"]) > 4096: raise V2SchemaError("block must contain at most 4096 transactions")
    _canonical_size(block, MAX_BLOCK_BYTES, "block")
    ids = [_digest(x, "transaction ID") for x in transaction_ids]
    if len(block["transactions"]) != len(ids): raise V2SchemaError("validated transaction count does not match block")
    preimage = {k: v for k, v in block.items() if k != "block_hash"}
    preimage["transactions"] = ids
    _canonical_size(preimage, MAX_BLOCK_BYTES, "block preimage")
    result = hash_canonical_v1("block-v2", preimage)
    if _digest(block["block_hash"], "block_hash") != result: raise V2SchemaError("block_hash does not match preimage")
    return result
