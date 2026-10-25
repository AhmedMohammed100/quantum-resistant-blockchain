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
MAX_STATE_UTXOS = 100_000
_HEX64 = re.compile(r"[0-9a-f]{64}\Z")
_PROVIDER_ID = re.compile(r"[a-z0-9][a-z0-9_.-]{0,63}\Z")


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


def _validate_transaction_with_owners_v2(
    tx: Any, *, chain_id: str, kinds: Mapping[str, Callable[[dict[str, Any]], None]],
    providers: Mapping[str, Callable[[Any, Any, bytes], str]],
    provider_modes: Mapping[str, tuple[str, str | None]],
    address_validator: Callable[[str], bool],
    limits: Mapping[str, int] | None = None,
    provider_payload_limits: Mapping[str, tuple[int, int]] | None = None,
) -> tuple[str, list[str]]:
    """Validate a manifest-defined signed transaction and return recomputed tx_id.

    `kinds["transfer"]` validates transfer metadata. Provider callbacks receive
    the exact signature message and return the address derived from the verified
    public key. This function checks object-level rules; UTXO ownership and value
    conservation are applied by `apply_transfer_v2`.
    """
    fields = {"version", "chain_id", "kind", "timestamp_us", "fee", "inputs", "outputs", "metadata", "signature_scheme", "tx_id"}
    tx = _object(tx, fields, "transaction")
    if type(tx["version"]) is not int or tx["version"] != 2: raise V2SchemaError("version must be integer 2")
    if not isinstance(tx["chain_id"], str) or tx["chain_id"] != chain_id: raise V2SchemaError("chain_id does not match configured network")
    _string(tx["chain_id"], "chain_id", limit=64, ascii_only=True)
    kind = _string(tx["kind"], "kind")
    scheme = _string(tx["signature_scheme"], "signature_scheme", limit=64, ascii_only=True)
    if not _PROVIDER_ID.fullmatch(scheme): raise V2SchemaError("signature_scheme must be lowercase ASCII provider ID")
    if kind not in kinds: raise V2SchemaError("transaction kind is not registered by the manifest")
    if kind != "transfer": raise V2SchemaError("only the ordinary transfer schema is implemented")
    if scheme not in providers or scheme not in provider_modes:
        raise V2SchemaError("signature provider is not registered by the manifest")
    _integer(tx["timestamp_us"], "timestamp_us"); _integer(tx["fee"], "fee")
    limits = limits or {"max_transaction_bytes": MAX_TX_BYTES, "max_metadata_bytes": MAX_METADATA_BYTES, "max_inputs": 256, "max_outputs": 256}
    inputs, outputs = tx["inputs"], tx["outputs"]
    if not isinstance(inputs, list) or not 1 <= len(inputs) <= limits["max_inputs"]: raise V2SchemaError("transfer input count exceeds manifest limit")
    if not isinstance(outputs, list) or not 1 <= len(outputs) <= limits["max_outputs"]: raise V2SchemaError("transfer output count exceeds manifest limit")
    if tx["metadata"] != {}:
        raise V2SchemaError("transfer metadata must be an empty object in v2 schema 2")
    _object(tx["metadata"], set(), "transfer metadata")
    preimage = signature_preimage_v2(tx)
    mode, domain = provider_modes[scheme]
    message = signature_message_v2(preimage, mode=mode, domain=domain)
    seen: set[tuple[str, int]] = set()
    input_owners: list[str] = []
    for item in inputs:
        item = _object(item, {"prev_tx_id", "output_index", "public_key", "signature"}, "input")
        if provider_payload_limits is not None:
            max_key, max_signature = provider_payload_limits[scheme]
            _canonical_size(item["public_key"], max_key, "provider public key")
            _canonical_size(item["signature"], max_signature, "provider signature")
        outpoint = (_digest(item["prev_tx_id"], "prev_tx_id"), _integer(item["output_index"], "output_index"))
        if outpoint in seen: raise V2SchemaError("duplicate input outpoint")
        seen.add(outpoint)
        owner = providers[scheme](item["public_key"], item["signature"], message)
        owner = _string(owner, "provider-derived address", limit=256)
        if not address_validator(owner): raise V2SchemaError("provider-derived address is invalid")
        input_owners.append(owner)
    for item in outputs:
        item = _object(item, {"recipient", "amount"}, "output")
        recipient = _string(item["recipient"], "recipient", limit=256)
        if not address_validator(recipient): raise V2SchemaError("recipient address is invalid")
        _integer(item["amount"], "amount", minimum=1)
    _canonical_size(tx["metadata"], limits["max_metadata_bytes"], "metadata")
    kinds[kind](tx["metadata"])
    _canonical_size(tx, limits["max_transaction_bytes"], "signed transaction")
    preimage = {k: v for k, v in tx.items() if k != "tx_id"}
    tx_id = hash_canonical_v1("transaction-v2", preimage)
    if _digest(tx["tx_id"], "tx_id") != tx_id: raise V2SchemaError("tx_id does not match transaction preimage")
    return tx_id, input_owners


def validate_transaction_v2(
    tx: Any, *, chain_id: str, kinds: Mapping[str, Callable[[dict[str, Any]], None]],
    providers: Mapping[str, Callable[[Any, Any, bytes], str]],
    provider_modes: Mapping[str, tuple[str, str | None]],
    address_validator: Callable[[str], bool],
    limits: Mapping[str, int] | None = None,
    provider_payload_limits: Mapping[str, tuple[int, int]] | None = None,
) -> str:
    """Validate a complete v2 transfer and return its recomputed transaction ID."""
    tx_id, _ = _validate_transaction_with_owners_v2(
        tx, chain_id=chain_id, kinds=kinds, providers=providers,
        provider_modes=provider_modes, address_validator=address_validator,
        limits=limits, provider_payload_limits=provider_payload_limits,
    )
    return tx_id


def signature_preimage_v2(tx: Mapping[str, Any]) -> dict[str, Any]:
    """Return the exact v2 transaction-wide signature preimage projection."""
    return {
        "version": tx["version"],
        "chain_id": tx["chain_id"],
        "kind": tx["kind"],
        "timestamp_us": tx["timestamp_us"],
        "fee": tx["fee"],
        "inputs": [
            {"prev_tx_id": item["prev_tx_id"], "output_index": item["output_index"]}
            for item in tx["inputs"]
        ],
        "outputs": tx["outputs"],
        "metadata": tx["metadata"],
        "signature_scheme": tx["signature_scheme"],
    }


def signature_message_v2(
    preimage: Mapping[str, Any], *, mode: str, domain: str | None,
) -> bytes:
    """Build the provider message selected by its immutable manifest descriptor."""
    if mode == "canonical-bytes" and domain is None:
        return canonical_json_v1(dict(preimage))
    if mode == "provider-digest" and isinstance(domain, str):
        return bytes.fromhex(hash_canonical_v1(domain, dict(preimage)))
    raise V2SchemaError("invalid manifest signature mode/domain pairing")


def validate_transaction_with_owners_v2(
    tx: Any, *, chain_id: str, kinds: Mapping[str, Callable[[dict[str, Any]], None]],
    providers: Mapping[str, Callable[[Any, Any, bytes], str]],
    provider_modes: Mapping[str, tuple[str, str | None]],
    address_validator: Callable[[str], bool],
    limits: Mapping[str, int] | None = None,
    provider_payload_limits: Mapping[str, tuple[int, int]] | None = None,
) -> tuple[str, list[str]]:
    """Validate a signed transfer and return its ID plus verified input owners."""
    return _validate_transaction_with_owners_v2(
        tx, chain_id=chain_id, kinds=kinds, providers=providers,
        provider_modes=provider_modes, address_validator=address_validator,
        limits=limits, provider_payload_limits=provider_payload_limits,
    )


def apply_transfer_v2(
    tx: Mapping[str, Any], *, tx_id: str, input_owners: Sequence[str],
    utxos: Mapping[tuple[str, int], Mapping[str, Any]],
) -> dict[tuple[str, int], dict[str, Any]]:
    """Apply one validated transfer to a copy of UTXO state with no side effects."""
    if len(input_owners) != len(tx["inputs"]):
        raise V2SchemaError("verified input owner count does not match transaction")
    updated = {key: dict(value) for key, value in utxos.items()}
    input_total = 0
    outpoints: list[tuple[str, int]] = []
    for item, expected_owner in zip(tx["inputs"], input_owners, strict=True):
        outpoint = (item["prev_tx_id"], item["output_index"])
        coin = updated.get(outpoint)
        if coin is None:
            raise V2SchemaError("transfer input is missing or already spent")
        if coin["recipient"] != expected_owner:
            raise V2SchemaError("input signing address does not own the referenced UTXO")
        input_total += coin["amount"]
        if input_total > MAX_I64:
            raise V2SchemaError("transfer input sum overflows signed 64-bit range")
        outpoints.append(outpoint)
    output_total = 0
    for output in tx["outputs"]:
        output_total += output["amount"]
        if output_total > MAX_I64:
            raise V2SchemaError("transfer output sum overflows signed 64-bit range")
    required = output_total + tx["fee"]
    if required > MAX_I64 or input_total != required:
        raise V2SchemaError("transfer input value must equal outputs plus burned fee")
    for outpoint in outpoints:
        del updated[outpoint]
    for output_index, output in enumerate(tx["outputs"]):
        outpoint = (tx_id, output_index)
        if outpoint in updated:
            raise V2SchemaError("transaction would duplicate an existing UTXO outpoint")
        updated[outpoint] = {
            "tx_id": tx_id,
            "output_index": output_index,
            "recipient": output["recipient"],
            "amount": output["amount"],
        }
    return updated


def validate_state_utxos_v2(utxos: Any, *, address_validator: Callable[[str], bool]) -> str:
    if not isinstance(utxos, list): raise V2SchemaError("state-root preimage must be an array")
    if len(utxos) > MAX_STATE_UTXOS: raise V2SchemaError(f"state-root preimage exceeds {MAX_STATE_UTXOS} UTXOs")
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


def validate_block_context_v2(
    block: Any, *, parent: Mapping[str, Any], chain_id: str,
    transaction_ids: Sequence[str], difficulty_bits: int,
    max_timestamp_step_us: int, address_validator: Callable[[str], bool],
) -> str:
    """Validate a non-genesis block's linkage, fixed proof of work, and time rule."""
    if not 1 <= difficulty_bits <= 16:
        raise V2SchemaError("difficulty_bits must be in [1, 16]")
    if not 1 <= max_timestamp_step_us <= 120_000_000:
        raise V2SchemaError("max_timestamp_step_us must be in [1, 120000000]")
    block = _object(block, {"version", "chain_id", "height", "previous_hash", "timestamp_us", "difficulty", "nonce", "miner", "transactions", "state_root", "block_hash"}, "block")
    if block["height"] != parent["height"] + 1:
        raise V2SchemaError("block height must be parent height plus one")
    if block["previous_hash"] != parent["block_hash"]:
        raise V2SchemaError("previous_hash does not match parent block")
    if type(block["difficulty"]) is not int or block["difficulty"] != difficulty_bits:
        raise V2SchemaError("block difficulty does not match fixed network difficulty")
    if block["timestamp_us"] <= parent["timestamp_us"]:
        raise V2SchemaError("block timestamp must be greater than parent timestamp")
    if block["timestamp_us"] - parent["timestamp_us"] > max_timestamp_step_us:
        raise V2SchemaError("block timestamp exceeds the configured parent-time step")
    block_hash = validate_block_header_v2(
        block, chain_id=chain_id, transaction_ids=transaction_ids,
        address_validator=address_validator,
    )
    if int(block_hash, 16).bit_length() > 256 - difficulty_bits:
        raise V2SchemaError("block hash does not satisfy fixed proof of work")
    return block_hash
