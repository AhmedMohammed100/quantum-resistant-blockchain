"""Opt-in QBC v2 test-network manifest validation.

The structural schema is fixed here. Consensus and provider profile callbacks
must validate the network-specific meanings of their declared parameters; this
module never selects or activates those rules.
"""

from __future__ import annotations

import copy
import re
from collections.abc import Callable, Mapping
from typing import Any

from .portable_encoding import hash_canonical_v1
from .protocol_v2 import MAX_BLOCK_BYTES, MAX_METADATA_BYTES, MAX_TX_BYTES, V2SchemaError, _digest, _integer, _object, _string

_TOKEN = re.compile(r"[a-z][a-z0-9_-]{0,63}\Z")
_PROVIDER_ID = re.compile(r"[a-z0-9][a-z0-9_.-]{0,63}\Z")
_VERSION = re.compile(r"[A-Za-z0-9][A-Za-z0-9.+_-]{0,63}\Z")
_MANIFEST_FIELDS = {
    "manifest_version", "chain_id", "genesis_hash", "encoding_profile",
    "transaction_schema_version", "block_schema_version", "activation",
    "transaction_kinds", "signature_providers", "consensus_profile", "limits",
    "manifest_digest",
}
_LIMIT_FIELDS = {
    "max_transaction_bytes", "max_block_bytes", "max_metadata_bytes",
    "max_inputs", "max_outputs", "max_transactions_per_block",
}


def v2_network_manifest_digest(manifest: Mapping[str, Any]) -> str:
    """Hash the complete manifest except its self-referential digest field."""
    body = dict(manifest)
    body.pop("manifest_digest", None)
    return hash_canonical_v1("network-manifest-v2", body)


def validate_v2_network_manifest(
    manifest: Any, *,
    expected_chain_id: str,
    expected_genesis_hash: str,
    supported_kinds: set[str],
    provider_profiles: Mapping[tuple[str, str], Callable[[dict[str, Any]], None]],
    consensus_profiles: Mapping[tuple[str, str], Callable[[dict[str, Any]], None]],
) -> str:
    """Validate a genesis-activated test-network manifest and return its digest.

    `supported_kinds`, `provider_profiles`, and `consensus_profiles` are local
    registries that give manifest descriptors their meaning. Each profile raises
    `V2SchemaError` (or another validation exception) when unsupported.
    """
    value = _object(manifest, _MANIFEST_FIELDS, "network manifest")
    if type(value["manifest_version"]) is not int or value["manifest_version"] != 1:
        raise V2SchemaError("manifest_version must be integer 1")
    if type(value["transaction_schema_version"]) is not int or value["transaction_schema_version"] != 2:
        raise V2SchemaError("transaction_schema_version must be integer 2")
    if type(value["block_schema_version"]) is not int or value["block_schema_version"] != 2:
        raise V2SchemaError("block_schema_version must be integer 2")
    chain_id = _string(value["chain_id"], "chain_id", limit=64, ascii_only=True)
    if chain_id != expected_chain_id:
        raise V2SchemaError("manifest chain_id does not match configured network")
    genesis_hash = _digest(value["genesis_hash"], "genesis_hash")
    if genesis_hash != expected_genesis_hash:
        raise V2SchemaError("manifest genesis_hash does not match configured network")
    if value["encoding_profile"] != "qbc-cjson-v1":
        raise V2SchemaError("encoding_profile must be qbc-cjson-v1")
    activation = _object(value["activation"], {"mode"}, "activation")
    if activation["mode"] != "genesis":
        raise V2SchemaError("the v2 test-network manifest must activate at genesis")

    kinds = value["transaction_kinds"]
    if not isinstance(kinds, list) or not kinds:
        raise V2SchemaError("transaction_kinds must be a non-empty array")
    normalized_kinds: list[str] = []
    for kind in kinds:
        token = _string(kind, "transaction kind", limit=64, ascii_only=True)
        if not _TOKEN.fullmatch(token):
            raise V2SchemaError("transaction kind must be a lowercase token")
        if token not in supported_kinds:
            raise V2SchemaError(f"transaction kind {token!r} has no local schema")
        normalized_kinds.append(token)
    if normalized_kinds != sorted(set(normalized_kinds)):
        raise V2SchemaError("transaction_kinds must be sorted and unique")
    if "transfer" not in normalized_kinds:
        raise V2SchemaError("transaction_kinds must include transfer")

    providers = value["signature_providers"]
    if not isinstance(providers, list) or not providers:
        raise V2SchemaError("signature_providers must be a non-empty array")
    provider_ids: list[str] = []
    provider_entries: list[dict[str, Any]] = []
    for entry in providers:
        base = {"provider_id", "provider_version", "signing_mode", "public_key_schema", "signature_schema", "max_public_key_bytes", "max_signature_bytes"}
        if not isinstance(entry, dict):
            raise V2SchemaError("signature provider descriptor must be an object")
        mode = entry.get("signing_mode")
        fields = base | ({"signing_domain"} if mode == "provider-digest" else set())
        entry = _object(entry, fields, "signature provider descriptor")
        provider_id = _string(entry["provider_id"], "provider_id", limit=64, ascii_only=True)
        provider_version = _string(entry["provider_version"], "provider_version", limit=64, ascii_only=True)
        if not _PROVIDER_ID.fullmatch(provider_id):
            raise V2SchemaError("provider_id must be a lowercase ASCII identifier")
        if not _VERSION.fullmatch(provider_version):
            raise V2SchemaError("provider_version must be an exact version token")
        if mode not in {"canonical-bytes", "provider-digest"}:
            raise V2SchemaError("signing_mode must be canonical-bytes or provider-digest")
        if mode == "provider-digest":
            domain = _string(entry["signing_domain"], "signing_domain", limit=64, ascii_only=True)
            if not _TOKEN.fullmatch(domain):
                raise V2SchemaError("signing_domain must be a lowercase token")
        for field in ("public_key_schema", "signature_schema"):
            schema_id = _string(entry[field], field, limit=64, ascii_only=True)
            if not _TOKEN.fullmatch(schema_id):
                raise V2SchemaError(f"{field} must be a lowercase token")
        _integer(entry["max_public_key_bytes"], "max_public_key_bytes", minimum=1)
        _integer(entry["max_signature_bytes"], "max_signature_bytes", minimum=1)
        key = (provider_id, provider_version)
        if key not in provider_profiles:
            raise V2SchemaError(f"signature provider profile {key!r} is not supported locally")
        provider_profiles[key](copy.deepcopy(entry))
        provider_ids.append(provider_id)
        provider_entries.append(entry)
    if provider_ids != sorted(set(provider_ids)):
        raise V2SchemaError("signature_providers must be sorted by provider_id and unique")

    profile = _object(value["consensus_profile"], {"profile_id", "profile_version", "parameters"}, "consensus_profile")
    profile_id = _string(profile["profile_id"], "consensus profile ID", limit=64, ascii_only=True)
    profile_version = _string(profile["profile_version"], "consensus profile version", limit=64, ascii_only=True)
    if not _TOKEN.fullmatch(profile_id) or not _VERSION.fullmatch(profile_version):
        raise V2SchemaError("consensus profile ID/version is malformed")
    parameters = profile["parameters"]
    if not isinstance(parameters, dict):
        raise V2SchemaError("consensus profile parameters must be an object")
    profile_key = (profile_id, profile_version)
    if profile_key not in consensus_profiles:
        raise V2SchemaError(f"consensus profile {profile_key!r} is not supported locally")
    consensus_profiles[profile_key](copy.deepcopy(parameters))

    limits = _object(value["limits"], _LIMIT_FIELDS, "v2 schema limits")
    ceilings = {
        "max_transaction_bytes": MAX_TX_BYTES,
        "max_block_bytes": MAX_BLOCK_BYTES,
        "max_metadata_bytes": MAX_METADATA_BYTES,
        "max_inputs": 256,
        "max_outputs": 256,
        "max_transactions_per_block": 4096,
    }
    for name, ceiling in ceilings.items():
        _integer(limits[name], name, minimum=1)
        if limits[name] > ceiling:
            raise V2SchemaError(f"{name} exceeds the normative v2 ceiling {ceiling}")
    if limits["max_metadata_bytes"] > limits["max_transaction_bytes"]:
        raise V2SchemaError("max_metadata_bytes cannot exceed max_transaction_bytes")
    if limits["max_transaction_bytes"] > limits["max_block_bytes"]:
        raise V2SchemaError("max_transaction_bytes cannot exceed max_block_bytes")
    for entry in provider_entries:
        for field in ("max_public_key_bytes", "max_signature_bytes"):
            if entry[field] > limits["max_transaction_bytes"]:
                raise V2SchemaError(f"{field} cannot exceed max_transaction_bytes")

    digest = v2_network_manifest_digest(value)
    if _digest(value["manifest_digest"], "manifest_digest") != digest:
        raise V2SchemaError("manifest_digest does not match canonical manifest")
    return digest
