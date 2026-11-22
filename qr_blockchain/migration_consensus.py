from __future__ import annotations

import hashlib
import json
import re
from typing import Any


PROFILE_SCHEMA = "qbc-migration-consensus-profile"
PROFILE_VERSION = 1
_HASH_PATTERN = re.compile(r"^[0-9a-f]{64}$")

_POLICY_FIELDS = {
    "allowed_providers",
    "claim_end_height",
    "claim_start_height",
    "conversion_denominator",
    "conversion_numerator",
    "conversion_policy",
    "dispute_window_blocks",
    "epoch_length_blocks",
    "epoch_mint_cap",
    "escrow_blocks",
    "migration_pool_cap",
    "per_address_cap",
}
_SNAPSHOT_FIELDS = {"entries_root", "manifest_hash", "snapshot_ref", "source_network"}
_PROFILE_FIELDS = {
    "activation_height",
    "chain_id",
    "policy",
    "profile_schema",
    "profile_version",
    "snapshots",
}


def canonical_json(value: object) -> str:
    """Return the deterministic JSON representation used by this profile."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _require_nonempty_string(value: object, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field} must be a non-empty string.")
    return value


def _require_nonnegative_integer(value: object, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ValueError(f"{field} must be a non-negative integer.")
    return value


def _validate_policy(policy: object) -> dict[str, object]:
    if not isinstance(policy, dict):
        raise ValueError("Migration consensus policy must be an object.")
    unknown = set(policy) - _POLICY_FIELDS
    missing = _POLICY_FIELDS - set(policy)
    if unknown or missing:
        raise ValueError(
            f"Migration consensus policy fields mismatch (missing={sorted(missing)}, unknown={sorted(unknown)})."
        )

    normalized: dict[str, object] = {}
    for name in (
        "claim_start_height",
        "conversion_numerator",
        "dispute_window_blocks",
        "epoch_length_blocks",
        "epoch_mint_cap",
        "escrow_blocks",
        "migration_pool_cap",
        "per_address_cap",
    ):
        normalized[name] = _require_nonnegative_integer(policy[name], name)

    end_height = policy["claim_end_height"]
    if end_height is not None:
        end_height = _require_nonnegative_integer(end_height, "claim_end_height")
    if end_height is not None and end_height < normalized["claim_start_height"]:
        raise ValueError("claim_end_height must be at or after claim_start_height.")
    normalized["claim_end_height"] = end_height

    denominator = _require_nonnegative_integer(policy["conversion_denominator"], "conversion_denominator")
    if denominator == 0:
        raise ValueError("conversion_denominator must be positive.")
    normalized["conversion_denominator"] = denominator
    normalized["conversion_policy"] = _require_nonempty_string(policy["conversion_policy"], "conversion_policy")

    providers = policy["allowed_providers"]
    if not isinstance(providers, list) or any(not isinstance(item, str) or not item.strip() for item in providers):
        raise ValueError("allowed_providers must be a list of non-empty strings.")
    if len(providers) != len(set(providers)):
        raise ValueError("allowed_providers must not contain duplicates.")
    normalized["allowed_providers"] = sorted(providers)

    return normalized


def _validate_snapshots(snapshots: object) -> list[dict[str, str]]:
    if not isinstance(snapshots, list) or not snapshots:
        raise ValueError("Migration consensus profile must pin at least one snapshot.")
    normalized: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for snapshot in snapshots:
        if not isinstance(snapshot, dict):
            raise ValueError("Snapshot commitment must be an object.")
        unknown = set(snapshot) - _SNAPSHOT_FIELDS
        missing = _SNAPSHOT_FIELDS - set(snapshot)
        if unknown or missing:
            raise ValueError(
                f"Snapshot commitment fields mismatch (missing={sorted(missing)}, unknown={sorted(unknown)})."
            )
        source_network = _require_nonempty_string(snapshot["source_network"], "source_network")
        snapshot_ref = _require_nonempty_string(snapshot["snapshot_ref"], "snapshot_ref")
        manifest_hash = _require_nonempty_string(snapshot["manifest_hash"], "manifest_hash")
        entries_root = _require_nonempty_string(snapshot["entries_root"], "entries_root")
        if not _HASH_PATTERN.fullmatch(manifest_hash) or not _HASH_PATTERN.fullmatch(entries_root):
            raise ValueError("Snapshot hashes must be 64 lowercase hexadecimal characters.")
        key = (source_network, snapshot_ref)
        if key in seen:
            raise ValueError("Migration consensus profile contains a duplicate snapshot.")
        seen.add(key)
        normalized.append(
            {
                "entries_root": entries_root,
                "manifest_hash": manifest_hash,
                "snapshot_ref": snapshot_ref,
                "source_network": source_network,
            }
        )
    return sorted(normalized, key=lambda item: (item["source_network"], item["snapshot_ref"]))


def validate_migration_consensus_profile(profile: object) -> dict[str, object]:
    """Validate and normalize the proposed v1 profile; never changes legacy consensus."""
    if not isinstance(profile, dict):
        raise ValueError("Migration consensus profile must be an object.")
    unknown = set(profile) - _PROFILE_FIELDS
    missing = _PROFILE_FIELDS - set(profile)
    if unknown or missing:
        raise ValueError(
            f"Migration consensus profile fields mismatch (missing={sorted(missing)}, unknown={sorted(unknown)})."
        )
    if profile["profile_schema"] != PROFILE_SCHEMA:
        raise ValueError("Unsupported migration consensus profile schema.")
    if profile["profile_version"] != PROFILE_VERSION or isinstance(profile["profile_version"], bool):
        raise ValueError("Unsupported migration consensus profile version.")

    return {
        "activation_height": _require_nonnegative_integer(profile["activation_height"], "activation_height"),
        "chain_id": _require_nonempty_string(profile["chain_id"], "chain_id"),
        "policy": _validate_policy(profile["policy"]),
        "profile_schema": PROFILE_SCHEMA,
        "profile_version": PROFILE_VERSION,
        "snapshots": _validate_snapshots(profile["snapshots"]),
    }


def migration_consensus_profile_hash(profile: object) -> str:
    normalized = validate_migration_consensus_profile(profile)
    return hashlib.sha256(canonical_json(normalized).encode("utf-8")).hexdigest()


def verify_migration_consensus_profile(
    profile: object,
    *,
    expected_chain_id: str,
    expected_profile_hash: str,
    local_snapshots: list[dict[str, str]],
) -> dict[str, object]:
    """Fail closed unless chain identity, pinned profile hash, and local roots agree."""
    normalized = validate_migration_consensus_profile(profile)
    if normalized["chain_id"] != expected_chain_id:
        raise ValueError("Migration consensus profile chain_id does not match this node.")
    actual_hash = hashlib.sha256(canonical_json(normalized).encode("utf-8")).hexdigest()
    if not _HASH_PATTERN.fullmatch(expected_profile_hash) or actual_hash != expected_profile_hash:
        raise ValueError("Migration consensus profile hash does not match the configured commitment.")
    local = _validate_snapshots(local_snapshots)
    if local != normalized["snapshots"]:
        raise ValueError("Local migration snapshots do not match the consensus profile commitments.")
    return normalized


def migration_consensus_profile_commitment(profile: object) -> dict[str, Any]:
    normalized = validate_migration_consensus_profile(profile)
    return {
        "profile_hash": hashlib.sha256(canonical_json(normalized).encode("utf-8")).hexdigest(),
        "profile": normalized,
    }
