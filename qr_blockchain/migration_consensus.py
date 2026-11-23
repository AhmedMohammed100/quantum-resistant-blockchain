from __future__ import annotations

import hashlib
import json
import math
import re
from typing import Any

from .snapshot import MigrationSnapshotBundle, validate_snapshot_bundle


PROFILE_SCHEMA = "qbc-migration-consensus-profile"
PROFILE_VERSION = 2
_HASH_PATTERN = re.compile(r"^[0-9a-f]{64}$")

_POLICY_FIELDS = {
    "allowed_classical_providers",
    "allowed_signature_providers",
    "claim_end_height",
    "claim_start_height",
    "conversion_denominator",
    "conversion_numerator",
    "conversion_policy",
    "dispute_window_blocks",
    "dual_control_end_height",
    "dual_control_start_height",
    "epoch_length_blocks",
    "epoch_mint_cap",
    "escrow_blocks",
    "migration_pool_cap",
    "per_address_cap",
}
_SNAPSHOT_FIELDS = {
    "entries",
    "entries_root",
    "entry_count",
    "generated_at",
    "manifest_hash",
    "reviewed_at",
    "snapshot_ref",
    "source_network",
    "status",
    "status_reason",
    "total_amount",
}
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


def _require_nonnegative_number(value: object, field: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f"{field} must be a non-negative number.")
    number = float(value)
    if not math.isfinite(number) or number < 0:
        raise ValueError(f"{field} must be a finite non-negative number.")
    return number


def _normalize_string_set(value: object, field: str) -> list[str]:
    if not isinstance(value, list) or any(not isinstance(item, str) or not item.strip() for item in value):
        raise ValueError(f"{field} must be a list of non-empty strings.")
    if len(value) != len(set(value)):
        raise ValueError(f"{field} must not contain duplicates.")
    return sorted(value)


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
        "dual_control_end_height",
        "dual_control_start_height",
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
    normalized["allowed_classical_providers"] = _normalize_string_set(
        policy["allowed_classical_providers"], "allowed_classical_providers"
    )
    normalized["allowed_signature_providers"] = _normalize_string_set(
        policy["allowed_signature_providers"], "allowed_signature_providers"
    )
    return normalized


def _validate_snapshots(snapshots: object) -> list[dict[str, object]]:
    if not isinstance(snapshots, list) or not snapshots:
        raise ValueError("Migration consensus profile must pin at least one snapshot.")
    normalized: list[dict[str, object]] = []
    seen_snapshots: set[tuple[str, str]] = set()
    seen_addresses: set[str] = set()

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
        status = snapshot["status"]
        if status not in {"active", "quarantined", "revoked"}:
            raise ValueError("Snapshot status is invalid.")
        status_reason = snapshot["status_reason"]
        if not isinstance(status_reason, str):
            raise ValueError("Snapshot status_reason must be a string.")
        if status != "active" and not status_reason.strip():
            raise ValueError("Snapshot status_reason is required for blocked snapshots.")

        entries = snapshot["entries"]
        if not isinstance(entries, list):
            raise ValueError("Snapshot entries must be a list.")
        for entry in entries:
            if not isinstance(entry, dict):
                raise ValueError("Snapshot entry must be an object.")
            address = _require_nonempty_string(entry.get("classical_address"), "classical_address")
            if address in seen_addresses:
                raise ValueError("Migration consensus registry contains a duplicate classical address.")
            seen_addresses.add(address)

        bundle_payload = {
            "source_network": source_network,
            "snapshot_ref": snapshot_ref,
            "generated_at": _require_nonnegative_number(snapshot["generated_at"], "generated_at"),
            "manifest_hash": _require_nonempty_string(snapshot["manifest_hash"], "manifest_hash"),
            "entries_root": _require_nonempty_string(snapshot["entries_root"], "entries_root"),
            "entry_count": _require_nonnegative_integer(snapshot["entry_count"], "entry_count"),
            "total_amount": _require_nonnegative_integer(snapshot["total_amount"], "total_amount"),
            "entries": entries,
        }
        bundle = validate_snapshot_bundle(MigrationSnapshotBundle.from_dict(bundle_payload))
        finalized = bundle.to_dict()
        if (
            finalized["manifest_hash"] != snapshot["manifest_hash"]
            or finalized["entries_root"] != snapshot["entries_root"]
            or finalized["entry_count"] != snapshot["entry_count"]
            or finalized["total_amount"] != snapshot["total_amount"]
        ):
            raise ValueError("Snapshot manifest and registry contents do not match.")
        key = (source_network, snapshot_ref)
        if key in seen_snapshots:
            raise ValueError("Migration consensus profile contains a duplicate snapshot.")
        seen_snapshots.add(key)

        reviewed_at = _require_nonnegative_number(snapshot["reviewed_at"], "reviewed_at")
        normalized.append(
            {
                **finalized,
                "reviewed_at": reviewed_at,
                "source_network": source_network,
                "snapshot_ref": snapshot_ref,
                "status": status,
                "status_reason": status_reason,
            }
        )

    return sorted(normalized, key=lambda item: (str(item["source_network"]), str(item["snapshot_ref"])))


def validate_migration_consensus_profile(profile: object) -> dict[str, object]:
    """Validate and normalize a complete, versioned migration consensus artifact."""
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
) -> dict[str, object]:
    """Fail closed unless the complete artifact matches its pinned chain and digest."""
    normalized = validate_migration_consensus_profile(profile)
    if normalized["chain_id"] != expected_chain_id:
        raise ValueError("Migration consensus profile chain_id does not match this node.")
    if not _HASH_PATTERN.fullmatch(expected_profile_hash) or migration_consensus_profile_hash(normalized) != expected_profile_hash:
        raise ValueError("Migration consensus profile hash does not match the configured commitment.")
    return normalized


def migration_consensus_profile_commitment(profile: object) -> dict[str, Any]:
    normalized = validate_migration_consensus_profile(profile)
    return {
        "profile_hash": hashlib.sha256(canonical_json(normalized).encode("utf-8")).hexdigest(),
        "profile": normalized,
    }
