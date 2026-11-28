#!/usr/bin/env python3
"""Independently verify a normalized QBC migration artifact using only stdlib."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import sys
from typing import Any


_SNAPSHOT_REF = re.compile(r"^[a-z0-9][a-z0-9._-]{0,95}$")
_HEX_256 = re.compile(r"^[0-9a-f]{64}$")


def _canonical(value: Any) -> str:
    # Matches the v0.1 migration-artifact JSON encoding. This script deliberately
    # does not import qr_blockchain or call NodeService.
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def _hash(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _object_hash(value: Any) -> str:
    return _hash(_canonical(value).encode("utf-8"))


def _merkle(items: list[dict[str, Any]]) -> str:
    leaves = [_object_hash(item) for item in sorted(items, key=_canonical)]
    if not leaves:
        raise ValueError("artifact must contain at least one record")
    while len(leaves) > 1:
        if len(leaves) % 2:
            leaves.append(leaves[-1])
        leaves = [
            _hash(f"{leaves[index]}:{leaves[index + 1]}".encode("ascii"))
            for index in range(0, len(leaves), 2)
        ]
    return leaves[0]


def _require_object(value: Any, name: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ValueError(f"{name} must be an object")
    return value


def _require_int(value: Any, name: str, *, minimum: int = 0) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        raise ValueError(f"{name} must be an integer >= {minimum}")
    return value


def _verify(artifact: dict[str, Any]) -> dict[str, Any]:
    bundle = _require_object(artifact.get("bundle"), "bundle")
    manifest = _require_object(artifact.get("ingestion_manifest"), "ingestion_manifest")
    provenance = _require_object(artifact.get("source_provenance"), "source_provenance")
    records_value = artifact.get("normalized_records")
    if not isinstance(records_value, list) or not records_value:
        raise ValueError("normalized_records must be a non-empty array")
    records = [_require_object(item, "normalized_records item") for item in records_value]

    source_network = bundle.get("source_network")
    snapshot_ref = bundle.get("snapshot_ref")
    generated_at = bundle.get("generated_at")
    if not isinstance(source_network, str) or not source_network:
        raise ValueError("bundle.source_network must be a non-empty string")
    if not isinstance(snapshot_ref, str) or not _SNAPSHOT_REF.fullmatch(snapshot_ref) or ".." in snapshot_ref:
        raise ValueError("bundle.snapshot_ref is invalid")
    if isinstance(generated_at, bool) or not isinstance(generated_at, (int, float)):
        raise ValueError("bundle.generated_at must be numeric")

    entries_value = bundle.get("entries")
    if not isinstance(entries_value, list) or not entries_value:
        raise ValueError("bundle.entries must be a non-empty array")
    entries = [_require_object(item, "bundle.entries item") for item in entries_value]
    normalized_entries = sorted(
        entries,
        key=lambda item: (str(item.get("classical_address", "")), str(item.get("provider_id", "")), item.get("amount", 0)),
    )
    seen_addresses: set[str] = set()
    total_amount = 0
    for index, entry in enumerate(normalized_entries):
        address = entry.get("classical_address")
        provider = entry.get("provider_id")
        amount = _require_int(entry.get("amount"), f"bundle.entries[{index}].amount", minimum=1)
        if not isinstance(address, str) or not address:
            raise ValueError(f"bundle.entries[{index}].classical_address must be a non-empty string")
        if not isinstance(provider, str) or not provider:
            raise ValueError(f"bundle.entries[{index}].provider_id must be a non-empty string")
        if address in seen_addresses:
            raise ValueError("bundle.entries contains duplicate classical addresses")
        seen_addresses.add(address)
        if entry.get("status", "active") not in {"active", "quarantined", "revoked"}:
            raise ValueError(f"bundle.entries[{index}].status is invalid")
        if entry.get("status", "active") != "active" and not str(entry.get("status_reason", "")).strip():
            raise ValueError(f"bundle.entries[{index}].status_reason is required for blocked entries")
        total_amount += amount

    entry_leaves = [_object_hash(entry) for entry in normalized_entries]
    while len(entry_leaves) > 1:
        if len(entry_leaves) % 2:
            entry_leaves.append(entry_leaves[-1])
        entry_leaves = [
            _hash(f"{entry_leaves[index]}:{entry_leaves[index + 1]}".encode("ascii"))
            for index in range(0, len(entry_leaves), 2)
        ]
    entries_root = entry_leaves[0]
    snapshot_payload = {
        "source_network": source_network,
        "snapshot_ref": snapshot_ref,
        "generated_at": generated_at,
        "entry_count": len(entries),
        "total_amount": total_amount,
        "entries_root": entries_root,
    }
    snapshot_hash = _object_hash(snapshot_payload)
    if bundle.get("entry_count") != len(entries) or bundle.get("total_amount") != total_amount:
        raise ValueError("bundle entry_count or total_amount does not match entries")
    if bundle.get("entries_root") != entries_root or bundle.get("manifest_hash") != snapshot_hash:
        raise ValueError("bundle entries_root or manifest_hash does not match entries")

    # Each source record carries provenance fields beyond the consensus snapshot
    # entry. Bind the consensus-relevant projection explicitly to the bundle.
    projected = []
    for index, record in enumerate(records):
        row = {
            "classical_address": record.get("classical_address"),
            "provider_id": record.get("provider_id"),
            "amount": record.get("amount"),
            "source_address": record.get("source_address"),
            "source_address_format": record.get("source_address_format"),
        }
        if record.get("source_network") != source_network:
            raise ValueError(f"normalized_records[{index}].source_network does not match bundle")
        if _require_int(row["amount"], f"normalized_records[{index}].amount", minimum=1) != row["amount"]:
            raise ValueError(f"normalized_records[{index}].amount is invalid")
        projected.append(row)
    expected_projection = [
        {
            "classical_address": entry.get("classical_address"),
            "provider_id": entry.get("provider_id"),
            "amount": entry.get("amount"),
            "source_address": entry.get("source_address", entry.get("classical_address", "")),
            "source_address_format": entry.get("source_address_format", ""),
        }
        for entry in entries
    ]
    if sorted(projected, key=_canonical) != sorted(expected_projection, key=_canonical):
        raise ValueError("normalized_records do not match the bundle entry projection")

    records_root = _merkle(records)
    source_hash_payload = {
        "source_network": source_network,
        "snapshot_ref": snapshot_ref,
        "provider_id": manifest.get("provider_id"),
        "generated_at": generated_at,
        "records": sorted(records, key=_canonical),
    }
    source_export_hash = _object_hash(source_hash_payload)
    expected_manifest_fields = {
        "ingestion_version": 1,
        "source_network": source_network,
        "snapshot_ref": snapshot_ref,
        "provider_id": manifest.get("provider_id"),
        "generated_at": generated_at,
        "record_count": len(entries),
        "total_amount": total_amount,
        "records_root": records_root,
        "source_export_hash": source_export_hash,
        "snapshot_manifest_hash": snapshot_hash,
        "snapshot_entries_root": entries_root,
    }
    for key, expected in expected_manifest_fields.items():
        if manifest.get(key) != expected:
            raise ValueError(f"ingestion_manifest.{key} does not match artifact contents")

    provenance_payload = dict(provenance)
    observed_provenance_hash = provenance_payload.pop("source_provenance_hash", None)
    if not isinstance(observed_provenance_hash, str) or not _HEX_256.fullmatch(observed_provenance_hash):
        raise ValueError("source_provenance.source_provenance_hash is invalid")
    if _object_hash(provenance_payload) != observed_provenance_hash:
        raise ValueError("source_provenance.source_provenance_hash does not match provenance")
    for key, expected in {
        "source_network": source_network,
        "snapshot_ref": snapshot_ref,
        "provider_id": manifest.get("provider_id"),
        "record_count": len(records),
        "records_root": records_root,
        "source_export_hash": source_export_hash,
    }.items():
        if provenance.get(key) != expected:
            raise ValueError(f"source_provenance.{key} does not match artifact contents")
    if manifest.get("source_provenance_hash") != observed_provenance_hash:
        raise ValueError("ingestion_manifest.source_provenance_hash does not match provenance")

    manifest_payload = dict(manifest)
    observed_manifest_hash = manifest_payload.pop("ingestion_manifest_hash", None)
    if not isinstance(observed_manifest_hash, str) or not _HEX_256.fullmatch(observed_manifest_hash):
        raise ValueError("ingestion_manifest.ingestion_manifest_hash is invalid")
    if _object_hash(manifest_payload) != observed_manifest_hash:
        raise ValueError("ingestion_manifest.ingestion_manifest_hash does not match manifest")
    return {
        "valid": True,
        "snapshot_ref": snapshot_ref,
        "snapshot_manifest_hash": snapshot_hash,
        "ingestion_manifest_hash": observed_manifest_hash,
        "record_count": len(records),
        "total_amount": total_amount,
        "verification_scope": "artifact integrity and internal consistency only; source-chain truth is not verified",
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", required=True, type=Path, help="normalized migration artifact JSON")
    args = parser.parse_args(argv)
    try:
        with args.input.open("r", encoding="utf-8") as source:
            artifact = json.load(source)
        result = _verify(_require_object(artifact, "artifact"))
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError, TypeError) as error:
        result = {"valid": False, "error": str(error)}
        print(json.dumps(result, sort_keys=True, indent=2))
        return 1
    print(json.dumps(result, sort_keys=True, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())

