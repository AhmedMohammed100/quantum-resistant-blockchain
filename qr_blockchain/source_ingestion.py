from __future__ import annotations

import hashlib

from .legacy_networks import validate_legacy_source_binding
from .migration import get_classical_claim_verifier
from .snapshot import MigrationSnapshotBundle, MigrationSnapshotEntry, canonical_json, validate_snapshot_bundle


def _merkle_root(items: list[dict[str, object]], *, empty_message: str) -> str:
    leaf_hashes = [
        hashlib.sha256(canonical_json(item).encode("utf-8")).hexdigest()
        for item in sorted(items, key=lambda value: canonical_json(value))
    ]
    if not leaf_hashes:
        raise ValueError(empty_message)
    current = leaf_hashes
    while len(current) > 1:
        if len(current) % 2 == 1:
            current.append(current[-1])
        current = [
            hashlib.sha256(f"{current[index]}:{current[index + 1]}".encode("utf-8")).hexdigest()
            for index in range(0, len(current), 2)
        ]
    return current[0]


def normalize_source_export(payload: dict[str, object]) -> dict[str, object]:
    source_network = str(payload.get("source_network", ""))
    snapshot_ref = str(payload.get("snapshot_ref", ""))
    generated_at = float(payload.get("generated_at", 0.0))
    provider_id = str(payload.get("provider_id", ""))
    default_source_address_format = str(payload.get("source_address_format", ""))
    records = payload.get("records", payload.get("entries", []))
    if not source_network:
        raise ValueError("Source export source_network is required.")
    if not snapshot_ref:
        raise ValueError("Source export snapshot_ref is required.")
    if not provider_id:
        raise ValueError("Source export provider_id is required.")
    if not isinstance(records, list) or not records:
        raise ValueError("Source export must include at least one record.")

    verifier = get_classical_claim_verifier(provider_id)
    entries: list[MigrationSnapshotEntry] = []
    normalized_records: list[dict[str, object]] = []
    warnings: list[dict[str, object]] = []
    for index, record in enumerate(records):
        if not isinstance(record, dict):
            raise ValueError(f"Source export record {index} must be an object.")
        amount = int(record.get("amount", 0))
        if amount <= 0:
            raise ValueError(f"Source export record {index} amount must be positive.")

        public_key = record.get("classical_public_key")
        classical_address = str(record.get("classical_address", ""))
        if not classical_address:
            if public_key is None:
                raise ValueError(f"Source export record {index} needs classical_address or classical_public_key.")
            classical_address = verifier.address_from_public_key(public_key)

        source_address = str(record.get("source_address", classical_address))
        source_address_format = str(record.get("source_address_format", default_source_address_format))
        binding = validate_legacy_source_binding(
            source_network=source_network,
            provider_id=provider_id,
            classical_address=classical_address,
            source_address=source_address,
            source_address_format=source_address_format,
        )
        if public_key is not None and not verifier.verify_source_address_ownership(
            public_key,
            source_address=str(binding["source_address"]),
            source_address_format=str(binding["source_address_format"]),
            source_network=source_network,
        ):
            raise ValueError(f"Source export record {index} public key does not own source_address.")
        if public_key is None:
            warnings.append(
                {
                    "record_index": index,
                    "kind": "missing_public_key",
                    "message": "Record relies on a precomputed canonical classical_address.",
                }
            )

        entries.append(
            MigrationSnapshotEntry(
                classical_address=classical_address,
                provider_id=provider_id,
                amount=amount,
                source_address=str(binding["source_address"]),
                source_address_format=str(binding["source_address_format"]),
            )
        )
        normalized_records.append(
            {
                "classical_address": classical_address,
                "provider_id": provider_id,
                "amount": amount,
                "source_address": str(binding["source_address"]),
                "source_address_format": str(binding["source_address_format"]),
                "source_network": source_network,
                "source_height": int(record.get("source_height", 0)),
                "source_tx_id": str(record.get("source_tx_id", "")),
                "source_output_index": int(record.get("source_output_index", -1)),
            }
        )

    bundle = validate_snapshot_bundle(
        MigrationSnapshotBundle(
            source_network=source_network,
            snapshot_ref=snapshot_ref,
            generated_at=generated_at,
            entries=tuple(entries),
        )
    )
    manifest = {
        "ingestion_version": 1,
        "source_network": source_network,
        "snapshot_ref": snapshot_ref,
        "provider_id": provider_id,
        "generated_at": generated_at,
        "record_count": len(normalized_records),
        "total_amount": sum(int(record["amount"]) for record in normalized_records),
        "records_root": _merkle_root(normalized_records, empty_message="Source export must include records."),
        "source_export_hash": hashlib.sha256(
            canonical_json(
                {
                    "source_network": source_network,
                    "snapshot_ref": snapshot_ref,
                    "provider_id": provider_id,
                    "generated_at": generated_at,
                    "records": sorted(normalized_records, key=lambda item: canonical_json(item)),
                }
            ).encode("utf-8")
        ).hexdigest(),
        "snapshot_manifest_hash": bundle.manifest_hash,
        "snapshot_entries_root": bundle.entries_root(),
        "warnings": warnings,
    }
    manifest["ingestion_manifest_hash"] = hashlib.sha256(canonical_json(manifest).encode("utf-8")).hexdigest()
    return {
        "bundle": bundle,
        "ingestion_manifest": manifest,
        "normalized_records": normalized_records,
    }


def normalize_source_export_to_snapshot(payload: dict[str, object]) -> MigrationSnapshotBundle:
    return normalize_source_export(payload)["bundle"]  # type: ignore[return-value]


def normalize_source_export_batch(payloads: list[dict[str, object]]) -> dict[str, object]:
    if not payloads:
        raise ValueError("Source export batch must include at least one payload.")
    items: list[dict[str, object]] = []
    total_records = 0
    total_amount = 0
    for index, payload in enumerate(payloads):
        normalized = normalize_source_export(payload)
        bundle = normalized["bundle"]
        manifest = dict(normalized["ingestion_manifest"])
        total_records += int(manifest["record_count"])
        total_amount += int(manifest["total_amount"])
        items.append(
            {
                "index": index,
                "bundle": bundle.to_dict(),  # type: ignore[union-attr]
                "ingestion_manifest": manifest,
            }
        )
    batch_manifest = {
        "batch_version": 1,
        "item_count": len(items),
        "total_records": total_records,
        "total_amount": total_amount,
        "item_manifest_hashes": [
            str(item["ingestion_manifest"]["ingestion_manifest_hash"])
            for item in items
        ],
    }
    batch_manifest["batch_hash"] = hashlib.sha256(canonical_json(batch_manifest).encode("utf-8")).hexdigest()
    return {
        "batch_manifest": batch_manifest,
        "items": items,
    }


def build_source_ingestion_runbook(normalized_payload: dict[str, object]) -> dict[str, object]:
    bundle_payload = normalized_payload.get("bundle", normalized_payload)
    bundle = validate_snapshot_bundle(MigrationSnapshotBundle.from_dict(dict(bundle_payload)))
    manifest = dict(normalized_payload.get("ingestion_manifest", {}))
    return {
        "runbook_version": 1,
        "source_network": bundle.source_network,
        "snapshot_ref": bundle.snapshot_ref,
        "snapshot_manifest_hash": bundle.manifest_hash,
        "ingestion_manifest_hash": str(manifest.get("ingestion_manifest_hash", "")),
        "operator_steps": [
            "Verify source export provenance and generation command.",
            "Validate the normalized snapshot artifact.",
            "Reconcile the snapshot against local migration state.",
            "Review ingestion warnings and reconciliation conflicts.",
            "Sign the artifact only after operator approval.",
            "Import the signed artifact on trusted nodes.",
            "Generate a migration audit report after import.",
        ],
        "required_evidence": [
            "source_export_hash",
            "records_root",
            "snapshot_manifest_hash",
            "snapshot_entries_root",
            "operator_identity",
            "import_result",
            "post_import_audit_report",
        ],
    }


def validate_ingestion_manifest(normalized_payload: dict[str, object]) -> dict[str, object]:
    bundle_payload = normalized_payload.get("bundle", normalized_payload)
    bundle = validate_snapshot_bundle(MigrationSnapshotBundle.from_dict(dict(bundle_payload)))
    manifest = dict(normalized_payload.get("ingestion_manifest", {}))
    expected_manifest = {
        "ingestion_version": 1,
        "source_network": bundle.source_network,
        "snapshot_ref": bundle.snapshot_ref,
        "provider_id": "",
        "generated_at": bundle.generated_at,
        "record_count": len(bundle.entries),
        "total_amount": sum(entry.amount for entry in bundle.entries),
        "snapshot_manifest_hash": bundle.manifest_hash,
        "snapshot_entries_root": bundle.entries_root(),
    }
    checks = [
        {
            "name": "manifest_present",
            "passed": bool(manifest),
        },
        {
            "name": "snapshot_hash_matches",
            "passed": manifest.get("snapshot_manifest_hash") == expected_manifest["snapshot_manifest_hash"],
        },
        {
            "name": "entries_root_matches",
            "passed": manifest.get("snapshot_entries_root") == expected_manifest["snapshot_entries_root"],
        },
        {
            "name": "record_count_matches",
            "passed": int(manifest.get("record_count", -1)) == expected_manifest["record_count"],
        },
        {
            "name": "total_amount_matches",
            "passed": int(manifest.get("total_amount", -1)) == expected_manifest["total_amount"],
        },
    ]
    return {
        "valid": all(bool(item["passed"]) for item in checks),
        "checks": checks,
        "snapshot_ref": bundle.snapshot_ref,
        "snapshot_manifest_hash": bundle.manifest_hash,
        "ingestion_manifest_hash": str(manifest.get("ingestion_manifest_hash", "")),
    }


def build_ingestion_approval(normalized_payload: dict[str, object], *, operator: str, decision: str, reason: str) -> dict[str, object]:
    if decision not in {"approved", "rejected"}:
        raise ValueError("Ingestion approval decision must be approved or rejected.")
    if not operator:
        raise ValueError("Ingestion approval operator is required.")
    if not reason.strip():
        raise ValueError("Ingestion approval reason is required.")
    validation = validate_ingestion_manifest(normalized_payload)
    if not validation["valid"]:
        raise ValueError("Cannot approve an invalid ingestion manifest.")
    approval = {
        "approval_version": 1,
        "operator": operator,
        "decision": decision,
        "reason": reason.strip(),
        "snapshot_ref": validation["snapshot_ref"],
        "snapshot_manifest_hash": validation["snapshot_manifest_hash"],
        "ingestion_manifest_hash": validation["ingestion_manifest_hash"],
    }
    approval["approval_hash"] = hashlib.sha256(canonical_json(approval).encode("utf-8")).hexdigest()
    return approval


def validate_ingestion_approval(normalized_payload: dict[str, object], approval: dict[str, object]) -> dict[str, object]:
    validation = validate_ingestion_manifest(normalized_payload)
    checks = [
        {"name": "manifest_valid", "passed": bool(validation["valid"])},
        {"name": "decision_approved", "passed": approval.get("decision") == "approved"},
        {
            "name": "snapshot_manifest_hash_matches",
            "passed": approval.get("snapshot_manifest_hash") == validation["snapshot_manifest_hash"],
        },
        {
            "name": "ingestion_manifest_hash_matches",
            "passed": approval.get("ingestion_manifest_hash") == validation["ingestion_manifest_hash"],
        },
    ]
    unsigned = dict(approval)
    approval_hash = str(unsigned.pop("approval_hash", ""))
    checks.append(
        {
            "name": "approval_hash_matches",
            "passed": bool(approval_hash)
            and hashlib.sha256(canonical_json(unsigned).encode("utf-8")).hexdigest() == approval_hash,
        }
    )
    return {
        "accepted": all(bool(item["passed"]) for item in checks),
        "checks": checks,
    }
