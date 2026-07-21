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


def _canonical_source_export_hash(
    *,
    source_network: str,
    snapshot_ref: str,
    provider_id: str,
    generated_at: float,
    normalized_records: list[dict[str, object]],
) -> str:
    return hashlib.sha256(
        canonical_json(
            {
                "source_network": source_network,
                "snapshot_ref": snapshot_ref,
                "provider_id": provider_id,
                "generated_at": generated_at,
                "records": sorted(normalized_records, key=lambda item: canonical_json(item)),
            }
        ).encode("utf-8")
    ).hexdigest()


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
                    "classical_address": classical_address,
                    "source_address": str(binding["source_address"]),
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
    provenance = build_source_export_provenance(
        payload,
        source_network=source_network,
        snapshot_ref=snapshot_ref,
        provider_id=provider_id,
        normalized_records=normalized_records,
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
        "source_export_hash": _canonical_source_export_hash(
            source_network=source_network,
            snapshot_ref=snapshot_ref,
            provider_id=provider_id,
            generated_at=generated_at,
            normalized_records=normalized_records,
        ),
        "snapshot_manifest_hash": bundle.manifest_hash,
        "snapshot_entries_root": bundle.entries_root(),
        "source_provenance_hash": provenance["source_provenance_hash"],
        "warnings": sorted(warnings, key=lambda item: canonical_json(item)),
    }
    manifest["ingestion_manifest_hash"] = hashlib.sha256(canonical_json(manifest).encode("utf-8")).hexdigest()
    return {
        "bundle": bundle,
        "ingestion_manifest": manifest,
        "source_provenance": provenance,
        "normalized_records": normalized_records,
    }


def build_source_export_provenance(
    payload: dict[str, object],
    *,
    source_network: str,
    snapshot_ref: str,
    provider_id: str,
    normalized_records: list[dict[str, object]],
) -> dict[str, object]:
    extractor = dict(payload.get("extractor", {})) if isinstance(payload.get("extractor"), dict) else {}
    source_anchor = dict(payload.get("source_anchor", {})) if isinstance(payload.get("source_anchor"), dict) else {}
    records_root = _merkle_root(normalized_records, empty_message="Source export must include records.")
    provenance = {
        "provenance_version": 1,
        "source_network": source_network,
        "snapshot_ref": snapshot_ref,
        "provider_id": provider_id,
        "extractor": {
            "name": str(extractor.get("name", payload.get("extractor_name", ""))),
            "version": str(extractor.get("version", payload.get("extractor_version", ""))),
            "command": str(extractor.get("command", payload.get("extractor_command", ""))),
            "code_commit": str(extractor.get("code_commit", payload.get("extractor_code_commit", ""))),
        },
        "source_anchor": {
            "height": int(source_anchor.get("height", payload.get("source_height", 0))),
            "block_hash": str(source_anchor.get("block_hash", payload.get("source_block_hash", ""))),
            "exported_at": str(source_anchor.get("exported_at", payload.get("exported_at", ""))),
        },
        "record_count": len(normalized_records),
        "records_root": records_root,
    }
    provenance["source_export_hash"] = _canonical_source_export_hash(
        source_network=source_network,
        snapshot_ref=snapshot_ref,
        provider_id=provider_id,
        generated_at=float(payload.get("generated_at", 0.0)),
        normalized_records=normalized_records,
    )
    provenance["source_provenance_hash"] = hashlib.sha256(canonical_json(provenance).encode("utf-8")).hexdigest()
    return provenance


def normalize_source_export_to_snapshot(payload: dict[str, object]) -> MigrationSnapshotBundle:
    return normalize_source_export(payload)["bundle"]  # type: ignore[return-value]


def _batch_record_conflicts(items: list[dict[str, object]]) -> list[dict[str, object]]:
    conflicts: list[dict[str, object]] = []
    seen_classical_addresses: dict[str, tuple[int, int]] = {}
    seen_source_bindings: dict[tuple[str, str, str], tuple[int, int]] = {}
    for item_index, item in enumerate(items):
        normalized_records = item.get("normalized_records", [])
        if not isinstance(normalized_records, list):
            continue
        for record_index, record in enumerate(normalized_records):
            if not isinstance(record, dict):
                continue
            classical_address = str(record.get("classical_address", ""))
            if classical_address:
                if classical_address in seen_classical_addresses:
                    first_item, first_record = seen_classical_addresses[classical_address]
                    conflicts.append(
                        {
                            "kind": "duplicate_classical_address",
                            "classical_address": classical_address,
                            "first_item_index": first_item,
                            "first_record_index": first_record,
                            "second_item_index": item_index,
                            "second_record_index": record_index,
                        }
                    )
                else:
                    seen_classical_addresses[classical_address] = (item_index, record_index)

            source_network = str(record.get("source_network", ""))
            source_address = str(record.get("source_address", ""))
            source_address_format = str(record.get("source_address_format", ""))
            if source_network and source_address and source_address_format:
                source_key = (source_network, source_address, source_address_format)
                if source_key in seen_source_bindings:
                    first_item, first_record = seen_source_bindings[source_key]
                    conflicts.append(
                        {
                            "kind": "duplicate_source_binding",
                            "source_network": source_network,
                            "source_address": source_address,
                            "source_address_format": source_address_format,
                            "first_item_index": first_item,
                            "first_record_index": first_record,
                            "second_item_index": item_index,
                            "second_record_index": record_index,
                        }
                    )
                else:
                    seen_source_bindings[source_key] = (item_index, record_index)
    return conflicts


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
                "source_provenance": normalized["source_provenance"],
                "normalized_records": normalized["normalized_records"],
            }
        )
        conflicts = _batch_record_conflicts(items)
        if conflicts:
            conflict = conflicts[0]
            if conflict["kind"] == "duplicate_classical_address":
                raise ValueError(
                    "Source export batch contains duplicate classical_address "
                    f"'{conflict['classical_address']}' in items "
                    f"{conflict['first_item_index']} and {conflict['second_item_index']}."
                )
            raise ValueError(
                "Source export batch contains duplicate source binding "
                f"'{conflict['source_network']}:{conflict['source_address_format']}:{conflict['source_address']}' "
                f"in items {conflict['first_item_index']} and {conflict['second_item_index']}."
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
    normalized_records = [
        dict(item)
        for item in normalized_payload.get("normalized_records", [])
        if isinstance(item, dict)
    ]
    source_provenance = (
        dict(normalized_payload.get("source_provenance", {}))
        if isinstance(normalized_payload.get("source_provenance"), dict)
        else {}
    )
    manifest_without_hash = dict(manifest)
    observed_manifest_hash = str(manifest_without_hash.pop("ingestion_manifest_hash", ""))
    recomputed_manifest_hash = hashlib.sha256(canonical_json(manifest_without_hash).encode("utf-8")).hexdigest()
    recomputed_records_root = (
        _merkle_root(normalized_records, empty_message="Source export must include records.")
        if normalized_records
        else ""
    )
    recomputed_source_export_hash = (
        _canonical_source_export_hash(
            source_network=bundle.source_network,
            snapshot_ref=bundle.snapshot_ref,
            provider_id=str(manifest.get("provider_id", "")),
            generated_at=bundle.generated_at,
            normalized_records=normalized_records,
        )
        if normalized_records
        else ""
    )
    provenance_without_hash = dict(source_provenance)
    observed_provenance_hash = str(provenance_without_hash.pop("source_provenance_hash", ""))
    recomputed_provenance_hash = (
        hashlib.sha256(canonical_json(provenance_without_hash).encode("utf-8")).hexdigest()
        if provenance_without_hash
        else ""
    )
    expected_manifest = {
        "ingestion_version": 1,
        "source_network": bundle.source_network,
        "snapshot_ref": bundle.snapshot_ref,
        "provider_id": str(manifest.get("provider_id", "")),
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
            "name": "source_network_matches",
            "passed": manifest.get("source_network") == expected_manifest["source_network"],
        },
        {
            "name": "snapshot_ref_matches",
            "passed": manifest.get("snapshot_ref") == expected_manifest["snapshot_ref"],
        },
        {
            "name": "generated_at_matches",
            "passed": float(manifest.get("generated_at", -1)) == expected_manifest["generated_at"],
        },
        {
            "name": "record_count_matches",
            "passed": int(manifest.get("record_count", -1)) == expected_manifest["record_count"],
        },
        {
            "name": "total_amount_matches",
            "passed": int(manifest.get("total_amount", -1)) == expected_manifest["total_amount"],
        },
        {
            "name": "normalized_records_present",
            "passed": bool(normalized_records),
        },
        {
            "name": "records_root_matches_normalized_records",
            "passed": bool(recomputed_records_root) and manifest.get("records_root") == recomputed_records_root,
        },
        {
            "name": "source_export_hash_matches_normalized_records",
            "passed": bool(recomputed_source_export_hash)
            and manifest.get("source_export_hash") == recomputed_source_export_hash,
        },
        {
            "name": "source_provenance_hash_matches",
            "passed": bool(recomputed_provenance_hash)
            and observed_provenance_hash == recomputed_provenance_hash
            and manifest.get("source_provenance_hash") == observed_provenance_hash,
        },
        {
            "name": "ingestion_manifest_hash_matches",
            "passed": bool(observed_manifest_hash) and observed_manifest_hash == recomputed_manifest_hash,
        },
    ]
    return {
        "valid": all(bool(item["passed"]) for item in checks),
        "checks": checks,
        "snapshot_ref": bundle.snapshot_ref,
        "snapshot_manifest_hash": bundle.manifest_hash,
        "ingestion_manifest_hash": observed_manifest_hash,
    }


def validate_source_export_batch(normalized_batch: dict[str, object]) -> dict[str, object]:
    batch_manifest = (
        dict(normalized_batch.get("batch_manifest", {}))
        if isinstance(normalized_batch.get("batch_manifest"), dict)
        else {}
    )
    items = [
        dict(item)
        for item in normalized_batch.get("items", [])
        if isinstance(item, dict)
    ]
    item_statuses = [validate_ingestion_manifest(item) for item in items]
    item_manifest_hashes = [
        str(dict(item.get("ingestion_manifest", {})).get("ingestion_manifest_hash", ""))
        for item in items
    ]
    expected_manifest = {
        "batch_version": 1,
        "item_count": len(items),
        "total_records": sum(
            int(dict(item.get("ingestion_manifest", {})).get("record_count", 0))
            for item in items
        ),
        "total_amount": sum(
            int(dict(item.get("ingestion_manifest", {})).get("total_amount", 0))
            for item in items
        ),
        "item_manifest_hashes": item_manifest_hashes,
    }
    observed_manifest_without_hash = dict(batch_manifest)
    observed_batch_hash = str(observed_manifest_without_hash.pop("batch_hash", ""))
    recomputed_observed_batch_hash = hashlib.sha256(
        canonical_json(observed_manifest_without_hash).encode("utf-8")
    ).hexdigest()
    expected_batch_hash = hashlib.sha256(canonical_json(expected_manifest).encode("utf-8")).hexdigest()
    conflicts = _batch_record_conflicts(items)
    checks = [
        {"name": "batch_manifest_present", "passed": bool(batch_manifest)},
        {"name": "items_present", "passed": bool(items)},
        {
            "name": "all_item_manifests_valid",
            "passed": bool(items) and all(bool(status["valid"]) for status in item_statuses),
        },
        {"name": "batch_version_matches", "passed": batch_manifest.get("batch_version") == 1},
        {"name": "item_count_matches", "passed": batch_manifest.get("item_count") == expected_manifest["item_count"]},
        {
            "name": "total_records_matches",
            "passed": batch_manifest.get("total_records") == expected_manifest["total_records"],
        },
        {
            "name": "total_amount_matches",
            "passed": batch_manifest.get("total_amount") == expected_manifest["total_amount"],
        },
        {
            "name": "item_manifest_hashes_match",
            "passed": batch_manifest.get("item_manifest_hashes") == expected_manifest["item_manifest_hashes"],
        },
        {"name": "batch_hash_matches", "passed": observed_batch_hash == recomputed_observed_batch_hash},
        {"name": "no_duplicate_batch_records", "passed": not conflicts},
    ]
    return {
        "valid": all(bool(item["passed"]) for item in checks),
        "checks": checks,
        "item_statuses": item_statuses,
        "record_conflicts": conflicts,
        "batch_hash": observed_batch_hash,
        "expected_batch_hash": expected_batch_hash,
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
