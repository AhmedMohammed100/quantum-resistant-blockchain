from __future__ import annotations

from .legacy_networks import validate_legacy_source_binding
from .migration import get_classical_claim_verifier
from .snapshot import MigrationSnapshotBundle, MigrationSnapshotEntry, validate_snapshot_bundle


def normalize_source_export_to_snapshot(payload: dict[str, object]) -> MigrationSnapshotBundle:
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
                raise ValueError(
                    f"Source export record {index} needs classical_address or classical_public_key."
                )
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
        entries.append(
            MigrationSnapshotEntry(
                classical_address=classical_address,
                provider_id=provider_id,
                amount=amount,
                source_address=str(binding["source_address"]),
                source_address_format=str(binding["source_address_format"]),
            )
        )

    return validate_snapshot_bundle(
        MigrationSnapshotBundle(
            source_network=source_network,
            snapshot_ref=snapshot_ref,
            generated_at=generated_at,
            entries=tuple(entries),
        )
    )
