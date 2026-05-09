from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import time


def canonical_json(data: object) -> str:
    return json.dumps(data, sort_keys=True, separators=(",", ":"))


@dataclass(frozen=True)
class MigrationSnapshotEntry:
    classical_address: str
    provider_id: str
    amount: int
    source_address: str = ""
    source_address_format: str = ""
    status: str = "active"
    status_reason: str = ""
    reviewed_at: float = 0.0

    def to_dict(self) -> dict[str, object]:
        payload = {
            "classical_address": self.classical_address,
            "provider_id": self.provider_id,
            "amount": self.amount,
            "source_address": self.source_address or self.classical_address,
            "source_address_format": self.source_address_format,
        }
        if self.status != "active" or self.status_reason or self.reviewed_at:
            payload["status"] = self.status
            if self.status_reason:
                payload["status_reason"] = self.status_reason
            if self.reviewed_at:
                payload["reviewed_at"] = self.reviewed_at
        return payload

    @staticmethod
    def from_dict(data: dict[str, object]) -> "MigrationSnapshotEntry":
        return MigrationSnapshotEntry(
            classical_address=str(data["classical_address"]),
            provider_id=str(data["provider_id"]),
            amount=int(data["amount"]),
            source_address=str(data.get("source_address", data.get("classical_address", ""))),
            source_address_format=str(data.get("source_address_format", "")),
            status=str(data.get("status", "active")),
            status_reason=str(data.get("status_reason", "")),
            reviewed_at=float(data.get("reviewed_at", 0.0)),
        )


@dataclass(frozen=True)
class MigrationSnapshotBundle:
    source_network: str
    snapshot_ref: str
    generated_at: float
    entries: tuple[MigrationSnapshotEntry, ...]
    manifest_hash: str = ""

    def normalized_entries(self) -> tuple[MigrationSnapshotEntry, ...]:
        return tuple(
            sorted(
                self.entries,
                key=lambda item: (item.classical_address, item.provider_id, item.amount),
            )
        )

    def entries_root(self) -> str:
        leaf_hashes = [
            hashlib.sha256(canonical_json(entry.to_dict()).encode("utf-8")).hexdigest()
            for entry in self.normalized_entries()
        ]
        if not leaf_hashes:
            raise ValueError("Migration snapshot must contain at least one entry.")
        current = leaf_hashes
        while len(current) > 1:
            if len(current) % 2 == 1:
                current.append(current[-1])
            current = [
                hashlib.sha256(f"{current[index]}:{current[index + 1]}".encode("utf-8")).hexdigest()
                for index in range(0, len(current), 2)
            ]
        return current[0]

    def compute_manifest_hash(self) -> str:
        manifest = {
            "source_network": self.source_network,
            "snapshot_ref": self.snapshot_ref,
            "generated_at": self.generated_at,
            "entry_count": len(self.entries),
            "total_amount": sum(entry.amount for entry in self.entries),
            "entries_root": self.entries_root(),
        }
        return hashlib.sha256(canonical_json(manifest).encode("utf-8")).hexdigest()

    def finalized(self) -> "MigrationSnapshotBundle":
        return MigrationSnapshotBundle(
            source_network=self.source_network,
            snapshot_ref=self.snapshot_ref,
            generated_at=self.generated_at,
            entries=self.normalized_entries(),
            manifest_hash=self.compute_manifest_hash(),
        )

    def to_dict(self) -> dict[str, object]:
        finalized = self.finalized()
        return {
            "source_network": finalized.source_network,
            "snapshot_ref": finalized.snapshot_ref,
            "generated_at": finalized.generated_at,
            "manifest_hash": finalized.manifest_hash,
            "entries_root": finalized.entries_root(),
            "entry_count": len(finalized.entries),
            "total_amount": sum(entry.amount for entry in finalized.entries),
            "entries": [entry.to_dict() for entry in finalized.entries],
        }

    @staticmethod
    def from_dict(data: dict[str, object]) -> "MigrationSnapshotBundle":
        entries = tuple(
            MigrationSnapshotEntry.from_dict(item)
            for item in data.get("entries", [])
        )
        bundle = MigrationSnapshotBundle(
            source_network=str(data["source_network"]),
            snapshot_ref=str(data["snapshot_ref"]),
            generated_at=float(data.get("generated_at", round(time.time(), 6))),
            entries=entries,
            manifest_hash=str(data.get("manifest_hash", "")),
        )
        return bundle


def snapshot_manifest_claims(bundle: MigrationSnapshotBundle) -> dict[str, object]:
    finalized = validate_snapshot_bundle(bundle)
    return {
        "source_network": finalized.source_network,
        "snapshot_ref": finalized.snapshot_ref,
        "generated_at": finalized.generated_at,
        "manifest_hash": finalized.manifest_hash,
        "entries_root": finalized.entries_root(),
        "entry_count": len(finalized.entries),
        "total_amount": sum(entry.amount for entry in finalized.entries),
    }


def validate_snapshot_bundle(bundle: MigrationSnapshotBundle) -> MigrationSnapshotBundle:
    if not bundle.source_network:
        raise ValueError("Migration snapshot source_network is required.")
    if not bundle.snapshot_ref:
        raise ValueError("Migration snapshot snapshot_ref is required.")
    if not bundle.entries:
        raise ValueError("Migration snapshot must contain at least one entry.")

    seen_addresses: set[str] = set()
    for entry in bundle.entries:
        if not entry.classical_address:
            raise ValueError("Migration snapshot entry is missing classical_address.")
        if not entry.provider_id:
            raise ValueError("Migration snapshot entry is missing provider_id.")
        if entry.amount <= 0:
            raise ValueError("Migration snapshot entry amount must be positive.")
        if entry.status not in {"active", "quarantined", "revoked"}:
            raise ValueError("Migration snapshot entry status is invalid.")
        if entry.status != "active" and not entry.status_reason.strip():
            raise ValueError("Migration snapshot entry status_reason is required for blocked entries.")
        if entry.classical_address in seen_addresses:
            raise ValueError("Migration snapshot contains duplicate classical addresses.")
        seen_addresses.add(entry.classical_address)

    finalized = bundle.finalized()
    if bundle.manifest_hash and bundle.manifest_hash != finalized.manifest_hash:
        raise ValueError("Migration snapshot manifest_hash does not match the bundle contents.")
    return finalized


def parse_snapshot_import_payload(payload: dict[str, object]) -> tuple[MigrationSnapshotBundle, dict[str, object] | None]:
    bundle_payload = payload.get("bundle")
    envelope_payload = payload.get("envelope")
    if isinstance(bundle_payload, dict):
        bundle = MigrationSnapshotBundle.from_dict(bundle_payload)
    else:
        bundle = MigrationSnapshotBundle.from_dict(payload)
    envelope = dict(envelope_payload) if isinstance(envelope_payload, dict) else None
    return validate_snapshot_bundle(bundle), envelope
