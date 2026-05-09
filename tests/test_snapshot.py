from __future__ import annotations

from pathlib import Path
import shutil
import unittest

from qr_blockchain import NodeConfig, NodeService
from qr_blockchain.migration import build_demo_classical_claim_address, build_demo_classical_claim_public_key
from qr_blockchain.snapshot import MigrationSnapshotBundle, MigrationSnapshotEntry, validate_snapshot_bundle


class MigrationSnapshotTests(unittest.TestCase):
    def demo_address(self, seed: str) -> str:
        return build_demo_classical_claim_address(build_demo_classical_claim_public_key(seed))

    def make_service(self) -> NodeService:
        root = Path("test_runtime") / self._testMethodName
        if root.exists():
            shutil.rmtree(root)
        root.mkdir(parents=True, exist_ok=True)
        self.addCleanup(lambda: shutil.rmtree(root, ignore_errors=True))
        return NodeService(
            NodeConfig(
                db_path=root / "chain.db",
                wallet_state_db_path=root / "wallet_state.db",
            )
        )

    def test_snapshot_bundle_hash_is_deterministic(self) -> None:
        first = validate_snapshot_bundle(
            MigrationSnapshotBundle(
                source_network="legacy-ledger",
                snapshot_ref="snapshot-001",
                generated_at=100.0,
                entries=(
                    MigrationSnapshotEntry(self.demo_address("addr-b"), "classical_claim_demo_v1", 7),
                    MigrationSnapshotEntry(self.demo_address("addr-a"), "classical_claim_demo_v1", 5),
                ),
            )
        )
        second = validate_snapshot_bundle(
            MigrationSnapshotBundle(
                source_network="legacy-ledger",
                snapshot_ref="snapshot-001",
                generated_at=100.0,
                entries=(
                    MigrationSnapshotEntry(self.demo_address("addr-a"), "classical_claim_demo_v1", 5),
                    MigrationSnapshotEntry(self.demo_address("addr-b"), "classical_claim_demo_v1", 7),
                ),
            )
        )

        self.assertEqual(first.manifest_hash, second.manifest_hash)
        self.assertEqual(first.entries_root(), second.entries_root())

    def test_imports_snapshot_and_exposes_snapshot_backed_sources(self) -> None:
        service = self.make_service()
        addr_a = self.demo_address("addr-a")
        addr_b = self.demo_address("addr-b")
        snapshot = {
            "source_network": "legacy-demo-ledger",
            "snapshot_ref": "snapshot-002",
            "generated_at": 101.0,
            "entries": [
                {"classical_address": addr_a, "provider_id": "classical_claim_demo_v1", "amount": 5},
                {"classical_address": addr_b, "provider_id": "classical_claim_demo_v1", "amount": 7},
            ],
        }

        imported = service.import_migration_snapshot(snapshot)

        self.assertEqual(imported["snapshot_ref"], "snapshot-002")
        self.assertEqual(imported["entry_count"], 2)
        self.assertEqual(imported["total_amount"], 12)
        sources = {item["classical_address"]: item for item in service.list_migration_sources()}
        self.assertEqual(sources[addr_a]["snapshot_ref"], "snapshot-002")
        self.assertEqual(sources[addr_a]["snapshot_hash"], imported["manifest_hash"])

    def test_snapshot_import_is_idempotent_for_identical_contents(self) -> None:
        service = self.make_service()
        addr_a = self.demo_address("addr-a")
        snapshot = {
            "source_network": "legacy-demo-ledger",
            "snapshot_ref": "snapshot-003",
            "generated_at": 102.0,
            "entries": [
                {"classical_address": addr_a, "provider_id": "classical_claim_demo_v1", "amount": 9},
            ],
        }

        first = service.import_migration_snapshot(snapshot)
        second = service.import_migration_snapshot(snapshot)

        self.assertEqual(first["manifest_hash"], second["manifest_hash"])
        self.assertEqual(len(service.list_migration_snapshots()), 1)
        self.assertEqual(len(service.list_migration_sources()), 1)

    def test_signs_and_imports_snapshot_with_provenance(self) -> None:
        service = self.make_service()
        addr_a = self.demo_address("addr-a")
        snapshot = {
            "source_network": "legacy-demo-ledger",
            "snapshot_ref": "snapshot-003-signed",
            "generated_at": 102.5,
            "entries": [
                {"classical_address": addr_a, "provider_id": "classical_claim_demo_v1", "amount": 9},
            ],
        }

        signed = service.sign_migration_snapshot(snapshot)
        imported = service.import_migration_snapshot(signed)

        self.assertEqual(imported["snapshot_ref"], "snapshot-003-signed")
        self.assertTrue(imported["signer_address"])
        self.assertTrue(imported["signer_node_id"])
        self.assertTrue(imported["signer_signature_scheme"])
        self.assertTrue(imported["signer_signature_provider"])

    def test_rejects_mutated_snapshot_with_same_ref(self) -> None:
        service = self.make_service()
        addr_a = self.demo_address("addr-a")
        snapshot = {
            "source_network": "legacy-demo-ledger",
            "snapshot_ref": "snapshot-004",
            "generated_at": 103.0,
            "entries": [
                {"classical_address": addr_a, "provider_id": "classical_claim_demo_v1", "amount": 4},
            ],
        }
        service.import_migration_snapshot(snapshot)

        mutated = {
            **snapshot,
            "entries": [
                {"classical_address": addr_a, "provider_id": "classical_claim_demo_v1", "amount": 8},
            ],
        }

        with self.assertRaisesRegex(ValueError, "already exists with different contents"):
            service.import_migration_snapshot(mutated)

    def test_rejects_signed_snapshot_with_mismatched_manifest_claims(self) -> None:
        service = self.make_service()
        addr_a = self.demo_address("addr-a")
        snapshot = {
            "source_network": "legacy-demo-ledger",
            "snapshot_ref": "snapshot-005",
            "generated_at": 104.0,
            "entries": [
                {"classical_address": addr_a, "provider_id": "classical_claim_demo_v1", "amount": 6},
            ],
        }

        signed = service.sign_migration_snapshot(snapshot)
        envelope = dict(signed["envelope"])
        claims = dict(envelope["claims"])
        claims["total_amount"] = 999
        envelope["claims"] = claims

        with self.assertRaisesRegex(ValueError, "Auth signature verification failed"):
            service.import_migration_snapshot({"bundle": signed["bundle"], "envelope": envelope})

    def test_exports_signed_snapshot_from_seeded_sources(self) -> None:
        service = self.make_service()
        addr_a = self.demo_address("seed-a")
        service.seed_migration_source(
            classical_address=addr_a,
            provider_id="classical_claim_demo_v1",
            source_network="legacy-demo-ledger",
            amount=11,
            snapshot_ref="seed-snapshot",
        )

        exported = service.export_migration_snapshot(
            source_network="legacy-demo-ledger",
            snapshot_ref="seed-snapshot",
            sign=True,
        )

        self.assertEqual(exported["source_count"], 1)
        self.assertEqual(exported["bundle"]["entries"][0]["classical_address"], addr_a)
        self.assertIn("envelope", exported)

    def test_reconciles_snapshot_before_import(self) -> None:
        service = self.make_service()
        existing = self.demo_address("existing")
        incoming = self.demo_address("incoming")
        service.seed_migration_source(
            classical_address=existing,
            provider_id="classical_claim_demo_v1",
            source_network="legacy-demo-ledger",
            amount=4,
            snapshot_ref="reconcile-snapshot",
        )
        snapshot = {
            "source_network": "legacy-demo-ledger",
            "snapshot_ref": "reconcile-snapshot",
            "generated_at": 107.0,
            "entries": [
                {"classical_address": existing, "provider_id": "classical_claim_demo_v1", "amount": 9},
                {"classical_address": incoming, "provider_id": "classical_claim_demo_v1", "amount": 3},
            ],
        }

        report = service.reconcile_migration_snapshot(snapshot)

        self.assertEqual(report["summary"]["would_add"], 1)
        self.assertEqual(report["summary"]["changed"], 1)
        self.assertEqual(report["would_add"][0]["classical_address"], incoming)
        self.assertEqual(report["changed"][0]["differences"]["amount"]["existing"], 4)

    def test_rejects_untrusted_snapshot_signer_when_policy_requires_allowlist(self) -> None:
        service = self.make_service()
        addr_a = self.demo_address("trusted-a")
        signed = service.sign_migration_snapshot(
            {
                "source_network": "legacy-demo-ledger",
                "snapshot_ref": "trusted-snapshot",
                "generated_at": 106.0,
                "entries": [
                    {"classical_address": addr_a, "provider_id": "classical_claim_demo_v1", "amount": 5},
                ],
            }
        )
        restricted = NodeService(
            NodeConfig(
                db_path=service.config.db_path.parent / "restricted-chain.db",
                wallet_state_db_path=service.config.wallet_state_db_path.parent / "restricted-wallet.db",
                migration_require_snapshot_signatures=True,
                migration_trusted_snapshot_signers=("not-the-real-signer",),
            )
        )

        with self.assertRaisesRegex(ValueError, "not trusted"):
            restricted.import_migration_snapshot(signed)


if __name__ == "__main__":
    unittest.main()
