from __future__ import annotations

from pathlib import Path
import json
import shutil
import unittest

from qr_blockchain import NodeConfig, NodeService
import qr_chain_classical_migration_backend_secp256k1 as secp_backend


class SourceExportIngestionTests(unittest.TestCase):
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

    def secp_public_key(self, private_key: int = 1) -> dict[str, object]:
        point = secp_backend._point_mul(private_key, secp_backend._G)
        assert point is not None
        public_key_bytes = b"\x04" + point[0].to_bytes(32, "big") + point[1].to_bytes(32, "big")
        return {"public_key_hex": public_key_bytes.hex()}

    def test_normalizes_source_export_with_public_key_linkage(self) -> None:
        service = self.make_service()
        public_key = self.secp_public_key()
        source_address = secp_backend.derive_bitcoin_p2pkh_addresses(public_key)[0]

        normalized = service.normalize_source_export_snapshot(
            {
                "source_network": "legacy-btc-mainnet",
                "snapshot_ref": "btc-export-001",
                "generated_at": 250.0,
                "provider_id": "ecdsa_secp256k1_migration_v1",
                "source_address_format": "bitcoin_base58",
                "records": [
                    {
                        "classical_public_key": public_key,
                        "source_address": source_address,
                        "amount": 42,
                    }
                ],
            },
            sign=True,
        )

        entry = normalized["bundle"]["entries"][0]
        self.assertEqual(entry["classical_address"], secp_backend.address_from_public_key(public_key))
        self.assertEqual(entry["source_address"], source_address)
        self.assertEqual(normalized["ingestion_manifest"]["record_count"], 1)
        self.assertTrue(normalized["ingestion_manifest"]["records_root"])
        self.assertTrue(normalized["ingestion_manifest"]["ingestion_manifest_hash"])
        self.assertIn("envelope", normalized)

    def test_rejects_source_export_with_mismatched_public_key(self) -> None:
        service = self.make_service()
        public_key = self.secp_public_key(1)
        other_public_key = self.secp_public_key(2)
        source_address = secp_backend.derive_bitcoin_p2pkh_addresses(other_public_key)[0]

        with self.assertRaisesRegex(ValueError, "does not own source_address"):
            service.normalize_source_export_snapshot(
                {
                    "source_network": "legacy-btc-mainnet",
                    "snapshot_ref": "btc-export-002",
                    "generated_at": 251.0,
                    "provider_id": "ecdsa_secp256k1_migration_v1",
                    "source_address_format": "bitcoin_base58",
                    "records": [
                        {
                            "classical_public_key": public_key,
                            "source_address": source_address,
                            "amount": 42,
                        }
                    ],
                }
            )

    def test_normalized_source_export_can_be_imported(self) -> None:
        service = self.make_service()
        public_key = self.secp_public_key()
        source_address = secp_backend.derive_bitcoin_p2pkh_addresses(public_key)[0]
        normalized = service.normalize_source_export_snapshot(
            {
                "source_network": "legacy-btc-mainnet",
                "snapshot_ref": "btc-export-003",
                "generated_at": 252.0,
                "provider_id": "ecdsa_secp256k1_migration_v1",
                "source_address_format": "bitcoin_base58",
                "records": [{"classical_public_key": public_key, "source_address": source_address, "amount": 12}],
            }
        )

        imported = service.import_migration_snapshot(normalized["bundle"])

        self.assertEqual(imported["snapshot_ref"], "btc-export-003")
        self.assertEqual(imported["entry_count"], 1)

    def test_ingestion_manifest_is_deterministic_for_reordered_records(self) -> None:
        service = self.make_service()
        first_key = self.secp_public_key(1)
        second_key = self.secp_public_key(2)
        first_record = {
            "classical_public_key": first_key,
            "source_address": secp_backend.derive_bitcoin_p2pkh_addresses(first_key)[0],
            "amount": 12,
            "source_height": 10,
            "source_tx_id": "tx-a",
            "source_output_index": 0,
        }
        second_record = {
            "classical_public_key": second_key,
            "source_address": secp_backend.derive_bitcoin_p2pkh_addresses(second_key)[0],
            "amount": 14,
            "source_height": 11,
            "source_tx_id": "tx-b",
            "source_output_index": 1,
        }
        base_payload = {
            "source_network": "legacy-btc-mainnet",
            "snapshot_ref": "btc-export-004",
            "generated_at": 253.0,
            "provider_id": "ecdsa_secp256k1_migration_v1",
            "source_address_format": "bitcoin_base58",
        }

        first = service.normalize_source_export_snapshot({**base_payload, "records": [first_record, second_record]})
        second = service.normalize_source_export_snapshot({**base_payload, "records": [second_record, first_record]})

        self.assertEqual(first["ingestion_manifest"]["records_root"], second["ingestion_manifest"]["records_root"])
        self.assertEqual(
            first["ingestion_manifest"]["ingestion_manifest_hash"],
            second["ingestion_manifest"]["ingestion_manifest_hash"],
        )

    def test_batch_normalizes_multiple_source_exports(self) -> None:
        service = self.make_service()
        first_key = self.secp_public_key(1)
        second_key = self.secp_public_key(2)

        batch = service.normalize_source_export_batch(
            [
                {
                    "source_network": "legacy-btc-mainnet",
                    "snapshot_ref": "btc-export-005-a",
                    "generated_at": 254.0,
                    "provider_id": "ecdsa_secp256k1_migration_v1",
                    "source_address_format": "bitcoin_base58",
                    "records": [
                        {
                            "classical_public_key": first_key,
                            "source_address": secp_backend.derive_bitcoin_p2pkh_addresses(first_key)[0],
                            "amount": 7,
                        }
                    ],
                },
                {
                    "source_network": "legacy-btc-mainnet",
                    "snapshot_ref": "btc-export-005-b",
                    "generated_at": 255.0,
                    "provider_id": "ecdsa_secp256k1_migration_v1",
                    "source_address_format": "bitcoin_base58",
                    "records": [
                        {
                            "classical_public_key": second_key,
                            "source_address": secp_backend.derive_bitcoin_p2pkh_addresses(second_key)[0],
                            "amount": 8,
                        }
                    ],
                },
            ]
        )

        self.assertEqual(batch["batch_manifest"]["item_count"], 2)
        self.assertEqual(batch["batch_manifest"]["total_records"], 2)
        self.assertEqual(batch["batch_manifest"]["total_amount"], 15)
        self.assertEqual(len(batch["items"]), 2)

    def test_builds_source_ingestion_runbook(self) -> None:
        service = self.make_service()
        public_key = self.secp_public_key()
        normalized = service.normalize_source_export_snapshot(
            {
                "source_network": "legacy-btc-mainnet",
                "snapshot_ref": "btc-export-006",
                "generated_at": 256.0,
                "provider_id": "ecdsa_secp256k1_migration_v1",
                "source_address_format": "bitcoin_base58",
                "records": [
                    {
                        "classical_public_key": public_key,
                        "source_address": secp_backend.derive_bitcoin_p2pkh_addresses(public_key)[0],
                        "amount": 9,
                    }
                ],
            }
        )

        runbook = service.source_ingestion_runbook(normalized)

        self.assertEqual(runbook["snapshot_ref"], "btc-export-006")
        self.assertEqual(runbook["ingestion_manifest_hash"], normalized["ingestion_manifest"]["ingestion_manifest_hash"])
        self.assertIn("post_import_audit_report", runbook["required_evidence"])

    def test_ingestion_approval_import_plan_and_approved_import(self) -> None:
        service = self.make_service()
        public_key = self.secp_public_key()
        normalized = service.normalize_source_export_snapshot(
            {
                "source_network": "legacy-btc-mainnet",
                "snapshot_ref": "btc-export-007",
                "generated_at": 257.0,
                "provider_id": "ecdsa_secp256k1_migration_v1",
                "source_address_format": "bitcoin_base58",
                "records": [
                    {
                        "classical_public_key": public_key,
                        "source_address": secp_backend.derive_bitcoin_p2pkh_addresses(public_key)[0],
                        "amount": 16,
                    }
                ],
            }
        )

        status = service.source_ingestion_manifest_status(normalized)
        approval = service.approve_source_ingestion(
            normalized,
            operator="operator-a",
            decision="approved",
            reason="matched archived source export",
        )
        plan = service.source_ingestion_import_plan(normalized, approval=approval)
        result = service.import_approved_source_ingestion(normalized, approval=approval)

        self.assertTrue(status["valid"])
        self.assertTrue(plan["ready"])
        self.assertEqual(result["imported"]["snapshot_ref"], "btc-export-007")
        self.assertEqual(result["rollback_evidence"]["status_reversal"]["status"], "quarantined")
        self.assertEqual(result["post_import_audit_report"]["source_count"], 1)

    def test_import_plan_blocks_existing_source_changes(self) -> None:
        service = self.make_service()
        public_key = self.secp_public_key()
        source_address = secp_backend.derive_bitcoin_p2pkh_addresses(public_key)[0]
        first = service.normalize_source_export_snapshot(
            {
                "source_network": "legacy-btc-mainnet",
                "snapshot_ref": "btc-export-008",
                "generated_at": 258.0,
                "provider_id": "ecdsa_secp256k1_migration_v1",
                "source_address_format": "bitcoin_base58",
                "records": [{"classical_public_key": public_key, "source_address": source_address, "amount": 16}],
            }
        )
        approval = service.approve_source_ingestion(first, operator="operator-a", decision="approved", reason="initial")
        service.import_approved_source_ingestion(first, approval=approval)
        changed = service.normalize_source_export_snapshot(
            {
                "source_network": "legacy-btc-mainnet",
                "snapshot_ref": "btc-export-008",
                "generated_at": 258.0,
                "provider_id": "ecdsa_secp256k1_migration_v1",
                "source_address_format": "bitcoin_base58",
                "records": [{"classical_public_key": public_key, "source_address": source_address, "amount": 17}],
            }
        )
        changed_approval = service.approve_source_ingestion(
            changed,
            operator="operator-a",
            decision="approved",
            reason="changed",
        )

        plan = service.source_ingestion_import_plan(changed, approval=changed_approval)

        self.assertFalse(plan["ready"])
        self.assertIn("existing_sources_would_change", plan["blockers"])


if __name__ == "__main__":
    unittest.main()
