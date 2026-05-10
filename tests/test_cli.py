from __future__ import annotations

from contextlib import redirect_stdout
import io
import json
from pathlib import Path
import shutil
import unittest

from qr_blockchain import NodeConfig, NodeService
from qr_blockchain.cli import main
from qr_blockchain.migration import build_demo_classical_claim_address, build_demo_classical_claim_public_key


class OperatorCliTests(unittest.TestCase):
    def setUp(self) -> None:
        self.root = Path("test_runtime") / self._testMethodName
        if self.root.exists():
            shutil.rmtree(self.root)
        self.root.mkdir(parents=True, exist_ok=True)
        self.addCleanup(lambda: shutil.rmtree(self.root, ignore_errors=True))
        self.db_path = self.root / "chain.db"
        self.wallet_state_db_path = self.root / "wallet_state.db"
        self.service = NodeService(
            NodeConfig(
                db_path=self.db_path,
                wallet_state_db_path=self.wallet_state_db_path,
            )
        )

    def demo_address(self, seed: str) -> str:
        return build_demo_classical_claim_address(build_demo_classical_claim_public_key(seed))

    def test_cli_exports_and_validates_signed_snapshot(self) -> None:
        self.service.seed_migration_source(
            classical_address=self.demo_address("cli-user"),
            provider_id="classical_claim_demo_v1",
            source_network="legacy-demo-ledger",
            amount=17,
            snapshot_ref="cli-snapshot",
        )
        export_path = self.root / "snapshot.json"
        validate_buffer = io.StringIO()

        self.assertEqual(
            main(
                [
                    "--db-path",
                    str(self.db_path),
                    "--wallet-state-db-path",
                    str(self.wallet_state_db_path),
                    "migration-snapshot-export",
                    "--source-network",
                    "legacy-demo-ledger",
                    "--snapshot-ref",
                    "cli-snapshot",
                    "--sign",
                    "--output",
                    str(export_path),
                ]
            ),
            0,
        )
        with redirect_stdout(validate_buffer):
            exit_code = main(["migration-snapshot-validate", "--input", str(export_path)])
        self.assertEqual(exit_code, 0)
        payload = json.loads(validate_buffer.getvalue())
        self.assertTrue(payload["has_envelope"])
        self.assertEqual(payload["bundle"]["snapshot_ref"], "cli-snapshot")

    def test_cli_emits_migration_report(self) -> None:
        self.service.seed_migration_source(
            classical_address=self.demo_address("report-user"),
            provider_id="classical_claim_demo_v1",
            source_network="legacy-demo-ledger",
            amount=5,
            snapshot_ref="report-snapshot",
        )
        buffer = io.StringIO()

        with redirect_stdout(buffer):
            exit_code = main(
                [
                    "--db-path",
                    str(self.db_path),
                    "--wallet-state-db-path",
                    str(self.wallet_state_db_path),
                    "migration-report",
                    "--source-network",
                    "legacy-demo-ledger",
                ]
            )

        self.assertEqual(exit_code, 0)
        payload = json.loads(buffer.getvalue())
        self.assertEqual(payload["source_count"], 1)

    def test_cli_reconciles_snapshot_artifact(self) -> None:
        existing = self.demo_address("reconcile-existing")
        incoming = self.demo_address("reconcile-incoming")
        self.service.seed_migration_source(
            classical_address=existing,
            provider_id="classical_claim_demo_v1",
            source_network="legacy-demo-ledger",
            amount=4,
            snapshot_ref="cli-reconcile",
        )
        snapshot_path = self.root / "incoming-snapshot.json"
        snapshot_path.write_text(
            json.dumps(
                {
                    "source_network": "legacy-demo-ledger",
                    "snapshot_ref": "cli-reconcile",
                    "generated_at": 200.0,
                    "entries": [
                        {
                            "classical_address": existing,
                            "provider_id": "classical_claim_demo_v1",
                            "amount": 4,
                            "source_address": existing,
                            "source_address_format": "demo_claim_address",
                        },
                        {"classical_address": incoming, "provider_id": "classical_claim_demo_v1", "amount": 5},
                    ],
                }
            ),
            encoding="utf-8",
        )
        buffer = io.StringIO()

        with redirect_stdout(buffer):
            exit_code = main(
                [
                    "--db-path",
                    str(self.db_path),
                    "--wallet-state-db-path",
                    str(self.wallet_state_db_path),
                    "migration-snapshot-reconcile",
                    "--input",
                    str(snapshot_path),
                ]
            )

        self.assertEqual(exit_code, 0)
        payload = json.loads(buffer.getvalue())
        self.assertEqual(payload["summary"]["would_add"], 1)
        self.assertEqual(payload["summary"]["unchanged"], 1)

    def test_cli_normalizes_source_export(self) -> None:
        source_export_path = self.root / "source-export.json"
        source_export_path.write_text(
            json.dumps(
                {
                    "source_network": "legacy-demo-ledger",
                    "snapshot_ref": "source-export-cli",
                    "generated_at": 300.0,
                    "provider_id": "classical_claim_demo_v1",
                    "source_address_format": "demo_claim_address",
                    "records": [
                        {
                            "classical_address": self.demo_address("source-export-user"),
                            "amount": 10,
                        }
                    ],
                }
            ),
            encoding="utf-8",
        )
        buffer = io.StringIO()

        with redirect_stdout(buffer):
            exit_code = main(
                [
                    "--db-path",
                    str(self.db_path),
                    "--wallet-state-db-path",
                    str(self.wallet_state_db_path),
                    "migration-source-export-normalize",
                    "--input",
                    str(source_export_path),
                ]
            )

        self.assertEqual(exit_code, 0)
        payload = json.loads(buffer.getvalue())
        self.assertEqual(payload["bundle"]["snapshot_ref"], "source-export-cli")
        self.assertEqual(payload["bundle"]["entry_count"], 1)
        self.assertTrue(payload["ingestion_manifest"]["ingestion_manifest_hash"])

    def test_cli_batch_normalizes_source_exports_and_builds_runbook(self) -> None:
        first_path = self.root / "source-export-one.json"
        second_path = self.root / "source-export-two.json"
        normalized_path = self.root / "normalized.json"
        approval_path = self.root / "approval.json"
        first_path.write_text(
            json.dumps(
                {
                    "source_network": "legacy-demo-ledger",
                    "snapshot_ref": "source-export-one",
                    "generated_at": 301.0,
                    "provider_id": "classical_claim_demo_v1",
                    "source_address_format": "demo_claim_address",
                    "records": [{"classical_address": self.demo_address("batch-one"), "amount": 10}],
                }
            ),
            encoding="utf-8",
        )
        second_path.write_text(
            json.dumps(
                {
                    "source_network": "legacy-demo-ledger",
                    "snapshot_ref": "source-export-two",
                    "generated_at": 302.0,
                    "provider_id": "classical_claim_demo_v1",
                    "source_address_format": "demo_claim_address",
                    "records": [{"classical_address": self.demo_address("batch-two"), "amount": 11}],
                }
            ),
            encoding="utf-8",
        )
        batch_buffer = io.StringIO()

        with redirect_stdout(batch_buffer):
            batch_exit = main(
                [
                    "--db-path",
                    str(self.db_path),
                    "--wallet-state-db-path",
                    str(self.wallet_state_db_path),
                    "migration-source-export-batch-normalize",
                    "--input",
                    str(first_path),
                    "--input",
                    str(second_path),
                ]
            )

        self.assertEqual(batch_exit, 0)
        batch_payload = json.loads(batch_buffer.getvalue())
        self.assertEqual(batch_payload["batch_manifest"]["item_count"], 2)
        normalized_path.write_text(json.dumps(batch_payload["items"][0]), encoding="utf-8")
        runbook_buffer = io.StringIO()

        with redirect_stdout(runbook_buffer):
            runbook_exit = main(
                [
                    "--db-path",
                    str(self.db_path),
                    "--wallet-state-db-path",
                    str(self.wallet_state_db_path),
                    "migration-source-ingestion-runbook",
                    "--input",
                    str(normalized_path),
                ]
            )

        self.assertEqual(runbook_exit, 0)
        runbook_payload = json.loads(runbook_buffer.getvalue())
        self.assertEqual(runbook_payload["snapshot_ref"], "source-export-one")
        self.assertTrue(runbook_payload["operator_steps"])

        manifest_buffer = io.StringIO()
        with redirect_stdout(manifest_buffer):
            manifest_exit = main(
                [
                    "--db-path",
                    str(self.db_path),
                    "--wallet-state-db-path",
                    str(self.wallet_state_db_path),
                    "migration-source-ingestion-manifest-status",
                    "--input",
                    str(normalized_path),
                ]
            )
        self.assertEqual(manifest_exit, 0)
        self.assertTrue(json.loads(manifest_buffer.getvalue())["valid"])

        with redirect_stdout(io.StringIO()) as approval_buffer:
            approval_exit = main(
                [
                    "--db-path",
                    str(self.db_path),
                    "--wallet-state-db-path",
                    str(self.wallet_state_db_path),
                    "migration-source-ingestion-approve",
                    "--input",
                    str(normalized_path),
                    "--operator",
                    "cli-operator",
                    "--reason",
                    "reviewed source export",
                    "--output",
                    str(approval_path),
                ]
            )
        self.assertEqual(approval_exit, 0)
        self.assertEqual(approval_buffer.getvalue(), "")

        plan_buffer = io.StringIO()
        with redirect_stdout(plan_buffer):
            plan_exit = main(
                [
                    "--db-path",
                    str(self.db_path),
                    "--wallet-state-db-path",
                    str(self.wallet_state_db_path),
                    "migration-source-ingestion-import-plan",
                    "--input",
                    str(normalized_path),
                    "--approval",
                    str(approval_path),
                ]
            )
        self.assertEqual(plan_exit, 0)
        self.assertTrue(json.loads(plan_buffer.getvalue())["ready"])

    def test_cli_preflights_migration_claim(self) -> None:
        self.service.create_genesis_block({"bootstrap": 1})
        classical_address = self.demo_address("preflight-cli")
        self.service.seed_migration_source(
            classical_address=classical_address,
            provider_id="classical_claim_demo_v1",
            source_network="legacy-demo-ledger",
            amount=6,
            snapshot_ref="cli-preflight",
        )
        buffer = io.StringIO()

        with redirect_stdout(buffer):
            exit_code = main(
                [
                    "--db-path",
                    str(self.db_path),
                    "--wallet-state-db-path",
                    str(self.wallet_state_db_path),
                    "migration-claim-preflight",
                    "--destination-address",
                    "pq-test-destination",
                    "--classical-address",
                    classical_address,
                    "--classical-provider-id",
                    "classical_claim_demo_v1",
                    "--source-network",
                    "legacy-demo-ledger",
                    "--snapshot-ref",
                    "cli-preflight",
                ]
            )

        self.assertEqual(exit_code, 0)
        payload = json.loads(buffer.getvalue())
        self.assertTrue(payload["ready"])
        self.assertTrue(payload["classical_claim_message_hex"])

    def test_cli_can_quarantine_snapshot(self) -> None:
        self.service.seed_migration_source(
            classical_address=self.demo_address("quarantine-user"),
            provider_id="classical_claim_demo_v1",
            source_network="legacy-demo-ledger",
            amount=6,
            snapshot_ref="quarantine-snapshot",
        )
        buffer = io.StringIO()

        with redirect_stdout(buffer):
            exit_code = main(
                [
                    "--db-path",
                    str(self.db_path),
                    "--wallet-state-db-path",
                    str(self.wallet_state_db_path),
                    "migration-snapshot-status",
                    "--snapshot-ref",
                    "quarantine-snapshot",
                    "--status",
                    "quarantined",
                    "--reason",
                    "cli-review",
                ]
            )

        self.assertEqual(exit_code, 0)
        payload = json.loads(buffer.getvalue())
        self.assertEqual(payload["status"], "quarantined")

    def test_cli_snapshot_export_can_include_inactive_sources(self) -> None:
        seeded = self.service.seed_migration_source(
            classical_address=self.demo_address("inactive-user"),
            provider_id="classical_claim_demo_v1",
            source_network="legacy-demo-ledger",
            amount=8,
            snapshot_ref="inactive-snapshot",
        )
        self.service.set_migration_source_status(
            seeded["classical_address"],
            status="quarantined",
            reason="manual review",
        )
        buffer = io.StringIO()

        with redirect_stdout(buffer):
            exit_code = main(
                [
                    "--db-path",
                    str(self.db_path),
                    "--wallet-state-db-path",
                    str(self.wallet_state_db_path),
                    "migration-snapshot-export",
                    "--source-network",
                    "legacy-demo-ledger",
                    "--snapshot-ref",
                    "inactive-snapshot",
                    "--include-inactive",
                ]
            )

        self.assertEqual(exit_code, 0)
        payload = json.loads(buffer.getvalue())
        self.assertEqual(payload["bundle"]["entry_count"], 1)
        self.assertEqual(payload["bundle"]["entries"][0]["status"], "quarantined")


if __name__ == "__main__":
    unittest.main()
