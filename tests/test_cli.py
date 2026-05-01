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


if __name__ == "__main__":
    unittest.main()
