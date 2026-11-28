from __future__ import annotations

import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "tests" / "fixtures" / "migration-export-v1.json"
VERIFIER = ROOT / "scripts" / "verify_migration_artifact.py"


class IndependentMigrationArtifactVerifierTests(unittest.TestCase):
    def verify(self, payload: object) -> subprocess.CompletedProcess[str]:
        with tempfile.TemporaryDirectory() as temporary_directory:
            artifact_path = Path(temporary_directory) / "artifact.json"
            artifact_path.write_text(json.dumps(payload), encoding="utf-8")
            return subprocess.run(
                [sys.executable, str(VERIFIER), "--input", str(artifact_path)],
                cwd=ROOT,
                check=False,
                capture_output=True,
                text=True,
            )

    def test_golden_artifact_is_independently_reproducible(self) -> None:
        artifact = json.loads(FIXTURE.read_text(encoding="utf-8"))

        result = self.verify(artifact)

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        report = json.loads(result.stdout)
        self.assertTrue(report["valid"])
        self.assertEqual(report["snapshot_ref"], "golden-export-v1")
        self.assertEqual(report["record_count"], 1)
        self.assertEqual(report["total_amount"], 12345)
        self.assertEqual(
            report["snapshot_manifest_hash"],
            "328e6491eeb1303b835c934277ba5efb3d7bec6c84a52b1d682f61e2e58d42e9",
        )
        self.assertEqual(
            report["ingestion_manifest_hash"],
            "42b80590b1198efe21cf97a5e64fc774319b773737c33039a2237123355a05d9",
        )

    def test_rejects_normalized_record_that_differs_from_snapshot_entry(self) -> None:
        artifact = json.loads(FIXTURE.read_text(encoding="utf-8"))
        artifact["normalized_records"][0]["amount"] += 1

        result = self.verify(artifact)

        self.assertEqual(result.returncode, 1)
        self.assertIn("normalized_records do not match the bundle entry projection", result.stdout)

    def test_rejects_tampered_snapshot_entry(self) -> None:
        artifact = json.loads(FIXTURE.read_text(encoding="utf-8"))
        artifact["bundle"]["entries"][0]["amount"] += 1

        result = self.verify(artifact)

        self.assertEqual(result.returncode, 1)
        self.assertIn("entry_count or total_amount", result.stdout)

    def test_rejects_tampered_source_anchor(self) -> None:
        artifact = json.loads(FIXTURE.read_text(encoding="utf-8"))
        artifact["source_provenance"]["source_anchor"]["block_hash"] = "00" * 32

        result = self.verify(artifact)

        self.assertEqual(result.returncode, 1)
        self.assertIn("source_provenance_hash does not match provenance", result.stdout)


if __name__ == "__main__":
    unittest.main()

