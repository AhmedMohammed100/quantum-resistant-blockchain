"""Cross-runtime conformance checks for the opt-in manifest candidate."""

import copy
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from qr_blockchain.portable_encoding import canonical_json_v1, hash_canonical_v1
from qr_blockchain.protocol_v2 import V2SchemaError
from qr_blockchain.protocol_v2_manifest import validate_v2_network_manifest
from tests.test_protocol_v2_manifest import fixture_manifest, validate


ROOT = Path(__file__).resolve().parents[1]
GO_MODULE = ROOT / "conformance" / "go"
CHAIN_ID = "qbc-v2-fixture"
GENESIS_HASH = "a" * 64


@unittest.skipUnless(shutil.which("go"), "Go is required for cross-runtime conformance")
class ProtocolV2ManifestCrossRuntimeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        runtime_dir = ROOT / "test_runtime"
        runtime_dir.mkdir(exist_ok=True)
        cls.binary_dir = tempfile.TemporaryDirectory(prefix="qbc-manifestcheck-", dir=runtime_dir)
        cls.go_env = os.environ.copy()
        cls.go_env["GOCACHE"] = str(runtime_dir / "go-cache")
        cls.go_env["GOTMPDIR"] = str(runtime_dir / "go-tmp")
        Path(cls.go_env["GOTMPDIR"]).mkdir(exist_ok=True)
        binary_name = "manifestcheck.exe" if os.name == "nt" else "manifestcheck"
        cls.binary = Path(cls.binary_dir.name) / binary_name
        subprocess.run(
            ["go", "build", "-o", str(cls.binary), "./cmd/manifestcheck"],
            cwd=GO_MODULE,
            env=cls.go_env,
            check=True,
            capture_output=True,
            text=True,
        )

    @classmethod
    def tearDownClass(cls):
        cls.binary_dir.cleanup()

    def go_validate(self, manifest, *, chain_id=CHAIN_ID, genesis_hash=GENESIS_HASH):
        return subprocess.run(
            [str(self.binary), "--chain-id", chain_id, "--genesis-hash", genesis_hash],
            input=canonical_json_v1(manifest),
            cwd=ROOT,
            capture_output=True,
            check=False,
        )

    def python_validate(self, manifest, *, chain_id=CHAIN_ID, genesis_hash=GENESIS_HASH):
        return validate_v2_network_manifest(
            manifest,
            expected_chain_id=chain_id,
            expected_genesis_hash=genesis_hash,
            supported_kinds={"transfer"},
            provider_profiles={("fixture_pq_v1", "1.0.0"): lambda _: None},
            consensus_profiles={("fixture-pow", "1"): lambda _: None},
        )

    def test_independent_runtimes_accept_same_manifest_and_digest(self):
        manifest = fixture_manifest()
        expected = "dcaee8df5e114551a305bf44b2a6ee21f53f439faca7f0f05502a3955311649c"

        python_digest = self.python_validate(manifest)
        go_result = self.go_validate(manifest)

        self.assertEqual(python_digest, expected)
        self.assertEqual(go_result.returncode, 0, go_result.stderr.decode("utf-8", errors="replace"))
        self.assertEqual(go_result.stdout.decode("ascii").strip(), python_digest)

    def test_each_runtime_rejects_a_node_network_mismatch(self):
        manifest = fixture_manifest()

        with self.assertRaisesRegex(V2SchemaError, "chain_id"):
            self.python_validate(manifest, chain_id="another-node-network")
        go_result = self.go_validate(manifest, chain_id="another-node-network")
        self.assertNotEqual(go_result.returncode, 0)
        self.assertIn(b"chain_id", go_result.stderr)

        with self.assertRaisesRegex(V2SchemaError, "genesis_hash"):
            self.python_validate(manifest, genesis_hash="b" * 64)
        go_result = self.go_validate(manifest, genesis_hash="b" * 64)
        self.assertNotEqual(go_result.returncode, 0)
        self.assertIn(b"genesis_hash", go_result.stderr)

    def test_each_runtime_rejects_the_same_semantic_mutation(self):
        manifest = fixture_manifest()
        manifest["transaction_kinds"] = ["unsupported", "transfer"]
        manifest["manifest_digest"] = hash_canonical_v1(
            "network-manifest-v2",
            {key: value for key, value in manifest.items() if key != "manifest_digest"},
        )

        with self.assertRaisesRegex(V2SchemaError, "no local schema"):
            self.python_validate(manifest)
        go_result = self.go_validate(manifest)
        self.assertNotEqual(go_result.returncode, 0)
        self.assertIn(b"no local schema", go_result.stderr)

        changed_digest = copy.deepcopy(fixture_manifest())
        changed_digest["manifest_digest"] = "0" * 64
        with self.assertRaisesRegex(V2SchemaError, "manifest_digest"):
            validate(changed_digest)
        go_result = self.go_validate(changed_digest)
        self.assertNotEqual(go_result.returncode, 0)
        self.assertIn(b"manifest_digest", go_result.stderr)


if __name__ == "__main__":
    unittest.main()
