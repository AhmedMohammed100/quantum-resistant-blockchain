from __future__ import annotations

import json
import os
from pathlib import Path
import unittest


ACVP_COMMIT = "a7f283cdc87d2d6dd93c1bac59e5622c5f9f8324"
VECTOR_SET_ID = 42


class OfficialMLDSA65ACVPTests(unittest.TestCase):
    """Verify official NIST ACVP ML-DSA-65 pure-signature vectors with liboqs."""

    @classmethod
    def setUpClass(cls) -> None:
        data_dir = os.environ.get("QBC_ACVP_DATA_DIR")
        if not data_dir:
            raise unittest.SkipTest(
                "Set QBC_ACVP_DATA_DIR to a directory containing the official "
                "NIST ACVP prompt.json and expectedResults.json files."
            )

        root = Path(data_dir)
        prompt_path = root / "prompt.json"
        expected_path = root / "expectedResults.json"
        if not prompt_path.is_file() or not expected_path.is_file():
            raise unittest.SkipTest("Official NIST ACVP vector files are not present.")

        cls.prompt = json.loads(prompt_path.read_text(encoding="utf-8"))
        cls.expected = json.loads(expected_path.read_text(encoding="utf-8"))

        try:
            import oqs  # type: ignore[import-not-found]
        except (ImportError, SystemExit, RuntimeError) as error:
            raise unittest.SkipTest(f"liboqs-python/native liboqs unavailable: {error}") from error

        cls.oqs = oqs

    def test_official_nist_fips204_mldsa65_pure_sigver_vectors(self) -> None:
        self.assertEqual(self.prompt.get("algorithm"), "ML-DSA")
        self.assertEqual(self.prompt.get("mode"), "sigVer")
        self.assertEqual(self.prompt.get("revision"), "FIPS204")
        self.assertEqual(self.prompt.get("vsId"), VECTOR_SET_ID)
        self.assertEqual(self.expected.get("vsId"), VECTOR_SET_ID)

        expected_by_id = {
            int(case["tcId"]): bool(case["testPassed"])
            for group in self.expected.get("testGroups", [])
            for case in group.get("tests", [])
        }
        selected = [
            (group, case)
            for group in self.prompt.get("testGroups", [])
            if group.get("parameterSet") == "ML-DSA-65"
            and group.get("signatureInterface") == "external"
            and group.get("preHash") == "pure"
            for case in group.get("tests", [])
        ]
        self.assertTrue(selected, "No ML-DSA-65 pure external ACVP vectors found.")

        passed = 0
        rejected = 0
        with self.oqs.Signature("ML-DSA-65") as verifier:
            verify_with_context = getattr(verifier, "verify_with_ctx_str", None)
            self.assertTrue(
                callable(verify_with_context),
                "liboqs-python >= 0.12 with verify_with_ctx_str() is required.",
            )
            for group, case in selected:
                with self.subTest(tcId=case["tcId"], tgId=group["tgId"]):
                    tc_id = int(case["tcId"])
                    self.assertIn(tc_id, expected_by_id, f"Missing expected result for tcId {tc_id}")
                    public_key = bytes.fromhex(case["pk"])
                    signature = bytes.fromhex(case["signature"])
                    message = bytes.fromhex(case["message"])
                    context = bytes.fromhex(group.get("context", case.get("context", "")))
                    actual = bool(verify_with_context(message, signature, context, public_key))
                    self.assertEqual(actual, expected_by_id[tc_id])
                    if actual:
                        passed += 1
                    else:
                        rejected += 1

        self.assertGreater(passed, 0, "Expected at least one valid signature vector.")
        self.assertGreater(rejected, 0, "Expected at least one invalid signature vector.")
        self.assertEqual(len(selected), 15, "The pinned NIST vector-set group changed unexpectedly.")


if __name__ == "__main__":
    unittest.main()
