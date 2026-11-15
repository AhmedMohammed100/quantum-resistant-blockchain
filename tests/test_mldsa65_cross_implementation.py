from __future__ import annotations

import json
import os
import subprocess
import unittest
from pathlib import Path
from typing import Any

from qr_blockchain.crypto import get_signature_provider


TOOL_ENV = "QBC_CIRCL_MLDSA_TOOL"
MECHANISM = "ML-DSA-65"
PUBLIC_KEY_SIZE = 1952
SIGNATURE_SIZE = 3309
MESSAGES = (
    b"QBC ML-DSA-65 independent interoperability v1",
    b"\x00QBC\xffembedded-nul and non-UTF8 bytes\x00",
)


class MLDSA65CrossImplementationTests(unittest.TestCase):
    """Check raw FIPS 204 signatures in both directions: liboqs <-> CIRCL."""

    @classmethod
    def setUpClass(cls) -> None:
        tool = os.environ.get(TOOL_ENV)
        if not tool:
            raise unittest.SkipTest(f"Set {TOOL_ENV} to the pinned CIRCL test helper.")
        cls.tool = Path(tool)
        if not cls.tool.is_file():
            raise RuntimeError(f"CIRCL interoperability helper does not exist: {cls.tool}")

        cls.provider = get_signature_provider("mldsa65_oqs_v1")
        status = cls.provider.backend_status()
        if status.get("available") is not True:
            raise RuntimeError(
                "The cross-implementation CI job requires real ML-DSA-65: "
                + str(status.get("error", status))
            )
        if status.get("selected_mechanism") != MECHANISM:
            raise RuntimeError(f"Expected {MECHANISM}, got {status.get('selected_mechanism')!r}")

    def _run_circl(self, payload: dict[str, str]) -> dict[str, Any]:
        result = subprocess.run(
            [str(self.tool)],
            input=json.dumps(payload),
            text=True,
            capture_output=True,
            check=False,
            timeout=30,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        try:
            response = json.loads(result.stdout)
        except json.JSONDecodeError as error:
            self.fail(f"CIRCL helper returned invalid JSON: {error}: {result.stdout!r}")
        self.assertEqual(
            response.get("implementation"),
            "cloudflare/circl/sign/mldsa/mldsa65@v1.6.0",
        )
        return response

    def test_liboqs_signatures_verify_in_independent_circl(self) -> None:
        keypair = self.provider.generate_keypair()
        public_key = self.provider.export_public_key(keypair)

        for message in MESSAGES:
            with self.subTest(message=message.hex()):
                actual_public_key, signature = self.provider.sign(keypair, message)
                public_key_hex = actual_public_key["public_key_hex"]
                signature_hex = signature["signature_hex"]
                self.assertEqual(len(bytes.fromhex(public_key_hex)), PUBLIC_KEY_SIZE)
                self.assertEqual(len(bytes.fromhex(signature_hex)), SIGNATURE_SIZE)

                request = {
                    "operation": "verify",
                    "message_hex": message.hex(),
                    "public_key_hex": public_key_hex,
                    "signature_hex": signature_hex,
                }
                self.assertTrue(self._run_circl(request)["valid"])

                tampered = dict(request, message_hex=(message + b"!").hex())
                self.assertFalse(self._run_circl(tampered)["valid"])
                truncated = dict(request, signature_hex=signature_hex[:-2])
                self.assertFalse(self._run_circl(truncated)["valid"])

        self.assertEqual(public_key["mechanism"], MECHANISM)

    def test_circl_signatures_verify_in_liboqs_and_reject_mismatch(self) -> None:
        for message in MESSAGES:
            with self.subTest(message=message.hex()):
                external = self._run_circl(
                    {"operation": "sign", "message_hex": message.hex()}
                )
                self.assertTrue(external["valid"])
                public_key_hex = external["public_key_hex"]
                signature_hex = external["signature_hex"]
                self.assertEqual(len(bytes.fromhex(public_key_hex)), PUBLIC_KEY_SIZE)
                self.assertEqual(len(bytes.fromhex(signature_hex)), SIGNATURE_SIZE)

                public_key = {
                    "library": "oqs",
                    "mechanism": MECHANISM,
                    "public_key_hex": public_key_hex,
                }
                signature = {
                    "library": "oqs",
                    "mechanism": MECHANISM,
                    "signature_hex": signature_hex,
                }
                self.assertTrue(self.provider.verify(message, signature, public_key))
                self.assertFalse(self.provider.verify(message + b"!", signature, public_key))

                truncated = dict(signature, signature_hex=signature_hex[:-2])
                self.assertFalse(self.provider.verify(message, truncated, public_key))

                mismatched = dict(signature, mechanism="ML-DSA-44")
                self.assertFalse(self.provider.verify(message, mismatched, public_key))


if __name__ == "__main__":
    unittest.main()
