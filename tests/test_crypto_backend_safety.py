from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from qr_chain_lms_backend import oqs_backend as lms
from qr_chain_xmss_backend import oqs_backend as xmss


class FakeStatefulSignature:
    def __init__(self, mechanism: str, *, fail_sign: bool = False):
        self.mechanism = mechanism
        self.secret = b"initial"
        self.fail_sign = fail_sign

    def import_secret_key(self, secret: bytes) -> None:
        self.secret = secret

    def sign(self, message: bytes) -> bytes:
        if self.fail_sign:
            raise ValueError("simulated signing failure")
        self.secret += b"!"
        return b"signature:" + message

    def export_secret_key(self) -> bytes:
        return self.secret

    def verify(self, message: bytes, signature: bytes, public_key: bytes) -> bool:
        return signature == b"signature:" + message and public_key == b"public"


class FakeOQS:
    __name__ = "oqs"

    def __init__(self, version: bytes = b"0.17.0"):
        self.version = version
        self.fail_sign = False

    def native(self):
        return SimpleNamespace(OQS_version=lambda: self.version)

    def get_enabled_stateful_sig_mechanisms(self):
        return ["LMS_SHA256_H10_W4"]

    def StatefulSignature(self, mechanism: str):
        return FakeStatefulSignature(mechanism, fail_sign=self.fail_sign)


class CryptoBackendSafetyTests(unittest.TestCase):
    def test_lms_rejects_liboqs_versions_with_disclosed_lms_issues(self) -> None:
        with self.assertRaisesRegex(ValueError, "require liboqs >= 0.17.0"):
            lms._native_liboqs_version(FakeOQS(b"0.16.0"))

    def test_lms_accepts_and_reports_safe_native_version(self) -> None:
        version, version_text = lms._native_liboqs_version(FakeOQS(b"0.17.0"))
        self.assertEqual(version, (0, 17, 0))
        self.assertEqual(version_text, "0.17.0")

    def test_xmss_rejects_versions_affected_by_cve_2026_46344(self) -> None:
        with self.assertRaisesRegex(ValueError, "CVE-2026-46344"):
            xmss._native_liboqs_version(FakeOQS(b"0.15.0"))

    def test_xmss_accepts_fixed_native_version(self) -> None:
        version, version_text = xmss._native_liboqs_version(FakeOQS(b"0.16.0"))
        self.assertEqual(version, (0, 16, 0))
        self.assertEqual(version_text, "0.16.0")

    def test_lms_rejects_algorithm_and_provider_mismatches(self) -> None:
        public_key = {
            "scheme": lms.EXPECTED_SCHEME_ID,
            "provider": lms.EXPECTED_SCHEME_ID,
            "mechanism": "LMS_SHA256_H10_W4",
            "library": "oqs",
            "public_key_hex": "7075626c6963",
        }
        signature = {
            "mechanism": "LMS_SHA256_H10_W8",
            "library": "oqs",
            "signature_hex": "736967",
        }
        with patch.object(lms, "_load_oqs", side_effect=AssertionError("must reject before native call")):
            self.assertFalse(lms.verify(b"msg", signature, public_key))
            signature["mechanism"] = public_key["mechanism"]
            public_key["provider"] = "wrong-provider"
            self.assertFalse(lms.verify(b"msg", signature, public_key))

    def test_lms_malformed_hex_is_a_controlled_verification_failure(self) -> None:
        public_key = {
            "scheme": lms.EXPECTED_SCHEME_ID,
            "provider": lms.EXPECTED_SCHEME_ID,
            "mechanism": "LMS_SHA256_H10_W4",
            "library": "oqs",
            "public_key_hex": "not-hex",
        }
        signature = {
            "mechanism": "LMS_SHA256_H10_W4",
            "library": "oqs",
            "signature_hex": "00",
        }
        with patch.object(lms, "_load_oqs", return_value=FakeOQS()):
            self.assertFalse(lms.verify(b"msg", signature, public_key))

    def test_lms_reservation_token_is_single_use_and_advances_state(self) -> None:
        keypair = lms.OQSLMSKeyPair(
            mechanism="LMS_SHA256_H10_W4",
            public_key_hex=b"public".hex(),
            secret_key_hex=b"initial".hex(),
        )
        with patch.object(lms, "_load_oqs", return_value=FakeOQS()):
            reservation = lms.reserve_signing_material(keypair)
            with self.assertRaisesRegex(ValueError, "stale, forged"):
                lms.sign_with_reservation(keypair, b"msg", {"reservation_id": "wrong"})
            public_key, signature = lms.sign_with_reservation(keypair, b"msg", reservation)
            self.assertEqual(keypair.signatures_used, 1)
            self.assertIsNone(keypair.pending_reservation_id)
            self.assertEqual(bytes.fromhex(keypair.secret_key_hex), b"initial!")
            self.assertTrue(lms.verify(b"msg", signature, public_key))
            with self.assertRaisesRegex(ValueError, "stale, forged"):
                lms.sign_with_reservation(keypair, b"replay", reservation)

    def test_lms_failed_signing_keeps_reservation_blocked_after_restore(self) -> None:
        keypair = lms.OQSLMSKeyPair(
            mechanism="LMS_SHA256_H10_W4",
            public_key_hex=b"public".hex(),
            secret_key_hex=b"initial".hex(),
        )
        oqs = FakeOQS()
        oqs.fail_sign = True
        with patch.object(lms, "_load_oqs", return_value=oqs):
            reservation = lms.reserve_signing_material(keypair)
            with self.assertRaisesRegex(ValueError, "simulated signing failure"):
                lms.sign_with_reservation(keypair, b"msg", reservation)
        restored = lms.deserialize_keypair(lms.serialize_keypair(keypair))
        self.assertEqual(restored.pending_reservation_id, reservation["reservation_id"])
        with self.assertRaisesRegex(ValueError, "unfinished signing reservation"):
            lms.reserve_signing_material(restored)

    def test_lms_concurrent_reservations_have_only_one_winner(self) -> None:
        keypair = lms.OQSLMSKeyPair(
            mechanism="LMS_SHA256_H10_W4",
            public_key_hex=b"public".hex(),
            secret_key_hex=b"initial".hex(),
        )

        def reserve(_: int) -> bool:
            try:
                lms.reserve_signing_material(keypair)
                return True
            except ValueError:
                return False

        with ThreadPoolExecutor(max_workers=8) as executor:
            results = list(executor.map(reserve, range(8)))
        self.assertEqual(results.count(True), 1)


if __name__ == "__main__":
    unittest.main()
