from __future__ import annotations

import unittest

from qr_blockchain.crypto import get_signature_provider


class MLDSA65RuntimeHardeningTests(unittest.TestCase):
    """Live liboqs integration checks; these are not a substitute for NIST ACVP KATs."""

    def test_live_backend_round_trip_and_rejects_tampering(self) -> None:
        provider = get_signature_provider("mldsa65_oqs_v1")
        status = provider.backend_status()
        if not status.get("available", False):
            self.skipTest(
                "ML-DSA-65 OQS runtime unavailable: "
                + str(status.get("error", status.get("notes", "backend unavailable")))
            )

        self.assertEqual(status.get("selected_mechanism"), "ML-DSA-65")
        self.assertIn("FIPS 204", str(status.get("standardization", "")))

        keypair = provider.generate_keypair()
        message = b"QBC ML-DSA-65 hardening test v1"
        public_key, signature = provider.sign(keypair, message)

        self.assertEqual(provider.derive_address(keypair), provider.address_from_public_key(public_key))
        self.assertTrue(provider.verify(message, signature, public_key))
        self.assertFalse(provider.verify(message + b"!", signature, public_key))

        other_keypair = provider.generate_keypair()
        other_public_key = provider.export_public_key(other_keypair)
        self.assertFalse(provider.verify(message, signature, other_public_key))

    def test_malformed_signature_is_rejected_not_raised(self) -> None:
        provider = get_signature_provider("mldsa65_oqs_v1")
        self.assertFalse(
            provider.verify(
                b"message",
                {"library": "oqs", "mechanism": "ML-DSA-65", "signature_hex": "not-hex"},
                {
                    "library": "oqs",
                    "mechanism": "ML-DSA-65",
                    "public_key_hex": "not-hex",
                },
            )
        )


if __name__ == "__main__":
    unittest.main()
