from __future__ import annotations

import unittest

from qr_chain_xmss_backend import reference_backend


class XmssSecurityTests(unittest.TestCase):
    def test_reference_xmss_rejects_out_of_range_leaf_and_bad_auth_path(self) -> None:
        keypair = reference_backend.generate_keypair(height=2)
        public_key, signature = reference_backend.sign(keypair, b"qbc-test")

        self.assertTrue(reference_backend.verify(b"qbc-test", signature, public_key))

        out_of_range = dict(signature)
        out_of_range["leaf_index"] = 4
        self.assertFalse(reference_backend.verify(b"qbc-test", out_of_range, public_key))

        short_path = dict(signature)
        short_path["auth_path"] = list(signature["auth_path"][:-1])
        self.assertFalse(reference_backend.verify(b"qbc-test", short_path, public_key))

    def test_reference_xmss_rejects_stale_or_invalid_reservations(self) -> None:
        keypair = reference_backend.generate_keypair(height=2)
        reservation = reference_backend.reserve_signing_material(keypair)

        with self.assertRaises(ValueError):
            reference_backend.sign_with_reservation(
                keypair,
                b"qbc-test",
                {"leaf_index": -1},
            )

        with self.assertRaises(ValueError):
            reference_backend.sign_with_reservation(
                keypair,
                b"qbc-test",
                {"leaf_index": 0},
            )

        public_key, signature = reference_backend.sign_with_reservation(
            keypair,
            b"qbc-test",
            reservation,
        )
        self.assertTrue(reference_backend.verify(b"qbc-test", signature, public_key))


if __name__ == "__main__":
    unittest.main()
