from __future__ import annotations

import unittest

from qr_blockchain.crypto import get_signature_provider, get_signature_verifier


class XMSSVerificationHardeningTests(unittest.TestCase):
    def setUp(self) -> None:
        self.provider = get_signature_provider("xmss_merkle_lamport_v1")
        self.verifier = get_signature_verifier("xmss_merkle_lamport_v1")
        keypair = self.provider.generate_keypair()
        self.public_key, self.signature = self.provider.sign(keypair, b"verification-boundary-test")

    def test_rejects_index_that_aliases_a_leaf_above_tree_capacity(self) -> None:
        height = self.public_key["height"]
        forged = dict(self.signature)
        forged["leaf_index"] = self.signature["leaf_index"] + (1 << height)
        self.assertFalse(self.verifier.verify(b"verification-boundary-test", forged, self.public_key))

    def test_rejects_index_at_tree_capacity(self) -> None:
        forged = dict(self.signature)
        forged["leaf_index"] = 1 << self.public_key["height"]
        self.assertFalse(self.verifier.verify(b"verification-boundary-test", forged, self.public_key))

    def test_rejects_authentication_path_with_wrong_depth(self) -> None:
        forged = dict(self.signature)
        forged["auth_path"] = list(self.signature["auth_path"][:-1])
        self.assertFalse(self.verifier.verify(b"verification-boundary-test", forged, self.public_key))

        forged["auth_path"] = list(self.signature["auth_path"]) + ["00" * 32]
        self.assertFalse(self.verifier.verify(b"verification-boundary-test", forged, self.public_key))

    def test_malformed_index_and_key_metadata_fail_closed(self) -> None:
        for bad_index in ("0", None, True, -1):
            with self.subTest(leaf_index=bad_index):
                forged = dict(self.signature)
                forged["leaf_index"] = bad_index
                self.assertFalse(self.verifier.verify(b"verification-boundary-test", forged, self.public_key))

        for bad_height in ("4", None, True, 0, 65):
            with self.subTest(height=bad_height):
                forged_public_key = dict(self.public_key)
                forged_public_key["height"] = bad_height
                self.assertFalse(self.verifier.verify(b"verification-boundary-test", self.signature, forged_public_key))

    def test_valid_signature_still_verifies(self) -> None:
        self.assertTrue(self.verifier.verify(b"verification-boundary-test", self.signature, self.public_key))


if __name__ == "__main__":
    unittest.main()
