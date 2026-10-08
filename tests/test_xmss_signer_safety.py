from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import tempfile
import unittest

from qr_blockchain.crypto import get_signature_verifier
from qr_blockchain.signer import LocalWalletSigner


class XMSSSignerSafetyTests(unittest.TestCase):
    def make_signer(self, db_path: Path) -> LocalWalletSigner:
        return LocalWalletSigner(
            label="xmss-safety-test",
            signature_provider="xmss_merkle_lamport_v1",
            state_db_path=db_path,
            custody_mode="auto",
            custody_scope="current_user",
            reservation_ttl_seconds=60,
        )

    def test_leaf_indices_advance_across_signer_restart(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            db_path = Path(directory) / "wallet-state.sqlite3"
            signer = self.make_signer(db_path)
            address = signer.create_address()

            first = signer.sign_for_address(address, b"first message")
            self.assertEqual(first.signature["leaf_index"], 0)

            restarted = self.make_signer(db_path)
            self.assertIn(address, restarted.addresses())
            second = restarted.sign_for_address(address, b"second message")
            self.assertEqual(second.signature["leaf_index"], 1)

            verifier = get_signature_verifier("xmss_merkle_lamport_v1")
            public_key = verifier.export_public_key(restarted._keys[address])
            self.assertTrue(verifier.verify(b"first message", first.signature, public_key))
            self.assertTrue(verifier.verify(b"second message", second.signature, public_key))

    def test_concurrent_signers_never_return_the_same_leaf(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            db_path = Path(directory) / "wallet-state.sqlite3"
            initial = self.make_signer(db_path)
            address = initial.create_address()
            signers = [self.make_signer(db_path), self.make_signer(db_path)]

            def sign_once(pair: tuple[int, LocalWalletSigner]):
                index, signer = pair
                try:
                    result = signer.sign_for_address(address, f"concurrent-{index}".encode())
                    return result.signature["leaf_index"]
                except ValueError:
                    # A live reservation may reject a simultaneous request. Rejection is safe;
                    # successful operations must still never reuse an index.
                    return None

            with ThreadPoolExecutor(max_workers=2) as executor:
                leaf_indices = list(executor.map(sign_once, enumerate(signers)))

            successful = [index for index in leaf_indices if index is not None]
            self.assertGreaterEqual(len(successful), 1)
            self.assertEqual(len(successful), len(set(successful)))


if __name__ == "__main__":
    unittest.main()
