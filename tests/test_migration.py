from __future__ import annotations

import hashlib
import os
import random
import unittest
from unittest.mock import patch

from qr_blockchain.migration import (
    build_demo_classical_claim_address,
    build_demo_classical_claim_proof,
    build_demo_classical_claim_public_key,
    classical_claim_message_bytes,
    get_classical_claim_verifier,
    list_classical_claim_verifier_statuses,
)
import qr_chain_classical_migration_backend_rsa as rsa_backend
import qr_chain_classical_migration_backend_secp256k1 as secp_backend


def _secp256k1_sign(message: bytes, private_key: int, nonce: int = 7) -> bytes:
    z = int.from_bytes(hashlib.sha256(message).digest(), "big")
    point = secp_backend._point_mul(nonce, secp_backend._G)
    assert point is not None
    r = point[0] % secp_backend._N
    s = (secp_backend._mod_inv(nonce, secp_backend._N) * (z + r * private_key)) % secp_backend._N
    if s > secp_backend._N // 2:
        s = secp_backend._N - s

    def _der_integer(value: int) -> bytes:
        encoded = value.to_bytes((value.bit_length() + 7) // 8 or 1, "big")
        if encoded[0] & 0x80:
            encoded = b"\x00" + encoded
        return b"\x02" + bytes([len(encoded)]) + encoded

    body = _der_integer(r) + _der_integer(s)
    return b"\x30" + bytes([len(body)]) + body


def _is_probable_prime(candidate: int) -> bool:
    if candidate % 2 == 0:
        return False
    small_primes = (3, 5, 7, 11, 13, 17, 19, 23, 29)
    for prime in small_primes:
        if candidate == prime:
            return True
        if candidate % prime == 0:
            return False
    d = candidate - 1
    s = 0
    while d % 2 == 0:
        d //= 2
        s += 1
    for base in (2, 3, 5, 17, 257, 65537):
        if base >= candidate:
            continue
        x = pow(base, d, candidate)
        if x in (1, candidate - 1):
            continue
        for _ in range(s - 1):
            x = pow(x, 2, candidate)
            if x == candidate - 1:
                break
        else:
            return False
    return True


def _generate_probable_prime(bits: int, seed: int) -> int:
    rng = random.Random(seed)
    while True:
        candidate = rng.getrandbits(bits) | (1 << (bits - 1)) | 1
        if _is_probable_prime(candidate):
            return candidate


def _build_rsa_keypair() -> tuple[dict[str, object], int]:
    p = _generate_probable_prime(512, 11)
    q = _generate_probable_prime(512, 23)
    while q == p:
        q = _generate_probable_prime(512, 29)
    modulus = p * q
    phi = (p - 1) * (q - 1)
    exponent = 65537
    private_exponent = pow(exponent, -1, phi)
    return (
        {"modulus_hex": f"{modulus:x}", "exponent": exponent},
        private_exponent,
    )


def _rsa_pkcs1v15_sign(message: bytes, public_key: dict[str, object], private_exponent: int) -> bytes:
    modulus = int(str(public_key["modulus_hex"]), 16)
    digest = hashlib.sha256(message).digest()
    digest_info = rsa_backend._SHA256_DIGESTINFO_PREFIX + digest
    k = (modulus.bit_length() + 7) // 8
    ps = b"\xff" * (k - len(digest_info) - 3)
    encoded_message = b"\x00\x01" + ps + b"\x00" + digest_info
    signature_int = pow(int.from_bytes(encoded_message, "big"), private_exponent, modulus)
    return signature_int.to_bytes(k, "big")


class ClassicalMigrationVerifierTests(unittest.TestCase):
    def test_demo_verifier_accepts_demo_claim(self) -> None:
        verifier = get_classical_claim_verifier("classical_claim_demo_v1")
        public_key = build_demo_classical_claim_public_key("legacy-user")
        message = classical_claim_message_bytes(b"payload")
        proof = build_demo_classical_claim_proof(public_key, message)

        self.assertTrue(verifier.verify_claim(message, proof, public_key))
        self.assertEqual(verifier.address_from_public_key(public_key), build_demo_classical_claim_address(public_key))

    def test_demo_verifier_rejects_tampered_claim(self) -> None:
        verifier = get_classical_claim_verifier("classical_claim_demo_v1")
        public_key = build_demo_classical_claim_public_key("legacy-user")
        proof = build_demo_classical_claim_proof(public_key, classical_claim_message_bytes(b"payload"))

        self.assertFalse(verifier.verify_claim(classical_claim_message_bytes(b"other"), proof, public_key))

    def test_external_migration_provider_reports_missing_backend(self) -> None:
        verifier = get_classical_claim_verifier("ecdsa_secp256k1_migration_v1")
        with patch.dict(
            os.environ,
            {"QR_CHAIN_ECDSA_MIGRATION_BACKEND_MODULE": "missing_ecdsa_migration_backend"},
            clear=False,
        ):
            with self.assertRaisesRegex(ValueError, "missing_ecdsa_migration_backend"):
                verifier.address_from_public_key({"public_key_hex": "abc"})

    def test_lists_migration_provider_statuses(self) -> None:
        statuses = {item["provider_id"]: item for item in list_classical_claim_verifier_statuses()}

        self.assertIn("classical_claim_demo_v1", statuses)
        self.assertIn("ecdsa_secp256k1_migration_v1", statuses)
        self.assertIn("rsa_pkcs1v15_sha256_migration_v1", statuses)
        self.assertTrue(statuses["classical_claim_demo_v1"]["available"])

    def test_real_secp256k1_verifier_accepts_valid_claim(self) -> None:
        verifier = get_classical_claim_verifier("ecdsa_secp256k1_migration_v1")
        private_key = 1
        public_point = secp_backend._point_mul(private_key, secp_backend._G)
        assert public_point is not None
        public_key_bytes = b"\x04" + public_point[0].to_bytes(32, "big") + public_point[1].to_bytes(32, "big")
        public_key = {"public_key_hex": public_key_bytes.hex()}
        message = classical_claim_message_bytes(b"claim-payload")
        signature = _secp256k1_sign(message, private_key)

        self.assertTrue(
            verifier.verify_claim(message, {"signature_hex": signature.hex()}, public_key)
        )
        self.assertTrue(verifier.address_from_public_key(public_key).startswith("secp256k1-p2pkh:"))
        self.assertTrue(
            verifier.verify_source_address_ownership(
                public_key,
                source_address=secp_backend.derive_bitcoin_p2pkh_addresses(public_key)[0],
                source_address_format="bitcoin_base58",
                source_network="legacy-btc-mainnet",
            )
        )
        self.assertTrue(
            verifier.verify_source_address_ownership(
                public_key,
                source_address=secp_backend.derive_ethereum_eoa_address(public_key),
                source_address_format="ethereum_eoa",
                source_network="legacy-eth-mainnet",
            )
        )
        self.assertTrue(
            verifier.verify_source_address_ownership(
                public_key,
                source_address=secp_backend.derive_bitcoin_p2sh_p2wpkh_address(public_key),
                source_address_format="bitcoin_p2sh_p2wpkh",
                source_network="legacy-btc-mainnet",
            )
        )

    def test_real_secp256k1_verifier_rejects_mismatched_external_source_address(self) -> None:
        verifier = get_classical_claim_verifier("ecdsa_secp256k1_migration_v1")
        private_key = 1
        public_point = secp_backend._point_mul(private_key, secp_backend._G)
        assert public_point is not None
        public_key_bytes = b"\x04" + public_point[0].to_bytes(32, "big") + public_point[1].to_bytes(32, "big")
        public_key = {"public_key_hex": public_key_bytes.hex()}

        self.assertFalse(
            verifier.verify_source_address_ownership(
                public_key,
                source_address="1BoatSLRHtKNngkdXEeobR76b53LETtpyT",
                source_address_format="bitcoin_base58",
                source_network="legacy-btc-mainnet",
            )
        )

    def test_real_rsa_verifier_accepts_valid_claim(self) -> None:
        verifier = get_classical_claim_verifier("rsa_pkcs1v15_sha256_migration_v1")
        public_key, private_exponent = _build_rsa_keypair()
        message = classical_claim_message_bytes(b"claim-payload")
        signature = _rsa_pkcs1v15_sign(message, public_key, private_exponent)

        self.assertTrue(verifier.verify_claim(message, {"signature_hex": signature.hex()}, public_key))
        self.assertTrue(verifier.address_from_public_key(public_key).startswith("rsa-pkcs1v15:"))


if __name__ == "__main__":
    unittest.main()
