from __future__ import annotations

import hashlib


_SHA256_DIGESTINFO_PREFIX = bytes.fromhex("3031300d060960864801650304020105000420")


def _parse_public_key(public_key: object) -> tuple[int, int]:
    if not isinstance(public_key, dict):
        raise ValueError("RSA migration public key must be an object.")
    modulus_hex = str(public_key.get("modulus_hex", ""))
    exponent = int(public_key.get("exponent", 0))
    if not modulus_hex or exponent <= 1:
        raise ValueError("RSA migration public key is incomplete.")
    return int(modulus_hex, 16), exponent


def verify_claim(message: bytes, proof: object, public_key: object) -> bool:
    if not isinstance(proof, dict):
        return False
    signature_hex = str(proof.get("signature_hex", ""))
    if not signature_hex:
        return False
    try:
        modulus, exponent = _parse_public_key(public_key)
    except ValueError:
        return False
    signature_int = int(signature_hex, 16)
    if signature_int <= 0 or signature_int >= modulus:
        return False
    k = (modulus.bit_length() + 7) // 8
    em = pow(signature_int, exponent, modulus).to_bytes(k, "big")
    digest = hashlib.sha256(message).digest()
    expected_t = _SHA256_DIGESTINFO_PREFIX + digest
    ps_length = k - len(expected_t) - 3
    if ps_length < 8:
        return False
    expected_em = b"\x00\x01" + (b"\xff" * ps_length) + b"\x00" + expected_t
    return em == expected_em


def address_from_public_key(public_key: object) -> str:
    modulus, exponent = _parse_public_key(public_key)
    fingerprint = hashlib.sha256(f"rsa:{modulus:x}:{exponent}".encode("utf-8")).hexdigest()
    return f"rsa-pkcs1v15:{fingerprint}"


def backend_info() -> dict[str, object]:
    return {
        "status": "available",
        "backend_module": __name__,
        "backend_name": "pure_python_rsa_pkcs1v15_sha256_migration_verifier",
        "algorithm_family": "rsa",
        "supports_claim_verification": True,
    }
