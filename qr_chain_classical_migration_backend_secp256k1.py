from __future__ import annotations

import hashlib


_P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
_A = 0
_B = 7
_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
_GX = 55066263022277343669578718895168534326250603453777594175500187360389116729240
_GY = 32670510020758816978083085130507043184471273380659243275938904335757337482424
_G = (_GX, _GY)


def _hash160(data: bytes) -> str:
    sha = hashlib.sha256(data).digest()
    try:
        ripemd = hashlib.new("ripemd160")
        ripemd.update(sha)
        return ripemd.hexdigest()
    except ValueError:
        return hashlib.sha256(b"ripemd160-fallback:" + sha).hexdigest()[:40]


def _mod_inv(value: int, modulus: int) -> int:
    return pow(value, modulus - 2, modulus)


def _is_on_curve(point: tuple[int, int] | None) -> bool:
    if point is None:
        return True
    x, y = point
    return (y * y - (x * x * x + _A * x + _B)) % _P == 0


def _point_add(left: tuple[int, int] | None, right: tuple[int, int] | None) -> tuple[int, int] | None:
    if left is None:
        return right
    if right is None:
        return left
    x1, y1 = left
    x2, y2 = right
    if x1 == x2 and (y1 + y2) % _P == 0:
        return None
    if left == right:
        slope = ((3 * x1 * x1 + _A) * _mod_inv((2 * y1) % _P, _P)) % _P
    else:
        slope = ((y2 - y1) * _mod_inv((x2 - x1) % _P, _P)) % _P
    x3 = (slope * slope - x1 - x2) % _P
    y3 = (slope * (x1 - x3) - y1) % _P
    point = (x3, y3)
    if not _is_on_curve(point):
        raise ValueError("Computed secp256k1 point is invalid.")
    return point


def _point_mul(scalar: int, point: tuple[int, int] | None) -> tuple[int, int] | None:
    result = None
    addend = point
    value = scalar
    while value:
        if value & 1:
            result = _point_add(result, addend)
        addend = _point_add(addend, addend)
        value >>= 1
    return result


def _sqrt_mod(value: int) -> int:
    return pow(value, (_P + 1) // 4, _P)


def _parse_public_key(public_key: object) -> bytes:
    if not isinstance(public_key, dict):
        raise ValueError("secp256k1 migration public key must be an object.")
    public_key_hex = str(public_key.get("public_key_hex", ""))
    if not public_key_hex:
        raise ValueError("secp256k1 migration public key is missing public_key_hex.")
    return bytes.fromhex(public_key_hex)


def _decode_point(public_key_bytes: bytes) -> tuple[int, int]:
    if len(public_key_bytes) == 33 and public_key_bytes[0] in (2, 3):
        x = int.from_bytes(public_key_bytes[1:], "big")
        alpha = (pow(x, 3, _P) + 7) % _P
        beta = _sqrt_mod(alpha)
        y = beta if beta % 2 == public_key_bytes[0] % 2 else (_P - beta)
        point = (x, y)
    elif len(public_key_bytes) == 65 and public_key_bytes[0] == 4:
        x = int.from_bytes(public_key_bytes[1:33], "big")
        y = int.from_bytes(public_key_bytes[33:], "big")
        point = (x, y)
    else:
        raise ValueError("Unsupported secp256k1 public key encoding.")
    if not _is_on_curve(point):
        raise ValueError("secp256k1 public key is not on curve.")
    return point


def _parse_der_signature(signature_bytes: bytes) -> tuple[int, int]:
    if len(signature_bytes) < 8 or signature_bytes[0] != 0x30:
        raise ValueError("ECDSA signature is not valid DER.")
    total_length = signature_bytes[1]
    if total_length + 2 != len(signature_bytes):
        raise ValueError("ECDSA signature DER length is invalid.")
    if signature_bytes[2] != 0x02:
        raise ValueError("ECDSA signature DER is missing r.")
    r_length = signature_bytes[3]
    r_start = 4
    r_end = r_start + r_length
    if r_end >= len(signature_bytes) or signature_bytes[r_end] != 0x02:
        raise ValueError("ECDSA signature DER is missing s.")
    s_length = signature_bytes[r_end + 1]
    s_start = r_end + 2
    s_end = s_start + s_length
    if s_end != len(signature_bytes):
        raise ValueError("ECDSA signature DER trailing bytes are invalid.")
    r = int.from_bytes(signature_bytes[r_start:r_end], "big")
    s = int.from_bytes(signature_bytes[s_start:s_end], "big")
    if not (1 <= r < _N and 1 <= s < _N):
        raise ValueError("ECDSA signature values are out of range.")
    return r, s


def verify_claim(message: bytes, proof: object, public_key: object) -> bool:
    if not isinstance(proof, dict):
        return False
    signature_hex = str(proof.get("signature_hex", ""))
    if not signature_hex:
        return False
    try:
        public_key_bytes = _parse_public_key(public_key)
        point = _decode_point(public_key_bytes)
        r, s = _parse_der_signature(bytes.fromhex(signature_hex))
    except ValueError:
        return False
    digest = hashlib.sha256(message).digest()
    z = int.from_bytes(digest, "big")
    w = _mod_inv(s, _N)
    u1 = (z * w) % _N
    u2 = (r * w) % _N
    point_result = _point_add(_point_mul(u1, _G), _point_mul(u2, point))
    if point_result is None:
        return False
    x, _ = point_result
    return (x % _N) == r


def address_from_public_key(public_key: object) -> str:
    public_key_bytes = _parse_public_key(public_key)
    return f"secp256k1-p2pkh:{_hash160(public_key_bytes)}"


def backend_info() -> dict[str, object]:
    return {
        "status": "available",
        "backend_module": __name__,
        "backend_name": "pure_python_secp256k1_migration_verifier",
        "algorithm_family": "ecdsa",
        "supports_claim_verification": True,
    }
