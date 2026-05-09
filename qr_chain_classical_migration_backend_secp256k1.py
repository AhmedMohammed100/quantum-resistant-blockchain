from __future__ import annotations

import hashlib


_P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
_A = 0
_B = 7
_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
_GX = 55066263022277343669578718895168534326250603453777594175500187360389116729240
_GY = 32670510020758816978083085130507043184471273380659243275938904335757337482424
_G = (_GX, _GY)
_BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_BECH32_ALPHABET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
_BECH32_GENERATOR = [0x3b6a57b2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3]
_KECCAK_ROUND_CONSTANTS = [
    0x0000000000000001,
    0x0000000000008082,
    0x800000000000808A,
    0x8000000080008000,
    0x000000000000808B,
    0x0000000080000001,
    0x8000000080008081,
    0x8000000000008009,
    0x000000000000008A,
    0x0000000000000088,
    0x0000000080008009,
    0x000000008000000A,
    0x000000008000808B,
    0x800000000000008B,
    0x8000000000008089,
    0x8000000000008003,
    0x8000000000008002,
    0x8000000000000080,
    0x000000000000800A,
    0x800000008000000A,
    0x8000000080008081,
    0x8000000000008080,
    0x0000000080000001,
    0x8000000080008008,
]
_KECCAK_ROTATIONS = [
    [0, 36, 3, 41, 18],
    [1, 44, 10, 45, 2],
    [62, 6, 43, 15, 61],
    [28, 55, 25, 21, 56],
    [27, 20, 39, 8, 14],
]


def _hash160(data: bytes) -> str:
    sha = hashlib.sha256(data).digest()
    try:
        ripemd = hashlib.new("ripemd160")
        ripemd.update(sha)
        return ripemd.hexdigest()
    except ValueError:
        return hashlib.sha256(b"ripemd160-fallback:" + sha).hexdigest()[:40]


def _hash160_bytes(data: bytes) -> bytes:
    return bytes.fromhex(_hash160(data))


def _double_sha256(data: bytes) -> bytes:
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()


def _base58check_encode(payload: bytes) -> str:
    full = payload + _double_sha256(payload)[:4]
    value = int.from_bytes(full, "big")
    encoded = ""
    while value:
        value, remainder = divmod(value, 58)
        encoded = _BASE58_ALPHABET[remainder] + encoded
    leading_zeroes = len(full) - len(full.lstrip(b"\x00"))
    return ("1" * leading_zeroes) + (encoded or "1")


def _bech32_polymod(values: list[int]) -> int:
    checksum = 1
    for value in values:
        top = checksum >> 25
        checksum = ((checksum & 0x1FFFFFF) << 5) ^ value
        for index in range(5):
            if (top >> index) & 1:
                checksum ^= _BECH32_GENERATOR[index]
    return checksum


def _bech32_hrp_expand(hrp: str) -> list[int]:
    return [ord(char) >> 5 for char in hrp] + [0] + [ord(char) & 31 for char in hrp]


def _bech32_create_checksum(hrp: str, data: list[int]) -> list[int]:
    values = _bech32_hrp_expand(hrp) + data
    polymod = _bech32_polymod(values + [0, 0, 0, 0, 0, 0]) ^ 1
    return [(polymod >> 5 * (5 - index)) & 31 for index in range(6)]


def _bech32_encode(hrp: str, data: list[int]) -> str:
    combined = data + _bech32_create_checksum(hrp, data)
    return hrp + "1" + "".join(_BECH32_ALPHABET[value] for value in combined)


def _convert_bits(data: bytes, from_bits: int, to_bits: int) -> list[int]:
    accumulator = 0
    bits = 0
    values: list[int] = []
    max_value = (1 << to_bits) - 1
    for value in data:
        accumulator = (accumulator << from_bits) | value
        bits += from_bits
        while bits >= to_bits:
            bits -= to_bits
            values.append((accumulator >> bits) & max_value)
    if bits:
        values.append((accumulator << (to_bits - bits)) & max_value)
    return values


def _rotl(value: int, shift: int) -> int:
    return ((value << shift) | (value >> (64 - shift))) & ((1 << 64) - 1)


def _keccak_f1600(state: list[int]) -> None:
    for round_constant in _KECCAK_ROUND_CONSTANTS:
        c = [state[x] ^ state[x + 5] ^ state[x + 10] ^ state[x + 15] ^ state[x + 20] for x in range(5)]
        d = [c[(x - 1) % 5] ^ _rotl(c[(x + 1) % 5], 1) for x in range(5)]
        for x in range(5):
            for y in range(5):
                state[x + 5 * y] ^= d[x]
        b = [0] * 25
        for x in range(5):
            for y in range(5):
                b[y + 5 * ((2 * x + 3 * y) % 5)] = _rotl(state[x + 5 * y], _KECCAK_ROTATIONS[x][y])
        for x in range(5):
            for y in range(5):
                state[x + 5 * y] = b[x + 5 * y] ^ ((~b[((x + 1) % 5) + 5 * y]) & b[((x + 2) % 5) + 5 * y])
        state[0] ^= round_constant


def _keccak_256(data: bytes) -> bytes:
    rate_bytes = 136
    state = [0] * 25
    padded = bytearray(data)
    padded.append(0x01)
    while (len(padded) % rate_bytes) != rate_bytes - 1:
        padded.append(0x00)
    padded.append(0x80)
    for offset in range(0, len(padded), rate_bytes):
        block = padded[offset : offset + rate_bytes]
        for index, value in enumerate(block):
            state[index // 8] ^= value << (8 * (index % 8))
        _keccak_f1600(state)
    output = bytearray()
    while len(output) < 32:
        for lane in state[: rate_bytes // 8]:
            output.extend(lane.to_bytes(8, "little"))
            if len(output) >= 32:
                break
        if len(output) < 32:
            _keccak_f1600(state)
    return bytes(output[:32])


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


def _compressed_public_key(point: tuple[int, int]) -> bytes:
    x, y = point
    prefix = 0x02 if y % 2 == 0 else 0x03
    return bytes([prefix]) + x.to_bytes(32, "big")


def _uncompressed_public_key(point: tuple[int, int]) -> bytes:
    x, y = point
    return b"\x04" + x.to_bytes(32, "big") + y.to_bytes(32, "big")


def derive_bitcoin_p2pkh_addresses(public_key: object) -> list[str]:
    public_key_bytes = _parse_public_key(public_key)
    point = _decode_point(public_key_bytes)
    compressed = _compressed_public_key(point)
    uncompressed = _uncompressed_public_key(point)
    return [
        _base58check_encode(b"\x00" + _hash160_bytes(compressed)),
        _base58check_encode(b"\x00" + _hash160_bytes(uncompressed)),
    ]


def derive_bitcoin_p2wpkh_address(public_key: object) -> str:
    public_key_bytes = _parse_public_key(public_key)
    point = _decode_point(public_key_bytes)
    witness_program = _hash160_bytes(_compressed_public_key(point))
    return _bech32_encode("bc", [0] + _convert_bits(witness_program, 8, 5))


def derive_bitcoin_p2sh_p2wpkh_address(public_key: object) -> str:
    public_key_bytes = _parse_public_key(public_key)
    point = _decode_point(public_key_bytes)
    witness_program = _hash160_bytes(_compressed_public_key(point))
    redeem_script = b"\x00\x14" + witness_program
    script_hash = _hash160_bytes(redeem_script)
    return _base58check_encode(b"\x05" + script_hash)


def derive_ethereum_eoa_address(public_key: object) -> str:
    public_key_bytes = _parse_public_key(public_key)
    point = _decode_point(public_key_bytes)
    uncompressed = _uncompressed_public_key(point)[1:]
    digest = _keccak_256(uncompressed)
    return "0x" + digest[-20:].hex()


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


def verify_source_address_ownership(
    public_key: object,
    *,
    source_address: str,
    source_address_format: str,
    source_network: str,
) -> bool:
    if source_address_format == "secp256k1_claim_address":
        return address_from_public_key(public_key) == source_address
    if source_address_format == "bitcoin_base58":
        return source_address in derive_bitcoin_p2pkh_addresses(public_key)
    if source_address_format == "bitcoin_bech32":
        return derive_bitcoin_p2wpkh_address(public_key).lower() == source_address.lower()
    if source_address_format == "bitcoin_p2sh_p2wpkh":
        return derive_bitcoin_p2sh_p2wpkh_address(public_key) == source_address
    if source_address_format == "ethereum_eoa":
        return derive_ethereum_eoa_address(public_key).lower() == source_address.lower()
    return False


def backend_info() -> dict[str, object]:
    return {
        "status": "available",
        "backend_module": __name__,
        "backend_name": "pure_python_secp256k1_migration_verifier",
        "algorithm_family": "ecdsa",
        "supports_claim_verification": True,
        "supports_source_address_ownership": True,
        "source_address_formats": [
            "secp256k1_claim_address",
            "bitcoin_base58",
            "bitcoin_bech32",
            "bitcoin_p2sh_p2wpkh",
            "ethereum_eoa",
        ],
    }
