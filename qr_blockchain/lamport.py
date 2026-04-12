from __future__ import annotations

from dataclasses import dataclass
import hashlib
import secrets


HASH_BYTES = 32
HASH_BITS = HASH_BYTES * 8


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def bits_from_digest(digest: bytes) -> list[int]:
    return [int(bit) for byte in digest for bit in f"{byte:08b}"]


@dataclass(frozen=True)
class LamportKeyPair:
    private_key: tuple[tuple[str, str], ...]
    public_key: tuple[tuple[str, str], ...]

    @staticmethod
    def generate() -> "LamportKeyPair":
        private_rows: list[tuple[str, str]] = []
        public_rows: list[tuple[str, str]] = []

        for _ in range(HASH_BITS):
            left_secret = secrets.token_hex(HASH_BYTES)
            right_secret = secrets.token_hex(HASH_BYTES)
            private_rows.append((left_secret, right_secret))
            public_rows.append(
                (
                    sha256_hex(bytes.fromhex(left_secret)),
                    sha256_hex(bytes.fromhex(right_secret)),
                )
            )

        return LamportKeyPair(tuple(private_rows), tuple(public_rows))

    def sign(self, message: bytes) -> list[str]:
        digest_bits = bits_from_digest(sha256(message))
        return [
            self.private_key[index][bit]
            for index, bit in enumerate(digest_bits)
        ]

    def address(self) -> str:
        serialized = "".join(left + right for left, right in self.public_key)
        return sha256_hex(serialized.encode("ascii"))


def verify_signature(message: bytes, signature: list[str], public_key: list[list[str]] | tuple[tuple[str, str], ...]) -> bool:
    if len(signature) != HASH_BITS or len(public_key) != HASH_BITS:
        return False

    digest_bits = bits_from_digest(sha256(message))
    normalized_public_key = [tuple(row) for row in public_key]

    for index, bit in enumerate(digest_bits):
        expected_hash = normalized_public_key[index][bit]
        if sha256_hex(bytes.fromhex(signature[index])) != expected_hash:
            return False

    return True
