from __future__ import annotations

from dataclasses import dataclass

from .lamport import LamportKeyPair, address_from_public_key, verify_signature


@dataclass(frozen=True)
class SignatureSuite:
    suite_id: str

    def generate_keypair(self) -> LamportKeyPair:
        if self.suite_id != "hash_lamport_v1":
            raise ValueError(f"Unsupported signature suite: {self.suite_id}")
        return LamportKeyPair.generate()

    def sign(self, keypair: LamportKeyPair, message: bytes) -> list[str]:
        if self.suite_id != "hash_lamport_v1":
            raise ValueError(f"Unsupported signature suite: {self.suite_id}")
        return keypair.sign(message)

    def verify(self, message: bytes, signature: list[str], public_key: list[list[str]]) -> bool:
        if self.suite_id != "hash_lamport_v1":
            return False
        return verify_signature(message, signature, public_key)

    def address_from_public_key(self, public_key: list[list[str]]) -> str:
        if self.suite_id != "hash_lamport_v1":
            raise ValueError(f"Unsupported signature suite: {self.suite_id}")
        return address_from_public_key(public_key)


SUPPORTED_SIGNATURE_SUITES: dict[str, SignatureSuite] = {
    "hash_lamport_v1": SignatureSuite("hash_lamport_v1"),
}


def get_signature_suite(suite_id: str) -> SignatureSuite:
    try:
        return SUPPORTED_SIGNATURE_SUITES[suite_id]
    except KeyError as error:
        raise ValueError(f"Unsupported signature suite: {suite_id}") from error
