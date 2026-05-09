from __future__ import annotations

from dataclasses import dataclass
import hashlib
import re


_BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_BASE58_INDEX = {char: index for index, char in enumerate(_BASE58_ALPHABET)}
_HEX_40 = re.compile(r"^[0-9a-fA-F]{40}$")
_HEX_64 = re.compile(r"^[0-9a-f]{64}$")
_HEX_40_LOWER = re.compile(r"^[0-9a-f]{40}$")
_BECH32_ALPHABET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
_BECH32_INDEX = {char: index for index, char in enumerate(_BECH32_ALPHABET)}


@dataclass(frozen=True)
class LegacyNetworkProfile:
    network_id: str
    description: str
    allowed_provider_ids: tuple[str, ...]
    accepted_address_formats: tuple[str, ...]

    def to_dict(self) -> dict[str, object]:
        return {
            "network_id": self.network_id,
            "description": self.description,
            "allowed_provider_ids": list(self.allowed_provider_ids),
            "accepted_address_formats": list(self.accepted_address_formats),
        }


NETWORK_PROFILES: dict[str, LegacyNetworkProfile] = {
    "legacy-btc-mainnet": LegacyNetworkProfile(
        network_id="legacy-btc-mainnet",
        description="Bitcoin-style migration source profile with base58 or bech32 legacy addresses.",
        allowed_provider_ids=("ecdsa_secp256k1_migration_v1",),
        accepted_address_formats=(
            "bitcoin_base58",
            "bitcoin_bech32",
            "bitcoin_p2sh_p2wpkh",
            "secp256k1_claim_address",
        ),
    ),
    "legacy-eth-mainnet": LegacyNetworkProfile(
        network_id="legacy-eth-mainnet",
        description="Ethereum-style migration source profile with EOA hex addresses.",
        allowed_provider_ids=("ecdsa_secp256k1_migration_v1",),
        accepted_address_formats=("ethereum_eoa", "secp256k1_claim_address"),
    ),
    "legacy-rsa-ledger": LegacyNetworkProfile(
        network_id="legacy-rsa-ledger",
        description="RSA-based legacy ledger profile using RSA ownership proofs and fingerprint addresses.",
        allowed_provider_ids=("rsa_pkcs1v15_sha256_migration_v1",),
        accepted_address_formats=("rsa_fingerprint",),
    ),
    "legacy-demo-ledger": LegacyNetworkProfile(
        network_id="legacy-demo-ledger",
        description="Demo migration profile for local and test flows.",
        allowed_provider_ids=("classical_claim_demo_v1",),
        accepted_address_formats=("demo_claim_address",),
    ),
}


def list_legacy_network_profiles() -> list[dict[str, object]]:
    return [profile.to_dict() for profile in NETWORK_PROFILES.values()]


def describe_legacy_network(network_id: str) -> dict[str, object] | None:
    profile = NETWORK_PROFILES.get(network_id)
    return None if profile is None else profile.to_dict()


def _sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def _double_sha256(data: bytes) -> bytes:
    return _sha256(_sha256(data))


def _decode_base58check(value: str) -> bytes:
    accumulator = 0
    for char in value:
        try:
            accumulator = accumulator * 58 + _BASE58_INDEX[char]
        except KeyError as error:
            raise ValueError("Address contains invalid base58 character.") from error
    full = accumulator.to_bytes((accumulator.bit_length() + 7) // 8, "big")
    leading_zeroes = len(value) - len(value.lstrip("1"))
    payload = (b"\x00" * leading_zeroes) + full
    if len(payload) < 5:
        raise ValueError("Base58Check payload is too short.")
    body, checksum = payload[:-4], payload[-4:]
    if _double_sha256(body)[:4] != checksum:
        raise ValueError("Base58Check checksum mismatch.")
    return body


def _bech32_polymod(values: list[int]) -> int:
    generator = [0x3b6a57b2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3]
    checksum = 1
    for value in values:
        top = checksum >> 25
        checksum = ((checksum & 0x1FFFFFF) << 5) ^ value
        for index in range(5):
            if (top >> index) & 1:
                checksum ^= generator[index]
    return checksum


def _bech32_hrp_expand(hrp: str) -> list[int]:
    return [ord(char) >> 5 for char in hrp] + [0] + [ord(char) & 31 for char in hrp]


def _validate_bech32(value: str) -> None:
    if any(ord(char) < 33 or ord(char) > 126 for char in value):
        raise ValueError("Bech32 address contains invalid characters.")
    if value.lower() != value and value.upper() != value:
        raise ValueError("Bech32 address must not mix case.")
    normalized = value.lower()
    separator = normalized.rfind("1")
    if separator < 1 or separator + 7 > len(normalized):
        raise ValueError("Bech32 address separator position is invalid.")
    hrp = normalized[:separator]
    data_part = normalized[separator + 1 :]
    try:
        data = [_BECH32_INDEX[char] for char in data_part]
    except KeyError as error:
        raise ValueError("Bech32 address contains invalid data characters.") from error
    if _bech32_polymod(_bech32_hrp_expand(hrp) + data) not in (1, 0x2BC830A3):
        raise ValueError("Bech32 checksum mismatch.")


def validate_canonical_claim_address(provider_id: str, classical_address: str) -> None:
    if provider_id == "ecdsa_secp256k1_migration_v1":
        if not classical_address.startswith("secp256k1-p2pkh:"):
            raise ValueError("secp256k1 migration claim addresses must use the canonical secp256k1-p2pkh format.")
        fingerprint = classical_address.split(":", 1)[1]
        if not _HEX_40_LOWER.fullmatch(fingerprint):
            raise ValueError("Canonical secp256k1 migration address fingerprint must be 40 lowercase hex characters.")
        return
    if provider_id == "rsa_pkcs1v15_sha256_migration_v1":
        if not classical_address.startswith("rsa-pkcs1v15:"):
            raise ValueError("RSA migration claim addresses must use the canonical rsa-pkcs1v15 format.")
        fingerprint = classical_address.split(":", 1)[1]
        if not _HEX_64.fullmatch(fingerprint):
            raise ValueError("Canonical RSA migration address fingerprint must be 64 lowercase hex characters.")
        return
    if provider_id == "classical_claim_demo_v1":
        if not _HEX_64.fullmatch(classical_address):
            raise ValueError("Demo migration claim addresses must be 64 lowercase hex characters.")
        return


def infer_source_address_format(provider_id: str, source_address: str) -> str:
    if source_address.startswith("secp256k1-p2pkh:"):
        return "secp256k1_claim_address"
    if source_address.startswith("rsa-pkcs1v15:"):
        return "rsa_fingerprint"
    if _HEX_64.fullmatch(source_address) and provider_id == "classical_claim_demo_v1":
        return "demo_claim_address"
    if source_address.startswith("0x") and _HEX_40.fullmatch(source_address[2:]):
        return "ethereum_eoa"
    if source_address.lower().startswith("bc1"):
        return "bitcoin_bech32"
    return "bitcoin_base58"


def validate_source_address_format(source_address: str, source_address_format: str) -> None:
    if source_address_format == "bitcoin_base58":
        payload = _decode_base58check(source_address)
        if payload[0] not in (0x00, 0x05):
            raise ValueError("Bitcoin base58 address version byte is not supported.")
        return
    if source_address_format == "bitcoin_bech32":
        _validate_bech32(source_address)
        if not source_address.lower().startswith("bc1"):
            raise ValueError("Bitcoin bech32 addresses must start with 'bc1'.")
        return
    if source_address_format == "bitcoin_p2sh_p2wpkh":
        payload = _decode_base58check(source_address)
        if payload[0] != 0x05:
            raise ValueError("Nested Bitcoin SegWit addresses must use the mainnet P2SH version byte.")
        return
    if source_address_format == "ethereum_eoa":
        if not source_address.startswith("0x") or not _HEX_40.fullmatch(source_address[2:]):
            raise ValueError("Ethereum EOA addresses must be 0x-prefixed 40-hex strings.")
        return
    if source_address_format == "rsa_fingerprint":
        if not source_address.startswith("rsa-pkcs1v15:") or not _HEX_64.fullmatch(source_address.split(":", 1)[1]):
            raise ValueError("RSA source addresses must use the canonical rsa-pkcs1v15 fingerprint form.")
        return
    if source_address_format == "secp256k1_claim_address":
        if not source_address.startswith("secp256k1-p2pkh:") or not _HEX_40_LOWER.fullmatch(source_address.split(":", 1)[1]):
            raise ValueError("Canonical secp256k1 claim addresses must use the secp256k1-p2pkh form.")
        return
    if source_address_format == "demo_claim_address":
        if not _HEX_64.fullmatch(source_address):
            raise ValueError("Demo claim addresses must be 64 lowercase hex characters.")
        return
    raise ValueError(f"Unsupported source_address_format '{source_address_format}'.")


def validate_legacy_source_binding(
    *,
    source_network: str,
    provider_id: str,
    classical_address: str,
    source_address: str,
    source_address_format: str,
) -> dict[str, object]:
    validate_canonical_claim_address(provider_id, classical_address)
    format_id = source_address_format or infer_source_address_format(provider_id, source_address)
    validate_source_address_format(source_address, format_id)

    profile = NETWORK_PROFILES.get(source_network)
    if profile is not None:
        if provider_id not in profile.allowed_provider_ids:
            raise ValueError(
                f"Source network '{source_network}' does not allow migration provider '{provider_id}'."
            )
        if format_id not in profile.accepted_address_formats:
            raise ValueError(
                f"Source network '{source_network}' does not accept source_address_format '{format_id}'."
            )
    return {
        "source_network": source_network,
        "provider_id": provider_id,
        "classical_address": classical_address,
        "source_address": source_address,
        "source_address_format": format_id,
        "network_profile": None if profile is None else profile.to_dict(),
    }
