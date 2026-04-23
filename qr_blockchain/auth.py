from __future__ import annotations

from dataclasses import dataclass
import hashlib
import os
import secrets
import time
from pathlib import Path

from .config import NodeConfig
from .crypto import get_signature_provider, get_signature_verifier
from .custody import WalletCustodyConfig
from .models import canonical_json
from .network import normalize_peer_url
from .wallet_store import SQLiteWalletStateStore


def auth_message_bytes(purpose: str, claims: dict[str, object]) -> bytes:
    return canonical_json({"purpose": purpose, "claims": claims}).encode("utf-8")


def request_claims_digest(request_claims: dict[str, object]) -> str:
    return hashlib.sha256(canonical_json(request_claims).encode("utf-8")).hexdigest()


@dataclass
class NodeIdentityManager:
    config: NodeConfig
    provider_id: str
    state_db_path: Path

    def __post_init__(self) -> None:
        self._provider = get_signature_provider(self.provider_id)
        self._store = SQLiteWalletStateStore(
            self.state_db_path,
            custody_config=WalletCustodyConfig(
                mode=self.config.wallet_custody_mode,
                scope=self.config.wallet_custody_scope,
            ),
            reservation_ttl_seconds=self.config.wallet_reservation_ttl_seconds,
        )
        self._label = f"__node_identity__:{self.config.node_id}"
        self._owner_id = f"node-identity:{self.config.node_id}:{os.getpid()}:{secrets.token_hex(8)}"
        self._key_address: str | None = None
        self._keypair: object | None = None
        self._load_or_create_identity()

    def _load_or_create_identity(self) -> None:
        keys = self._store.load_wallet_keys(self._label, self.provider_id)
        if keys:
            address, payload = keys[0]
            self._key_address = address
            self._keypair = self._provider.deserialize_keypair(payload)
            return

        keypair = self._provider.generate_keypair()
        address = self._provider.derive_address(keypair)
        self._store.save_wallet_key(
            self._label,
            address,
            self.provider_id,
            self._provider.serialize_keypair(keypair),
        )
        self._key_address = address
        self._keypair = keypair

    def public_identity(self) -> dict[str, object]:
        if self._keypair is None or self._key_address is None:
            raise ValueError("Node identity is not initialized.")
        return {
            "node_id": self.config.node_id,
            "chain_id": self.config.chain_id,
            "advertised_url": normalize_peer_url(self.config.advertised_url),
            "signature_scheme": self._provider.metadata.scheme_id,
            "signature_provider": self._provider.metadata.provider_id,
            "address": self._key_address,
            "public_key": self._provider.export_public_key(self._keypair),
        }

    def custody_status(self) -> dict[str, object]:
        return self._store.custody_status()

    def reservation_status_counts(self) -> dict[str, int]:
        return self._store.reservation_status_counts()

    def sign_claims(self, purpose: str, claims: dict[str, object]) -> dict[str, object]:
        if self._keypair is None or self._key_address is None:
            raise ValueError("Node identity is not initialized.")

        claims = dict(claims)
        claims.setdefault("node_id", self.config.node_id)
        claims.setdefault("chain_id", self.config.chain_id)
        claims.setdefault("advertised_url", normalize_peer_url(self.config.advertised_url))
        claims.setdefault("timestamp", int(time.time()))
        claims.setdefault("nonce", secrets.token_hex(16))

        message = auth_message_bytes(purpose, claims)

        def reserve_fn(current_state: object) -> tuple[object, object]:
            keypair = self._provider.deserialize_keypair(current_state)
            reservation = self._provider.reserve_signing_material(keypair)
            return self._provider.serialize_keypair(keypair), reservation

        next_state, reservation, reservation_id = self._store.reserve_wallet_key_state(
            self._label,
            self._key_address,
            self.provider_id,
            reserve_fn,
            owner_id=self._owner_id,
        )
        self._keypair = self._provider.deserialize_keypair(next_state)
        try:
            public_key, signature = self._provider.sign_with_reservation(self._keypair, message, reservation)
            self._store.complete_wallet_key_reservation(
                self._label,
                self._key_address,
                self.provider_id,
                reservation_id,
                self._provider.serialize_keypair(self._keypair),
                owner_id=self._owner_id,
            )
        except Exception as error:
            self._store.fail_wallet_key_reservation(
                self._label,
                self._key_address,
                self.provider_id,
                reservation_id,
                owner_id=self._owner_id,
                error_message=str(error),
            )
            raise

        return {
            "purpose": purpose,
            "claims": claims,
            "signature_scheme": self._provider.metadata.scheme_id,
            "signature_provider": self._provider.metadata.provider_id,
            "address": self._key_address,
            "public_key": public_key,
            "signature": signature,
        }


def verify_signed_envelope(
    envelope: dict[str, object],
    *,
    expected_purpose: str,
    expected_chain_id: str,
    time_skew_seconds: int,
) -> dict[str, object]:
    if str(envelope.get("purpose", "")) != expected_purpose:
        raise ValueError("Auth purpose mismatch.")

    claims = envelope.get("claims", {})
    if not isinstance(claims, dict):
        raise ValueError("Auth claims must be an object.")
    if str(claims.get("chain_id", "")) != expected_chain_id:
        raise ValueError("Auth chain mismatch.")

    timestamp = int(claims.get("timestamp", 0))
    if abs(int(time.time()) - timestamp) > time_skew_seconds:
        raise ValueError("Auth timestamp outside allowed skew.")

    scheme_id = str(envelope.get("signature_scheme", ""))
    provider = get_signature_verifier(scheme_id)
    public_key = envelope.get("public_key", {})
    address = provider.address_from_public_key(public_key)
    if address != str(envelope.get("address", "")):
        raise ValueError("Auth address does not match public key.")

    message = auth_message_bytes(expected_purpose, claims)
    if not provider.verify(message, envelope.get("signature", {}), public_key):
        raise ValueError("Auth signature verification failed.")

    return {
        "node_id": str(claims.get("node_id", "")),
        "chain_id": str(claims.get("chain_id", "")),
        "advertised_url": normalize_peer_url(str(claims.get("advertised_url", ""))),
        "nonce": str(claims.get("nonce", "")),
        "claims": dict(claims),
        "address": address,
        "signature_scheme": scheme_id,
        "signature_provider": str(envelope.get("signature_provider", "")),
        "public_key": public_key,
    }
