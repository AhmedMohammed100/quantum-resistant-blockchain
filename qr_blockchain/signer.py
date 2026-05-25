from __future__ import annotations

from dataclasses import dataclass
import os
from pathlib import Path
import secrets
from typing import TYPE_CHECKING, Protocol

from .crypto import SignatureProvider, get_signature_provider
from .custody import WalletCustodyConfig
from .migration import destination_acceptance_message_bytes
from .models import Transaction, TxInput, TxOutput
from .wallet_store import SQLiteWalletStateStore

if TYPE_CHECKING:
    from .service import NodeService


@dataclass(frozen=True)
class SigningResult:
    public_key: object
    signature: object
    reservation_id: str | None = None


class SignerBackend(Protocol):
    def create_address(self) -> str:
        raise NotImplementedError

    def addresses(self) -> list[str]:
        raise NotImplementedError

    def sign_for_address(self, address: str, message: bytes) -> SigningResult:
        raise NotImplementedError

    def signing_status(self) -> dict[str, object]:
        raise NotImplementedError


class LocalWalletSigner:
    """Crash-safe local signer boundary used by wallets, not consensus validation."""

    def __init__(
        self,
        *,
        label: str,
        signature_provider: str,
        state_db_path: Path | None,
        custody_mode: str,
        custody_scope: str,
        reservation_ttl_seconds: int,
    ):
        self.label = label
        self.signature_provider = signature_provider
        self._provider: SignatureProvider = get_signature_provider(signature_provider)
        self._owner_id = f"wallet-signer:{label}:{os.getpid()}:{secrets.token_hex(8)}"
        self._state_store = (
            None
            if state_db_path is None
            else SQLiteWalletStateStore(
                Path(state_db_path),
                custody_config=WalletCustodyConfig(
                    mode=custody_mode,
                    scope=custody_scope,
                ),
                reservation_ttl_seconds=reservation_ttl_seconds,
            )
        )
        self._keys: dict[str, object] = {}
        self._load_persisted_keys()

    @property
    def provider(self) -> SignatureProvider:
        return self._provider

    def _load_persisted_keys(self) -> None:
        if self._state_store is None:
            return
        for address, payload in self._state_store.load_wallet_keys(self.label, self.signature_provider):
            self._keys[address] = self._provider.deserialize_keypair(payload)

    def _persist_key(self, address: str) -> None:
        if self._state_store is None:
            return
        keypair = self._keys[address]
        key_state = self._provider.serialize_keypair(keypair)
        self._state_store.save_wallet_key(self.label, address, self.signature_provider, key_state)

    def _reserve_key_usage(self, address: str) -> tuple[object, object, str | None]:
        if address not in self._keys:
            raise ValueError("Address is not controlled by this signer.")
        if self._state_store is None:
            keypair = self._keys[address]
            reservation = self._provider.reserve_signing_material(keypair)
            return keypair, reservation, None

        def reserve_fn(current_state: object) -> tuple[object, object]:
            keypair = self._provider.deserialize_keypair(current_state)
            reservation = self._provider.reserve_signing_material(keypair)
            return self._provider.serialize_keypair(keypair), reservation

        next_state, reservation, reservation_id = self._state_store.reserve_wallet_key_state(
            self.label,
            address,
            self.signature_provider,
            reserve_fn,
            owner_id=self._owner_id,
        )
        keypair = self._provider.deserialize_keypair(next_state)
        self._keys[address] = keypair
        return keypair, reservation, reservation_id

    def create_address(self) -> str:
        keypair = self._provider.generate_keypair()
        address = self._provider.derive_address(keypair)
        self._keys[address] = keypair
        self._persist_key(address)
        return address

    def addresses(self) -> list[str]:
        return list(self._keys.keys())

    def sign_for_address(self, address: str, message: bytes) -> SigningResult:
        keypair, reservation, reservation_id = self._reserve_key_usage(address)
        try:
            if reservation is not None:
                public_key, signature = self._provider.sign_with_reservation(keypair, message, reservation)
                if self._state_store is not None and reservation_id is not None:
                    self._state_store.complete_wallet_key_reservation(
                        self.label,
                        address,
                        self.signature_provider,
                        reservation_id,
                        self._provider.serialize_keypair(keypair),
                        owner_id=self._owner_id,
                    )
                else:
                    self._persist_key(address)
            else:
                public_key, signature = self._provider.sign(keypair, message)
                self._persist_key(address)
        except Exception as error:
            if self._state_store is not None and reservation_id is not None:
                self._state_store.fail_wallet_key_reservation(
                    self.label,
                    address,
                    self.signature_provider,
                    reservation_id,
                    owner_id=self._owner_id,
                    error_message=str(error),
                )
            raise
        return SigningResult(public_key=public_key, signature=signature, reservation_id=reservation_id)

    def signing_status(self) -> dict[str, object]:
        return {
            "label": self.label,
            "signature_provider": self.signature_provider,
            "signature_scheme": self._provider.metadata.scheme_id,
            "backend": "local_wallet_signer",
            "custody_store": self._state_store is not None,
            "address_count": len(self._keys),
            "separation_boundary": "wallet_signer",
        }


class Wallet:
    def __init__(
        self,
        label: str,
        signature_provider: str = "xmss_merkle_lamport_v1",
        state_db_path: Path | None = None,
        custody_mode: str = "auto",
        custody_scope: str = "current_user",
        reservation_ttl_seconds: int = 60,
        signer: SignerBackend | None = None,
    ):
        self.label = label
        self.signature_provider = signature_provider
        self._signer = signer or LocalWalletSigner(
            label=label,
            signature_provider=signature_provider,
            state_db_path=state_db_path,
            custody_mode=custody_mode,
            custody_scope=custody_scope,
            reservation_ttl_seconds=reservation_ttl_seconds,
        )
        provider = getattr(self._signer, "provider", None)
        self._provider = provider if provider is not None else get_signature_provider(signature_provider)
        self._keys = getattr(self._signer, "_keys", {})
        self._state_store = getattr(self._signer, "_state_store", None)
        self._owner_id = getattr(self._signer, "_owner_id", f"wallet:{label}:external-signer")

    def create_address(self) -> str:
        return self._signer.create_address()

    def addresses(self) -> list[str]:
        return self._signer.addresses()

    def signing_status(self) -> dict[str, object]:
        return self._signer.signing_status()

    def balance(self, service: "NodeService") -> int:
        return service.balance_for_addresses(self.addresses())

    def create_transaction(self, service: "NodeService", recipient: str, amount: int, fee: int = 1) -> Transaction:
        if amount <= 0:
            raise ValueError("Amount must be positive.")
        if fee < 0:
            raise ValueError("Fee cannot be negative.")

        selected, total_input = service.select_inputs(self.addresses(), amount + fee)
        inputs = [TxInput(prev_tx_id=tx_id, output_index=output_index) for tx_id, output_index, _ in selected]
        outputs = [TxOutput(recipient=recipient, amount=amount)]

        change = total_input - amount - fee
        if change > 0:
            outputs.append(TxOutput(recipient=self.create_address(), amount=change))

        transaction = Transaction(
            inputs=inputs,
            outputs=outputs,
            chain_id=service.config.chain_id,
            signature_scheme=self._provider.metadata.scheme_id,
            fee=fee,
        )
        signing_payload = transaction.signing_payload()
        for tx_input, (_, _, previous_output) in zip(transaction.inputs, selected):
            result = self._signer.sign_for_address(previous_output.recipient, signing_payload)
            tx_input.public_key = result.public_key
            tx_input.signature = result.signature
        transaction.finalize()
        return transaction

    def create_migration_claim(
        self,
        service: "NodeService",
        *,
        classical_address: str,
        classical_provider_id: str,
        classical_public_key: object,
        classical_signature: object,
        source_network: str,
        snapshot_ref: str = "",
        destination_address: str | None = None,
        timestamp: float | None = None,
    ) -> Transaction:
        source = service.store.migration_source(classical_address)
        if source is None:
            raise ValueError("Migration source address is unknown.")
        if source["provider_id"] != classical_provider_id:
            raise ValueError("Migration source provider does not match the requested claim provider.")
        if source["source_network"] != source_network:
            raise ValueError("Migration source network does not match the requested claim network.")
        target_address = destination_address or self.create_address()
        if target_address not in self.addresses():
            raise ValueError("Destination address is not controlled by this wallet.")
        transaction = service.build_migration_claim_draft(
            destination_address=target_address,
            classical_address=classical_address,
            classical_provider_id=classical_provider_id,
            source_network=source_network,
            snapshot_ref=snapshot_ref or str(source.get("snapshot_ref", "")),
            classical_public_key=classical_public_key,
            timestamp=timestamp,
        )
        transaction.metadata["classical_signature"] = classical_signature
        if service._migration_dual_control_required(service.store.block_count()):
            transaction.metadata["destination_attestation"] = self._build_destination_attestation(transaction, target_address)
        transaction.finalize()
        return transaction

    def _build_destination_attestation(self, transaction: Transaction, address: str) -> dict[str, object]:
        message = destination_acceptance_message_bytes(transaction.migration_claim_payload())
        result = self._signer.sign_for_address(address, message)
        return {
            "address": address,
            "signature_scheme": self._provider.metadata.scheme_id,
            "public_key": result.public_key,
            "signature": result.signature,
        }
