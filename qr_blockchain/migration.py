from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
import hashlib
import importlib


def classical_claim_message_bytes(payload: bytes) -> bytes:
    return b"classical-claim-v1:" + payload


def destination_acceptance_message_bytes(payload: bytes) -> bytes:
    return b"pq-destination-accept-v1:" + payload


@dataclass(frozen=True)
class ClassicalClaimVerifierMetadata:
    provider_id: str
    algorithm_family: str
    implementation: str
    status: str
    supports_claim_verification: bool
    notes: str = ""


class ClassicalClaimVerifier(ABC):
    metadata: ClassicalClaimVerifierMetadata

    @abstractmethod
    def verify_claim(self, message: bytes, proof: object, public_key: object) -> bool:
        raise NotImplementedError

    @abstractmethod
    def address_from_public_key(self, public_key: object) -> str:
        raise NotImplementedError

    def backend_status(self) -> dict[str, object]:
        return {
            "provider_id": self.metadata.provider_id,
            "algorithm_family": self.metadata.algorithm_family,
            "implementation": self.metadata.implementation,
            "status": self.metadata.status,
            "supports_claim_verification": self.metadata.supports_claim_verification,
            "available": self.metadata.supports_claim_verification,
            "notes": self.metadata.notes,
        }


class DemoClassicalClaimVerifier(ClassicalClaimVerifier):
    metadata = ClassicalClaimVerifierMetadata(
        provider_id="classical_claim_demo_v1",
        algorithm_family="demo",
        implementation="in_repo_reference",
        status="available",
        supports_claim_verification=True,
        notes="Non-production demo verifier used to exercise classical-to-PQ migration flows.",
    )

    def verify_claim(self, message: bytes, proof: object, public_key: object) -> bool:
        if not isinstance(public_key, dict) or not isinstance(proof, dict):
            return False
        public_key_hex = str(public_key.get("public_key_hex", ""))
        signature_hex = str(proof.get("signature_hex", ""))
        expected = hashlib.sha256(b"classical-demo:" + public_key_hex.encode("utf-8") + message).hexdigest()
        return bool(public_key_hex) and signature_hex == expected

    def address_from_public_key(self, public_key: object) -> str:
        if not isinstance(public_key, dict):
            raise ValueError("Demo classical public key must be an object.")
        public_key_hex = str(public_key.get("public_key_hex", ""))
        if not public_key_hex:
            raise ValueError("Demo classical public key is missing public_key_hex.")
        return build_demo_classical_claim_address(public_key)


def build_demo_classical_claim_public_key(seed: str) -> dict[str, object]:
    return {
        "scheme": "classical_claim_demo_v1",
        "public_key_hex": hashlib.sha256(seed.encode("utf-8")).hexdigest(),
    }


def build_demo_classical_claim_address(public_key: object) -> str:
    if not isinstance(public_key, dict):
        raise ValueError("Demo classical public key must be an object.")
    public_key_hex = str(public_key.get("public_key_hex", ""))
    if not public_key_hex:
        raise ValueError("Demo classical public key is missing public_key_hex.")
    return hashlib.sha256(f"classical-demo:{public_key_hex}".encode("utf-8")).hexdigest()


def build_demo_classical_claim_proof(public_key: object, claim_message: bytes) -> dict[str, object]:
    if not isinstance(public_key, dict):
        raise ValueError("Demo classical public key must be an object.")
    public_key_hex = str(public_key.get("public_key_hex", ""))
    return {
        "signature_hex": hashlib.sha256(
            b"classical-demo:" + public_key_hex.encode("utf-8") + claim_message
        ).hexdigest()
    }


class ExternalModuleClassicalClaimVerifier(ClassicalClaimVerifier):
    def __init__(
        self,
        *,
        provider_id: str,
        algorithm_family: str,
        module_env_var: str,
        default_module_path: str,
        notes: str,
    ):
        self.module_env_var = module_env_var
        self.default_module_path = default_module_path
        self.metadata = ClassicalClaimVerifierMetadata(
            provider_id=provider_id,
            algorithm_family=algorithm_family,
            implementation="external_module_adapter",
            status="adapter_ready",
            supports_claim_verification=True,
            notes=notes,
        )

    def _module_path(self) -> str:
        import os

        return os.getenv(self.module_env_var, self.default_module_path)

    def _load_backend(self) -> object:
        module_path = self._module_path()
        try:
            return importlib.import_module(module_path)
        except ModuleNotFoundError as error:
            missing_module = getattr(error, "name", module_path)
            if missing_module == module_path:
                raise ValueError(
                    f"Migration provider {self.metadata.provider_id} requires the optional backend module "
                    f"'{module_path}'."
                ) from error
            raise ValueError(
                f"Migration provider {self.metadata.provider_id} could not load because dependency "
                f"'{missing_module}' required by backend module '{module_path}' is missing."
            ) from error

    def _backend_function(self, name: str):
        backend = self._load_backend()
        function = getattr(backend, name, None)
        if not callable(function):
            raise ValueError(
                f"Backend module '{self._module_path()}' for migration provider {self.metadata.provider_id} "
                f"must define a callable '{name}'."
            )
        return function

    def verify_claim(self, message: bytes, proof: object, public_key: object) -> bool:
        return bool(self._backend_function("verify_claim")(message, proof, public_key))

    def address_from_public_key(self, public_key: object) -> str:
        return str(self._backend_function("address_from_public_key")(public_key))

    def backend_status(self) -> dict[str, object]:
        status = super().backend_status()
        status["module_path"] = self._module_path()
        try:
            backend = self._load_backend()
            info_factory = getattr(backend, "backend_info", None)
            if callable(info_factory):
                info = info_factory()
                if isinstance(info, dict):
                    status.update(info)
            for name in ("verify_claim", "address_from_public_key"):
                if not callable(getattr(backend, name, None)):
                    raise ValueError(
                        f"Backend module '{self._module_path()}' is missing required callable '{name}'."
                    )
            status["available"] = True
        except ValueError as error:
            status["available"] = False
            status["error"] = str(error)
        return status


VERIFIERS: dict[str, ClassicalClaimVerifier] = {}


def register_classical_claim_verifier(verifier: ClassicalClaimVerifier) -> None:
    VERIFIERS[verifier.metadata.provider_id] = verifier


def get_classical_claim_verifier(provider_id: str) -> ClassicalClaimVerifier:
    try:
        return VERIFIERS[provider_id]
    except KeyError as error:
        raise ValueError(f"Unsupported classical migration provider: {provider_id}") from error


def list_classical_claim_verifier_statuses() -> list[dict[str, object]]:
    return [verifier.backend_status() for verifier in VERIFIERS.values()]


register_classical_claim_verifier(DemoClassicalClaimVerifier())
register_classical_claim_verifier(
    ExternalModuleClassicalClaimVerifier(
        provider_id="ecdsa_secp256k1_migration_v1",
        algorithm_family="ecdsa",
        module_env_var="QR_CHAIN_ECDSA_MIGRATION_BACKEND_MODULE",
        default_module_path="qr_chain_classical_migration_backend_secp256k1",
        notes="Adapter boundary for real secp256k1 ownership proofs during migration.",
    )
)
register_classical_claim_verifier(
    ExternalModuleClassicalClaimVerifier(
        provider_id="rsa_pkcs1v15_sha256_migration_v1",
        algorithm_family="rsa",
        module_env_var="QR_CHAIN_RSA_MIGRATION_BACKEND_MODULE",
        default_module_path="qr_chain_classical_migration_backend_rsa",
        notes="Adapter boundary for real RSA ownership proofs during migration.",
    )
)
