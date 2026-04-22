from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
import importlib
import os

from .lamport import LamportKeyPair, address_from_public_key, sha256_hex, verify_signature


def _normalize_lamport_public_key(public_key: object) -> list[list[str]]:
    if not isinstance(public_key, list):
        raise ValueError("Lamport public key must be a list.")
    return [[str(value) for value in row] for row in public_key]


def _normalize_lamport_signature(signature: object) -> list[str]:
    if not isinstance(signature, list):
        raise ValueError("Lamport signature must be a list.")
    return [str(value) for value in signature]


@dataclass(frozen=True)
class SignatureProviderMetadata:
    provider_id: str
    scheme_id: str
    algorithm_family: str
    implementation: str
    status: str
    supports_signing: bool
    notes: str = ""


class SignatureProvider(ABC):
    metadata: SignatureProviderMetadata

    @abstractmethod
    def generate_keypair(self) -> object:
        raise NotImplementedError

    @abstractmethod
    def derive_address(self, keypair: object) -> str:
        raise NotImplementedError

    @abstractmethod
    def sign(self, keypair: object, message: bytes) -> tuple[object, object]:
        raise NotImplementedError

    @abstractmethod
    def verify(self, message: bytes, signature: object, public_key: object) -> bool:
        raise NotImplementedError

    @abstractmethod
    def address_from_public_key(self, public_key: object) -> str:
        raise NotImplementedError

    def export_public_key(self, keypair: object) -> object:
        raise ValueError(f"Provider {self.metadata.provider_id} does not support public key export.")

    def serialize_keypair(self, keypair: object) -> object:
        raise ValueError(f"Provider {self.metadata.provider_id} does not support keypair serialization.")

    def deserialize_keypair(self, payload: object) -> object:
        raise ValueError(f"Provider {self.metadata.provider_id} does not support keypair deserialization.")

    def reserve_signing_material(self, keypair: object) -> object:
        return None

    def sign_with_reservation(self, keypair: object, message: bytes, reservation: object) -> tuple[object, object]:
        return self.sign(keypair, message)

    def backend_status(self) -> dict[str, object]:
        return {
            "provider_id": self.metadata.provider_id,
            "scheme_id": self.metadata.scheme_id,
            "algorithm_family": self.metadata.algorithm_family,
            "implementation": self.metadata.implementation,
            "status": self.metadata.status,
            "supports_signing": self.metadata.supports_signing,
            "available": self.metadata.supports_signing or self.metadata.status == "available",
            "notes": self.metadata.notes,
        }


@dataclass
class XMSSMerkleLamportKeyPair:
    height: int
    leaf_keypairs: list[LamportKeyPair]
    leaf_hashes: list[str]
    auth_paths: list[list[str]]
    root: str
    next_index: int = 0

    @staticmethod
    def generate(height: int = 4) -> "XMSSMerkleLamportKeyPair":
        if height <= 0:
            raise ValueError("XMSS tree height must be positive.")

        leaf_count = 2 ** height
        leaf_keypairs = [LamportKeyPair.generate() for _ in range(leaf_count)]
        leaf_hashes = [_leaf_hash(keypair.public_key) for keypair in leaf_keypairs]
        root, auth_paths = _build_merkle_tree(leaf_hashes)
        return XMSSMerkleLamportKeyPair(
            height=height,
            leaf_keypairs=leaf_keypairs,
            leaf_hashes=leaf_hashes,
            auth_paths=auth_paths,
            root=root,
            next_index=0,
        )

    def address(self) -> str:
        return self.root

    def remaining_signatures(self) -> int:
        return len(self.leaf_keypairs) - self.next_index


def _leaf_hash(public_key: tuple[tuple[str, str], ...] | list[list[str]]) -> str:
    return sha256_hex(("leaf:" + address_from_public_key(public_key)).encode("utf-8"))


def _merkle_parent(left: str, right: str) -> str:
    return sha256_hex(f"node:{left}:{right}".encode("utf-8"))


def _build_merkle_tree(leaf_hashes: list[str]) -> tuple[str, list[list[str]]]:
    if not leaf_hashes:
        raise ValueError("Merkle tree requires at least one leaf.")

    levels = [leaf_hashes[:]]
    while len(levels[-1]) > 1:
        level = levels[-1]
        next_level: list[str] = []
        for position in range(0, len(level), 2):
            next_level.append(_merkle_parent(level[position], level[position + 1]))
        levels.append(next_level)

    auth_paths: list[list[str]] = []
    for leaf_index in range(len(leaf_hashes)):
        auth_path: list[str] = []
        current_index = leaf_index
        for level in levels[:-1]:
            auth_path.append(level[current_index ^ 1])
            current_index //= 2
        auth_paths.append(auth_path)

    return levels[-1][0], auth_paths


def _root_from_auth_path(leaf_hash: str, leaf_index: int, auth_path: list[str]) -> str:
    current = leaf_hash
    index = leaf_index
    for sibling in auth_path:
        if index % 2 == 0:
            current = _merkle_parent(current, sibling)
        else:
            current = _merkle_parent(sibling, current)
        index //= 2
    return current


class LamportSignatureProvider(SignatureProvider):
    metadata = SignatureProviderMetadata(
        provider_id="hash_lamport_v1",
        scheme_id="hash_lamport_v1",
        algorithm_family="hash-based-signatures",
        implementation="in_repo_reference",
        status="available",
        supports_signing=True,
        notes="Compatibility provider using raw Lamport one-time signatures.",
    )

    def generate_keypair(self) -> LamportKeyPair:
        return LamportKeyPair.generate()

    def derive_address(self, keypair: object) -> str:
        if not isinstance(keypair, LamportKeyPair):
            raise ValueError("Invalid keypair for Lamport provider.")
        return keypair.address()

    def sign(self, keypair: object, message: bytes) -> tuple[object, object]:
        if not isinstance(keypair, LamportKeyPair):
            raise ValueError("Invalid keypair for Lamport provider.")
        return [list(row) for row in keypair.public_key], keypair.sign(message)

    def verify(self, message: bytes, signature: object, public_key: object) -> bool:
        try:
            return verify_signature(message, _normalize_lamport_signature(signature), _normalize_lamport_public_key(public_key))
        except ValueError:
            return False

    def address_from_public_key(self, public_key: object) -> str:
        return address_from_public_key(_normalize_lamport_public_key(public_key))

    def export_public_key(self, keypair: object) -> object:
        if not isinstance(keypair, LamportKeyPair):
            raise ValueError("Invalid keypair for Lamport provider.")
        return [list(row) for row in keypair.public_key]

    def serialize_keypair(self, keypair: object) -> object:
        if not isinstance(keypair, LamportKeyPair):
            raise ValueError("Invalid keypair for Lamport provider.")
        return {
            "private_key": [list(pair) for pair in keypair.private_key],
            "public_key": [list(pair) for pair in keypair.public_key],
        }

    def deserialize_keypair(self, payload: object) -> LamportKeyPair:
        if not isinstance(payload, dict):
            raise ValueError("Lamport key payload must be an object.")
        private_key = tuple((str(pair[0]), str(pair[1])) for pair in payload.get("private_key", []))
        public_key = tuple((str(pair[0]), str(pair[1])) for pair in payload.get("public_key", []))
        return LamportKeyPair(private_key=private_key, public_key=public_key)


class XMSSMerkleLamportSignatureProvider(SignatureProvider):
    metadata = SignatureProviderMetadata(
        provider_id="xmss_merkle_lamport_v1",
        scheme_id="xmss_merkle_lamport_v1",
        algorithm_family="hash-based-signatures",
        implementation="in_repo_reference",
        status="available",
        supports_signing=True,
        notes="XMSS-style Merkle wrapper around Lamport leaves used as the default software provider.",
    )

    def generate_keypair(self) -> XMSSMerkleLamportKeyPair:
        return XMSSMerkleLamportKeyPair.generate(height=4)

    def derive_address(self, keypair: object) -> str:
        if not isinstance(keypair, XMSSMerkleLamportKeyPair):
            raise ValueError("Invalid keypair for XMSS-style provider.")
        return keypair.address()

    def sign(self, keypair: object, message: bytes) -> tuple[object, object]:
        if not isinstance(keypair, XMSSMerkleLamportKeyPair):
            raise ValueError("Invalid keypair for XMSS-style provider.")
        reservation = self.reserve_signing_material(keypair)
        return self.sign_with_reservation(keypair, message, reservation)

    def verify(self, message: bytes, signature: object, public_key: object) -> bool:
        if not isinstance(public_key, dict) or not isinstance(signature, dict):
            return False

        root = str(public_key.get("root", ""))
        leaf_index = int(signature.get("leaf_index", -1))
        auth_path_raw = signature.get("auth_path", [])
        leaf_public_key_raw = signature.get("leaf_public_key", [])
        lamport_signature_raw = signature.get("lamport_signature", [])

        if leaf_index < 0 or not isinstance(auth_path_raw, list):
            return False

        leaf_public_key = _normalize_lamport_public_key(leaf_public_key_raw)
        lamport_signature = _normalize_lamport_signature(lamport_signature_raw)
        auth_path = [str(item) for item in auth_path_raw]

        if not verify_signature(message, lamport_signature, leaf_public_key):
            return False

        leaf_hash = _leaf_hash(leaf_public_key)
        derived_root = _root_from_auth_path(leaf_hash, leaf_index, auth_path)
        return derived_root == root

    def address_from_public_key(self, public_key: object) -> str:
        if not isinstance(public_key, dict):
            raise ValueError("XMSS-style public key must be an object.")
        root = str(public_key.get("root", ""))
        if not root:
            raise ValueError("XMSS-style public key is missing the Merkle root.")
        return root

    def export_public_key(self, keypair: object) -> object:
        if not isinstance(keypair, XMSSMerkleLamportKeyPair):
            raise ValueError("Invalid keypair for XMSS-style provider.")
        return {
            "root": keypair.root,
            "height": keypair.height,
            "scheme": self.metadata.scheme_id,
            "provider": self.metadata.provider_id,
        }

    def serialize_keypair(self, keypair: object) -> object:
        if not isinstance(keypair, XMSSMerkleLamportKeyPair):
            raise ValueError("Invalid keypair for XMSS-style provider.")
        lamport_provider = LamportSignatureProvider()
        return {
            "height": keypair.height,
            "root": keypair.root,
            "next_index": keypair.next_index,
            "leaf_hashes": list(keypair.leaf_hashes),
            "auth_paths": [list(path) for path in keypair.auth_paths],
            "leaf_keypairs": [lamport_provider.serialize_keypair(item) for item in keypair.leaf_keypairs],
        }

    def deserialize_keypair(self, payload: object) -> XMSSMerkleLamportKeyPair:
        if not isinstance(payload, dict):
            raise ValueError("XMSS-style key payload must be an object.")
        lamport_provider = LamportSignatureProvider()
        return XMSSMerkleLamportKeyPair(
            height=int(payload["height"]),
            root=str(payload["root"]),
            next_index=int(payload.get("next_index", 0)),
            leaf_hashes=[str(item) for item in payload.get("leaf_hashes", [])],
            auth_paths=[[str(value) for value in path] for path in payload.get("auth_paths", [])],
            leaf_keypairs=[lamport_provider.deserialize_keypair(item) for item in payload.get("leaf_keypairs", [])],
        )

    def reserve_signing_material(self, keypair: object) -> object:
        if not isinstance(keypair, XMSSMerkleLamportKeyPair):
            raise ValueError("Invalid keypair for XMSS-style provider.")
        if keypair.next_index >= len(keypair.leaf_keypairs):
            raise ValueError("XMSS-style keypair has exhausted all one-time leaves.")
        leaf_index = keypair.next_index
        keypair.next_index += 1
        return {"leaf_index": leaf_index}

    def sign_with_reservation(self, keypair: object, message: bytes, reservation: object) -> tuple[object, object]:
        if not isinstance(keypair, XMSSMerkleLamportKeyPair):
            raise ValueError("Invalid keypair for XMSS-style provider.")
        if not isinstance(reservation, dict) or "leaf_index" not in reservation:
            raise ValueError("XMSS-style signing requires a reserved leaf index.")
        leaf_index = int(reservation["leaf_index"])
        leaf_keypair = keypair.leaf_keypairs[leaf_index]
        public_key = {
            "root": keypair.root,
            "height": keypair.height,
            "scheme": self.metadata.scheme_id,
            "provider": self.metadata.provider_id,
        }
        signature = {
            "leaf_index": leaf_index,
            "leaf_public_key": [list(row) for row in leaf_keypair.public_key],
            "lamport_signature": leaf_keypair.sign(message),
            "auth_path": list(keypair.auth_paths[leaf_index]),
        }
        return public_key, signature


class UnavailableExternalProvider(SignatureProvider):
    def __init__(
        self,
        *,
        provider_id: str,
        algorithm_family: str,
        notes: str,
    ):
        self.metadata = SignatureProviderMetadata(
            provider_id=provider_id,
            scheme_id=provider_id,
            algorithm_family=algorithm_family,
            implementation="external_backend_boundary",
            status="planned",
            supports_signing=False,
            notes=notes,
        )

    def generate_keypair(self) -> object:
        raise ValueError(
            f"Provider {self.metadata.provider_id} is registered as a migration boundary but has no installed backend yet."
        )

    def derive_address(self, keypair: object) -> str:
        raise ValueError(f"Provider {self.metadata.provider_id} is not available for signing.")

    def sign(self, keypair: object, message: bytes) -> tuple[object, object]:
        raise ValueError(f"Provider {self.metadata.provider_id} is not available for signing.")

    def verify(self, message: bytes, signature: object, public_key: object) -> bool:
        raise ValueError(
            f"Provider {self.metadata.provider_id} has no verification backend configured yet."
        )

    def address_from_public_key(self, public_key: object) -> str:
        raise ValueError(
            f"Provider {self.metadata.provider_id} has no address derivation backend configured yet."
        )

    def backend_status(self) -> dict[str, object]:
        status = super().backend_status()
        status["available"] = False
        status["error"] = (
            f"Provider {self.metadata.provider_id} is reserved as a migration boundary and has no backend configured yet."
        )
        return status


class ExternalModuleSignatureProvider(SignatureProvider):
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
        self.metadata = SignatureProviderMetadata(
            provider_id=provider_id,
            scheme_id=provider_id,
            algorithm_family=algorithm_family,
            implementation="external_module_adapter",
            status="adapter_ready",
            supports_signing=True,
            notes=notes,
        )

    def _module_path(self) -> str:
        return os.getenv(self.module_env_var, self.default_module_path)

    def _load_backend(self) -> object:
        module_path = self._module_path()
        try:
            return importlib.import_module(module_path)
        except ModuleNotFoundError as error:
            missing_module = getattr(error, "name", module_path)
            if missing_module == module_path:
                raise ValueError(
                    f"Provider {self.metadata.provider_id} requires the optional backend module "
                    f"'{module_path}'. Install a compatible XMSS backend package or set "
                    f"{self.module_env_var} to a module that implements "
                    "'generate_keypair', 'derive_address', 'sign', 'verify', and 'address_from_public_key'."
                ) from error
            raise ValueError(
                f"Provider {self.metadata.provider_id} could not load because dependency "
                f"'{missing_module}' required by backend module '{module_path}' is missing."
            ) from error

    def _backend_function(self, name: str):
        backend = self._load_backend()
        function = getattr(backend, name, None)
        if not callable(function):
            raise ValueError(
                f"Backend module '{self._module_path()}' for provider {self.metadata.provider_id} "
                f"must define a callable '{name}'."
            )
        return function

    def _required_functions(self) -> tuple[str, ...]:
        return (
            "generate_keypair",
            "derive_address",
            "sign",
            "verify",
            "address_from_public_key",
            "export_public_key",
            "serialize_keypair",
            "deserialize_keypair",
            "reserve_signing_material",
            "sign_with_reservation",
        )

    def generate_keypair(self) -> object:
        return self._backend_function("generate_keypair")()

    def derive_address(self, keypair: object) -> str:
        return str(self._backend_function("derive_address")(keypair))

    def sign(self, keypair: object, message: bytes) -> tuple[object, object]:
        result = self._backend_function("sign")(keypair, message)
        if not isinstance(result, tuple) or len(result) != 2:
            raise ValueError(
                f"Backend module '{self._module_path()}' must return (public_key, signature) from sign()."
            )
        return result

    def verify(self, message: bytes, signature: object, public_key: object) -> bool:
        return bool(self._backend_function("verify")(message, signature, public_key))

    def address_from_public_key(self, public_key: object) -> str:
        return str(self._backend_function("address_from_public_key")(public_key))

    def export_public_key(self, keypair: object) -> object:
        return self._backend_function("export_public_key")(keypair)

    def serialize_keypair(self, keypair: object) -> object:
        return self._backend_function("serialize_keypair")(keypair)

    def deserialize_keypair(self, payload: object) -> object:
        return self._backend_function("deserialize_keypair")(payload)

    def reserve_signing_material(self, keypair: object) -> object:
        backend = self._load_backend()
        function = getattr(backend, "reserve_signing_material", None)
        if not callable(function):
            return None
        return function(keypair)

    def sign_with_reservation(self, keypair: object, message: bytes, reservation: object) -> tuple[object, object]:
        backend = self._load_backend()
        function = getattr(backend, "sign_with_reservation", None)
        if callable(function):
            result = function(keypair, message, reservation)
            if not isinstance(result, tuple) or len(result) != 2:
                raise ValueError(
                    f"Backend module '{self._module_path()}' must return (public_key, signature) from sign_with_reservation()."
                )
            return result
        return self.sign(keypair, message)

    def backend_status(self) -> dict[str, object]:
        status = super().backend_status()
        status["module_path"] = self._module_path()
        try:
            backend = self._load_backend()
            backend_info = getattr(backend, "backend_info", None)
            if callable(backend_info):
                info = backend_info()
                if isinstance(info, dict):
                    status.update(info)
            missing = [
                name
                for name in self._required_functions()
                if not callable(getattr(backend, name, None))
            ]
            if missing:
                status["available"] = False
                status["error"] = (
                    f"Backend module '{self._module_path()}' is missing required callables: {', '.join(missing)}."
                )
                return status
            status["available"] = True
            status.setdefault("backend_module", getattr(backend, "__name__", self._module_path()))
            status["supports_stateful_signing"] = callable(getattr(backend, "reserve_signing_material", None))
            status["supports_reserved_signing"] = callable(getattr(backend, "sign_with_reservation", None))
            return status
        except ValueError as error:
            status["available"] = False
            status["error"] = str(error)
            return status


PROVIDERS: dict[str, SignatureProvider] = {}
SCHEME_VERIFIERS: dict[str, SignatureProvider] = {}


def register_signature_provider(provider: SignatureProvider) -> None:
    PROVIDERS[provider.metadata.provider_id] = provider
    if provider.metadata.supports_signing or provider.metadata.status == "available":
        SCHEME_VERIFIERS.setdefault(provider.metadata.scheme_id, provider)


def get_signature_provider(provider_id: str) -> SignatureProvider:
    try:
        return PROVIDERS[provider_id]
    except KeyError as error:
        raise ValueError(f"Unsupported signature provider: {provider_id}") from error


def get_signature_verifier(scheme_id: str) -> SignatureProvider:
    try:
        return SCHEME_VERIFIERS[scheme_id]
    except KeyError as error:
        raise ValueError(f"Unsupported signature scheme: {scheme_id}") from error


def list_signature_providers() -> list[SignatureProviderMetadata]:
    return [provider.metadata for provider in PROVIDERS.values()]


def list_signature_provider_statuses() -> list[dict[str, object]]:
    return [provider.backend_status() for provider in PROVIDERS.values()]


def get_signature_suite(identifier: str) -> SignatureProvider:
    if identifier in PROVIDERS:
        return get_signature_provider(identifier)
    return get_signature_verifier(identifier)


register_signature_provider(LamportSignatureProvider())
register_signature_provider(XMSSMerkleLamportSignatureProvider())
register_signature_provider(
    ExternalModuleSignatureProvider(
        provider_id="xmss_nist_v1",
        algorithm_family="xmss",
        module_env_var="QR_CHAIN_XMSS_BACKEND_MODULE",
        default_module_path="qr_chain_xmss_backend",
        notes="Adapter boundary for a real audited XMSS backend loaded from an optional external module.",
    )
)
register_signature_provider(
    UnavailableExternalProvider(
        provider_id="lms_nist_v1",
        algorithm_family="lms",
        notes="Reserved provider slot for a real audited LMS/HSS implementation.",
    )
)
register_signature_provider(
    UnavailableExternalProvider(
        provider_id="sphincsplus_v1",
        algorithm_family="sphincs+",
        notes="Reserved provider slot for a real audited SPHINCS+ implementation.",
    )
)
