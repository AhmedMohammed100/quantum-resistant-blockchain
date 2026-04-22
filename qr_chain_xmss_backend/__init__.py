from __future__ import annotations

import os

from .contract import validate_backend_module
from . import module_backend
from . import reference_backend


BACKEND_VERSION = "0.3.0"

_IMPLEMENTATION_ENV = "QR_CHAIN_XMSS_BACKEND_IMPLEMENTATION"
_MODULE_ENV = "QR_CHAIN_XMSS_LIBRARY_MODULE"


def _load_backend() -> object:
    implementation = os.getenv(_IMPLEMENTATION_ENV, "reference").strip().lower()
    if implementation in {"reference", "software", ""}:
        return reference_backend
    if implementation in {"module", "external"}:
        return module_backend
    raise ValueError(
        f"Unsupported XMSS backend implementation '{implementation}'. Expected 'reference' or 'module'."
    )


def _backend_function(name: str):
    backend = _load_backend()
    function = getattr(backend, name, None)
    if name == "address_from_public_key" and not callable(function):
        function = getattr(backend, "address_from_public_key_value", None)
    if not callable(function):
        raise ValueError(
            f"XMSS backend '{getattr(backend, '__name__', type(backend).__name__)}' must define callable '{name}'."
        )
    return function


def backend_info() -> dict[str, object]:
    backend = _load_backend()
    implementation = os.getenv(_IMPLEMENTATION_ENV, "reference").strip().lower() or "reference"
    info_factory = getattr(backend, "backend_info", None)
    if callable(info_factory):
        info = info_factory()
        if isinstance(info, dict):
            info.setdefault("backend_version", BACKEND_VERSION)
            info.setdefault("implementation_mode", implementation)
            return info
    if backend is not module_backend:
        validate_backend_module(backend)
    return {
        "status": "available",
        "backend_version": BACKEND_VERSION,
        "implementation_mode": implementation,
        "backend_module": getattr(backend, "__name__", type(backend).__name__),
        "supports_stateful_signing": callable(getattr(backend, "reserve_signing_material", None)),
        "supports_reserved_signing": callable(getattr(backend, "sign_with_reservation", None)),
    }


def generate_keypair() -> object:
    return _backend_function("generate_keypair")()


def derive_address(keypair: object) -> str:
    return str(_backend_function("derive_address")(keypair))


def export_public_key(keypair: object) -> object:
    return _backend_function("export_public_key")(keypair)


def sign(keypair: object, message: bytes) -> tuple[object, object]:
    result = _backend_function("sign")(keypair, message)
    if not isinstance(result, tuple) or len(result) != 2:
        raise ValueError("XMSS backend sign() must return (public_key, signature).")
    return result


def serialize_keypair(keypair: object) -> object:
    return _backend_function("serialize_keypair")(keypair)


def deserialize_keypair(payload: object) -> object:
    return _backend_function("deserialize_keypair")(payload)


def reserve_signing_material(keypair: object) -> object:
    return _backend_function("reserve_signing_material")(keypair)


def sign_with_reservation(keypair: object, message: bytes, reservation: object) -> tuple[object, object]:
    result = _backend_function("sign_with_reservation")(keypair, message, reservation)
    if not isinstance(result, tuple) or len(result) != 2:
        raise ValueError("XMSS backend sign_with_reservation() must return (public_key, signature).")
    return result


def verify(message: bytes, signature: object, public_key: object) -> bool:
    return bool(_backend_function("verify")(message, signature, public_key))


def address_from_public_key(public_key: object) -> str:
    return str(_backend_function("address_from_public_key")(public_key))
