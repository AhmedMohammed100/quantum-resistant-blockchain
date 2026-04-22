from __future__ import annotations

import importlib
import os

from .contract import validate_backend_module
from . import oqs_backend


LIBRARY_MODULE_ENV = "QR_CHAIN_XMSS_LIBRARY_MODULE"
DEFAULT_LIBRARY_MODULE = "qr_chain_xmss_backend.oqs_backend"


def _load_library_backend() -> object:
    module_path = os.getenv(LIBRARY_MODULE_ENV, DEFAULT_LIBRARY_MODULE).strip() or DEFAULT_LIBRARY_MODULE
    if module_path == DEFAULT_LIBRARY_MODULE:
        backend = oqs_backend
    else:
        try:
            backend = importlib.import_module(module_path)
        except ModuleNotFoundError as error:
            missing_module = getattr(error, "name", module_path)
            if missing_module == module_path:
                raise ValueError(
                    f"XMSS backend module '{module_path}' is not installed. Set {LIBRARY_MODULE_ENV} to a valid module."
                ) from error
            raise ValueError(
                f"XMSS backend module '{module_path}' could not load because dependency '{missing_module}' is missing."
            ) from error
    validate_backend_module(backend)
    return backend


def backend_info() -> dict[str, object]:
    backend = _load_library_backend()
    info = validate_backend_module(backend)
    info_factory = getattr(backend, "backend_info", None)
    if callable(info_factory):
        nested_info = info_factory()
        if isinstance(nested_info, dict):
            info.update(nested_info)
    return info


def generate_keypair() -> object:
    return _load_library_backend().generate_keypair()


def derive_address(keypair: object) -> str:
    return str(_load_library_backend().derive_address(keypair))


def export_public_key(keypair: object) -> object:
    return _load_library_backend().export_public_key(keypair)


def sign(keypair: object, message: bytes) -> tuple[object, object]:
    result = _load_library_backend().sign(keypair, message)
    if not isinstance(result, tuple) or len(result) != 2:
        raise ValueError("XMSS library backend sign() must return (public_key, signature).")
    return result


def serialize_keypair(keypair: object) -> object:
    return _load_library_backend().serialize_keypair(keypair)


def deserialize_keypair(payload: object) -> object:
    return _load_library_backend().deserialize_keypair(payload)


def reserve_signing_material(keypair: object) -> object:
    return _load_library_backend().reserve_signing_material(keypair)


def sign_with_reservation(keypair: object, message: bytes, reservation: object) -> tuple[object, object]:
    result = _load_library_backend().sign_with_reservation(keypair, message, reservation)
    if not isinstance(result, tuple) or len(result) != 2:
        raise ValueError("XMSS library backend sign_with_reservation() must return (public_key, signature).")
    return result


def verify(message: bytes, signature: object, public_key: object) -> bool:
    return bool(_load_library_backend().verify(message, signature, public_key))


def address_from_public_key(public_key: object) -> str:
    return str(_load_library_backend().address_from_public_key(public_key))
