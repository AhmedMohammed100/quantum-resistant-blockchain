from __future__ import annotations

from dataclasses import dataclass
import ctypes as ct
import importlib
import os

from .contract import EXPECTED_ALGORITHM_FAMILY, EXPECTED_SCHEME_ID, XMSS_BACKEND_API_VERSION
from qr_blockchain.lamport import sha256_hex


OQS_MECHANISM_ENV = "QR_CHAIN_XMSS_OQS_MECHANISM"
DEFAULT_OQS_MECHANISM = "XMSS-SHA2_10_256"

XMSS_BACKEND_MANIFEST = {
    "backend_name": "open_quantum_safe_liboqs_python",
    "api_version": XMSS_BACKEND_API_VERSION,
    "scheme_id": EXPECTED_SCHEME_ID,
    "algorithm_family": EXPECTED_ALGORITHM_FAMILY,
    "implementation_type": "library_adapter",
    "supports_signing": True,
    "supports_stateful_signing": True,
    "supports_reserved_signing": True,
}


@dataclass
class OQSXMSSKeyPair:
    mechanism: str
    public_key_hex: str
    secret_key_hex: str
    signatures_used: int = 0


def _load_oqs() -> object:
    try:
        oqs_module = importlib.import_module("oqs")
        _prepare_oqs_runtime(oqs_module)
    except ModuleNotFoundError as error:
        raise ValueError(
            "The OQS-backed XMSS adapter requires the 'oqs' Python package from liboqs-python. "
            "Install liboqs-python and ensure liboqs is available on the system before using "
            "QR_CHAIN_XMSS_LIBRARY_MODULE=qr_chain_xmss_backend.oqs_backend."
        ) from error
    except SystemExit as error:
        detail = str(error) if str(error) else "liboqs runtime bootstrap failed"
        raise ValueError(
            "The OQS Python package is installed, but its native liboqs runtime is unavailable. "
            f"Runtime detail: {detail}. Install liboqs manually (or provide OQS_INSTALL_PATH) before using "
            "the OQS-backed XMSS adapter."
        ) from error
    except RuntimeError as error:
        raise ValueError(
            "The OQS Python package is installed, but its native liboqs runtime could not be loaded: "
            f"{error}"
        ) from error

    return oqs_module


def _prepare_oqs_runtime(oqs_module: object) -> None:
    native = getattr(oqs_module, "native", None)
    if not callable(native):
        return

    library = native()
    library.OQS_SIG_STFL_SECRET_KEY_serialize.argtypes = [
        ct.POINTER(ct.POINTER(ct.c_uint8)),
        ct.POINTER(ct.c_size_t),
        ct.c_void_p,
    ]
    library.OQS_SIG_STFL_SECRET_KEY_serialize.restype = ct.c_int
    library.OQS_SIG_STFL_SECRET_KEY_deserialize.argtypes = [
        ct.c_void_p,
        ct.c_void_p,
        ct.c_size_t,
        ct.c_void_p,
    ]
    library.OQS_SIG_STFL_SECRET_KEY_deserialize.restype = ct.c_int
    library.OQS_SIG_STFL_SECRET_KEY_free.argtypes = [ct.c_void_p]
    library.OQS_SIG_STFL_SECRET_KEY_free.restype = None

    if hasattr(library, "OQS_MEM_insecure_free"):
        library.OQS_MEM_insecure_free.argtypes = [ct.c_void_p]
        library.OQS_MEM_insecure_free.restype = None


def _native_library(oqs_module: object):
    native = getattr(oqs_module, "native", None)
    if not callable(native):
        return None
    return native()


def _selected_mechanism() -> str:
    return os.getenv(OQS_MECHANISM_ENV, DEFAULT_OQS_MECHANISM).strip() or DEFAULT_OQS_MECHANISM


def _enabled_xmss_mechanisms(oqs_module: object) -> list[str]:
    getter = getattr(oqs_module, "get_enabled_stateful_sig_mechanisms", None)
    if not callable(getter):
        raise ValueError("The installed 'oqs' module does not expose get_enabled_stateful_sig_mechanisms().")
    mechanisms = [str(item) for item in getter()]
    return [item for item in mechanisms if item.upper().startswith("XMSS")]


def _ensure_mechanism_supported(oqs_module: object, mechanism: str) -> None:
    enabled = _enabled_xmss_mechanisms(oqs_module)
    if mechanism not in enabled:
        if not enabled:
            raise ValueError("The installed OQS runtime does not report any enabled XMSS mechanisms.")
        raise ValueError(
            f"OQS mechanism '{mechanism}' is not enabled. Available XMSS mechanisms: {', '.join(enabled)}."
        )


def _new_signer(oqs_module: object, mechanism: str, secret_key: bytes | None = None):
    stateful_signature = getattr(oqs_module, "StatefulSignature", None)
    if stateful_signature is None:
        raise ValueError("The installed 'oqs' module does not expose StatefulSignature.")
    if secret_key is None:
        return stateful_signature(mechanism)
    try:
        return stateful_signature(mechanism, secret_key=secret_key)
    except TypeError:
        signer = stateful_signature(mechanism)
        _attach_secret_key(signer, secret_key)
        return signer


def _public_key_bytes_from_signer(signer: object, generated_public_key: object | None = None) -> bytes:
    if isinstance(generated_public_key, (bytes, bytearray)):
        return bytes(generated_public_key)
    for attribute in ("public_key", "public_key_bytes"):
        value = getattr(signer, attribute, None)
        if isinstance(value, (bytes, bytearray)):
            return bytes(value)
    raise ValueError("Unable to extract public key bytes from the OQS StatefulSignature object.")


def _secret_key_bytes_from_signer(signer: object) -> bytes:
    library = None
    signer_module_name = getattr(signer, "__module__", "")
    if signer_module_name:
        oqs_module = importlib.import_module(signer_module_name.split(".", 1)[0])
        library = _native_library(oqs_module)
    secret_key_pointer = getattr(signer, "_secret_key", None)
    if library is not None and secret_key_pointer:
        if isinstance(secret_key_pointer, int):
            secret_key_pointer = ct.c_void_p(secret_key_pointer)
        elif hasattr(secret_key_pointer, "value"):
            secret_key_pointer = ct.c_void_p(secret_key_pointer.value)
        buf_ptr = ct.POINTER(ct.c_uint8)()
        buf_len = ct.c_size_t()
        result = library.OQS_SIG_STFL_SECRET_KEY_serialize(
            ct.byref(buf_ptr),
            ct.byref(buf_len),
            secret_key_pointer,
        )
        if result != 0:
            raise ValueError("OQS secret-key serialization failed.")
        try:
            return bytes(ct.string_at(buf_ptr, buf_len.value))
        finally:
            if hasattr(library, "OQS_MEM_insecure_free"):
                library.OQS_MEM_insecure_free(buf_ptr)

    export_function = getattr(signer, "export_secret_key", None)
    if callable(export_function):
        value = export_function()
        if isinstance(value, (bytes, bytearray)):
            return bytes(value)
    value = getattr(signer, "secret_key", None)
    if isinstance(value, (bytes, bytearray)):
        return bytes(value)
    raise ValueError("Unable to extract secret key bytes from the OQS StatefulSignature object.")


def _attach_secret_key(signer: object, secret_key: bytes) -> None:
    for method_name in ("import_secret_key", "set_secret_key", "load_secret_key"):
        function = getattr(signer, method_name, None)
        if callable(function):
            function(secret_key)
            return
    if hasattr(signer, "secret_key"):
        setattr(signer, "secret_key", secret_key)
        return
    raise ValueError(
        "Unable to load secret key bytes into the OQS StatefulSignature object. "
        "The installed wrapper does not expose an import/set/load secret key method."
    )


def _sign_message(signer: object, message: bytes, secret_key: bytes) -> bytes:
    sign_function = getattr(signer, "sign", None)
    if not callable(sign_function):
        raise ValueError("The installed OQS StatefulSignature object does not expose sign().")
    try:
        signature = sign_function(message)
    except TypeError:
        signature = sign_function(message, secret_key)
    if not isinstance(signature, (bytes, bytearray)):
        raise ValueError("OQS StatefulSignature.sign() must return signature bytes.")
    return bytes(signature)


def _verify_message(signer: object, message: bytes, signature: bytes, public_key: bytes) -> bool:
    verify_function = getattr(signer, "verify", None)
    if not callable(verify_function):
        raise ValueError("The installed OQS StatefulSignature object does not expose verify().")
    return bool(verify_function(message, signature, public_key))


def _address_from_public_key_bytes(public_key: bytes) -> str:
    return sha256_hex(b"oqs-xmss:" + public_key)


def backend_info() -> dict[str, object]:
    oqs_module = _load_oqs()
    mechanism = _selected_mechanism()
    _ensure_mechanism_supported(oqs_module, mechanism)
    enabled = _enabled_xmss_mechanisms(oqs_module)
    return {
        "status": "available",
        "backend_module": __name__,
        "backend_name": str(XMSS_BACKEND_MANIFEST["backend_name"]),
        "api_version": int(XMSS_BACKEND_MANIFEST["api_version"]),
        "scheme_id": str(XMSS_BACKEND_MANIFEST["scheme_id"]),
        "algorithm_family": str(XMSS_BACKEND_MANIFEST["algorithm_family"]),
        "implementation_type": str(XMSS_BACKEND_MANIFEST["implementation_type"]),
        "supports_signing": True,
        "supports_stateful_signing": True,
        "supports_reserved_signing": True,
        "library_module": getattr(oqs_module, "__name__", "oqs"),
        "library_version": getattr(oqs_module, "__version__", "unknown"),
        "selected_mechanism": mechanism,
        "enabled_mechanisms": enabled,
    }


def generate_keypair() -> OQSXMSSKeyPair:
    oqs_module = _load_oqs()
    mechanism = _selected_mechanism()
    _ensure_mechanism_supported(oqs_module, mechanism)
    signer = _new_signer(oqs_module, mechanism)
    generated_public_key = signer.generate_keypair()
    public_key = _public_key_bytes_from_signer(signer, generated_public_key)
    secret_key = _secret_key_bytes_from_signer(signer)
    return OQSXMSSKeyPair(
        mechanism=mechanism,
        public_key_hex=public_key.hex(),
        secret_key_hex=secret_key.hex(),
        signatures_used=0,
    )


def derive_address(keypair: object) -> str:
    if not isinstance(keypair, OQSXMSSKeyPair):
        raise ValueError("Invalid keypair for OQS-backed XMSS backend.")
    return _address_from_public_key_bytes(bytes.fromhex(keypair.public_key_hex))


def export_public_key(keypair: object) -> object:
    if not isinstance(keypair, OQSXMSSKeyPair):
        raise ValueError("Invalid keypair for OQS-backed XMSS backend.")
    return {
        "scheme": EXPECTED_SCHEME_ID,
        "provider": EXPECTED_SCHEME_ID,
        "mechanism": keypair.mechanism,
        "library": "oqs",
        "public_key_hex": keypair.public_key_hex,
    }


def sign(keypair: object, message: bytes) -> tuple[object, object]:
    reservation = reserve_signing_material(keypair)
    return sign_with_reservation(keypair, message, reservation)


def verify(message: bytes, signature: object, public_key: object) -> bool:
    if not isinstance(public_key, dict) or not isinstance(signature, dict):
        return False
    if str(public_key.get("library", "")) != "oqs":
        return False
    mechanism = str(public_key.get("mechanism", ""))
    public_key_hex = str(public_key.get("public_key_hex", ""))
    signature_hex = str(signature.get("signature_hex", ""))
    if not mechanism or not public_key_hex or not signature_hex:
        return False
    try:
        oqs_module = _load_oqs()
        _ensure_mechanism_supported(oqs_module, mechanism)
        verifier = _new_signer(oqs_module, mechanism)
        return _verify_message(
            verifier,
            message,
            bytes.fromhex(signature_hex),
            bytes.fromhex(public_key_hex),
        )
    except ValueError:
        return False


def address_from_public_key(public_key: object) -> str:
    if not isinstance(public_key, dict):
        raise ValueError("OQS-backed XMSS public key must be an object.")
    public_key_hex = str(public_key.get("public_key_hex", ""))
    if not public_key_hex:
        raise ValueError("OQS-backed XMSS public key is missing public_key_hex.")
    return _address_from_public_key_bytes(bytes.fromhex(public_key_hex))


def serialize_keypair(keypair: object) -> object:
    if not isinstance(keypair, OQSXMSSKeyPair):
        raise ValueError("Invalid keypair for OQS-backed XMSS backend.")
    return {
        "mechanism": keypair.mechanism,
        "public_key_hex": keypair.public_key_hex,
        "secret_key_hex": keypair.secret_key_hex,
        "signatures_used": keypair.signatures_used,
    }


def deserialize_keypair(payload: object) -> OQSXMSSKeyPair:
    if not isinstance(payload, dict):
        raise ValueError("OQS-backed XMSS key payload must be an object.")
    return OQSXMSSKeyPair(
        mechanism=str(payload["mechanism"]),
        public_key_hex=str(payload["public_key_hex"]),
        secret_key_hex=str(payload["secret_key_hex"]),
        signatures_used=int(payload.get("signatures_used", 0)),
    )


def reserve_signing_material(keypair: object) -> object:
    if not isinstance(keypair, OQSXMSSKeyPair):
        raise ValueError("Invalid keypair for OQS-backed XMSS backend.")
    return {"reservation_id": keypair.signatures_used + 1}


def sign_with_reservation(keypair: object, message: bytes, reservation: object) -> tuple[object, object]:
    if not isinstance(keypair, OQSXMSSKeyPair):
        raise ValueError("Invalid keypair for OQS-backed XMSS backend.")
    if not isinstance(reservation, dict) or "reservation_id" not in reservation:
        raise ValueError("OQS-backed XMSS signing requires a reservation token.")

    oqs_module = _load_oqs()
    _ensure_mechanism_supported(oqs_module, keypair.mechanism)
    secret_key = bytes.fromhex(keypair.secret_key_hex)
    signer = _new_signer(oqs_module, keypair.mechanism, secret_key=secret_key)
    signature = _sign_message(signer, message, secret_key)
    next_secret_key = _secret_key_bytes_from_signer(signer)
    keypair.secret_key_hex = next_secret_key.hex()
    keypair.signatures_used += 1
    return export_public_key(keypair), {
        "mechanism": keypair.mechanism,
        "library": "oqs",
        "signature_hex": signature.hex(),
        "signatures_used": keypair.signatures_used,
    }
