from __future__ import annotations

from dataclasses import dataclass
import importlib
import os

from qr_blockchain.lamport import sha256_hex


PROVIDER_ID = "mldsa65_oqs_v1"
DEFAULT_MECHANISM = "ML-DSA-65"
MECHANISM_ENV = "QR_CHAIN_MLDSA_OQS_MECHANISM"

MECHANISM_ALIASES = {
    "DILITHIUM3": "ML-DSA-65",
    "DILITHIUM3-AES": "ML-DSA-65",
    "ML_DSA_65": "ML-DSA-65",
    "ML-DSA65": "ML-DSA-65",
}


@dataclass
class OQSMLDSAKeyPair:
    mechanism: str
    public_key_hex: str
    secret_key_hex: str


def _load_oqs() -> object:
    try:
        return importlib.import_module("oqs")
    except ModuleNotFoundError as error:
        raise ValueError(
            "The ML-DSA OQS adapter requires the 'oqs' Python package from liboqs-python "
            "and a native liboqs runtime with ML-DSA enabled."
        ) from error
    except SystemExit as error:
        detail = str(error) if str(error) else "liboqs runtime bootstrap failed"
        raise ValueError(
            "The OQS Python package is installed, but the native liboqs runtime is unavailable. "
            f"Runtime detail: {detail}."
        ) from error
    except RuntimeError as error:
        raise ValueError(f"The native liboqs runtime could not be loaded: {error}") from error


def _selected_mechanism() -> str:
    requested = os.getenv(MECHANISM_ENV, DEFAULT_MECHANISM).strip() or DEFAULT_MECHANISM
    return MECHANISM_ALIASES.get(requested.upper(), requested)


def _enabled_mechanisms(oqs_module: object) -> list[str]:
    getter = getattr(oqs_module, "get_enabled_sig_mechanisms", None)
    if not callable(getter):
        raise ValueError("The installed 'oqs' module does not expose get_enabled_sig_mechanisms().")
    return [str(item) for item in getter()]


def _ensure_mechanism_supported(oqs_module: object, mechanism: str) -> None:
    enabled = _enabled_mechanisms(oqs_module)
    if mechanism not in enabled:
        mldsa_enabled = [item for item in enabled if item.upper().startswith(("ML-DSA", "DILITHIUM"))]
        if not mldsa_enabled:
            raise ValueError("The installed OQS runtime does not report any enabled ML-DSA/Dilithium mechanisms.")
        raise ValueError(
            f"OQS mechanism '{mechanism}' is not enabled. Available ML-DSA/Dilithium mechanisms: "
            f"{', '.join(mldsa_enabled)}."
        )


def _new_signature(oqs_module: object, mechanism: str, secret_key: bytes | None = None):
    signature_class = getattr(oqs_module, "Signature", None)
    if signature_class is None:
        raise ValueError("The installed 'oqs' module does not expose Signature.")
    if secret_key is None:
        return signature_class(mechanism)
    try:
        return signature_class(mechanism, secret_key)
    except TypeError:
        signer = signature_class(mechanism)
        import_function = getattr(signer, "import_secret_key", None)
        if callable(import_function):
            import_function(secret_key)
        return signer


def _address_from_public_key_bytes(public_key: bytes) -> str:
    return sha256_hex(b"oqs-mldsa65:" + public_key)


def _public_key_bytes_from_generated(signer: object, generated: object) -> bytes:
    if isinstance(generated, (bytes, bytearray)):
        return bytes(generated)
    for attribute in ("public_key", "public_key_bytes"):
        value = getattr(signer, attribute, None)
        if isinstance(value, (bytes, bytearray)):
            return bytes(value)
    raise ValueError("Unable to extract public key bytes from OQS Signature.")


def _secret_key_bytes_from_signer(signer: object) -> bytes:
    export_function = getattr(signer, "export_secret_key", None)
    if callable(export_function):
        value = export_function()
        if isinstance(value, (bytes, bytearray)):
            return bytes(value)
    value = getattr(signer, "secret_key", None)
    if isinstance(value, (bytes, bytearray)):
        return bytes(value)
    raise ValueError("Unable to extract secret key bytes from OQS Signature.")


def backend_info() -> dict[str, object]:
    oqs_module = _load_oqs()
    mechanism = _selected_mechanism()
    _ensure_mechanism_supported(oqs_module, mechanism)
    return {
        "status": "available",
        "backend_module": __name__,
        "backend_name": "open_quantum_safe_liboqs_python",
        "api_version": 1,
        "scheme_id": PROVIDER_ID,
        "algorithm_family": "ml-dsa",
        "standardization": "NIST FIPS 204 ML-DSA family",
        "compatibility_aliases": ["Dilithium3"],
        "implementation_type": "library_adapter",
        "supports_signing": True,
        "supports_stateful_signing": False,
        "supports_reserved_signing": False,
        "library_module": getattr(oqs_module, "__name__", "oqs"),
        "library_version": getattr(oqs_module, "__version__", "unknown"),
        "selected_mechanism": mechanism,
        "enabled_mechanisms": _enabled_mechanisms(oqs_module),
    }


def generate_keypair() -> OQSMLDSAKeyPair:
    oqs_module = _load_oqs()
    mechanism = _selected_mechanism()
    _ensure_mechanism_supported(oqs_module, mechanism)
    signer = _new_signature(oqs_module, mechanism)
    generated_public_key = signer.generate_keypair()
    public_key = _public_key_bytes_from_generated(signer, generated_public_key)
    secret_key = _secret_key_bytes_from_signer(signer)
    return OQSMLDSAKeyPair(
        mechanism=mechanism,
        public_key_hex=public_key.hex(),
        secret_key_hex=secret_key.hex(),
    )


def derive_address(keypair: object) -> str:
    if not isinstance(keypair, OQSMLDSAKeyPair):
        raise ValueError("Invalid keypair for OQS-backed ML-DSA backend.")
    return _address_from_public_key_bytes(bytes.fromhex(keypair.public_key_hex))


def export_public_key(keypair: object) -> object:
    if not isinstance(keypair, OQSMLDSAKeyPair):
        raise ValueError("Invalid keypair for OQS-backed ML-DSA backend.")
    return {
        "scheme": PROVIDER_ID,
        "provider": PROVIDER_ID,
        "mechanism": keypair.mechanism,
        "library": "oqs",
        "public_key_hex": keypair.public_key_hex,
    }


def sign(keypair: object, message: bytes) -> tuple[object, object]:
    if not isinstance(keypair, OQSMLDSAKeyPair):
        raise ValueError("Invalid keypair for OQS-backed ML-DSA backend.")
    oqs_module = _load_oqs()
    _ensure_mechanism_supported(oqs_module, keypair.mechanism)
    secret_key = bytes.fromhex(keypair.secret_key_hex)
    signer = _new_signature(oqs_module, keypair.mechanism, secret_key)
    sign_function = getattr(signer, "sign", None)
    if not callable(sign_function):
        raise ValueError("The installed OQS Signature object does not expose sign().")
    try:
        signature = sign_function(message)
    except TypeError:
        signature = sign_function(message, secret_key)
    if not isinstance(signature, (bytes, bytearray)):
        raise ValueError("OQS Signature.sign() must return signature bytes.")
    return export_public_key(keypair), {
        "mechanism": keypair.mechanism,
        "library": "oqs",
        "signature_hex": bytes(signature).hex(),
    }


def verify(message: bytes, signature: object, public_key: object) -> bool:
    if not isinstance(public_key, dict) or not isinstance(signature, dict):
        return False
    if str(public_key.get("library", "")) != "oqs" or str(signature.get("library", "")) != "oqs":
        return False
    mechanism = str(public_key.get("mechanism", ""))
    public_key_hex = str(public_key.get("public_key_hex", ""))
    signature_hex = str(signature.get("signature_hex", ""))
    if not mechanism or not public_key_hex or not signature_hex:
        return False
    try:
        oqs_module = _load_oqs()
        _ensure_mechanism_supported(oqs_module, mechanism)
        verifier = _new_signature(oqs_module, mechanism)
        verify_function = getattr(verifier, "verify", None)
        if not callable(verify_function):
            raise ValueError("The installed OQS Signature object does not expose verify().")
        return bool(verify_function(message, bytes.fromhex(signature_hex), bytes.fromhex(public_key_hex)))
    except ValueError:
        return False


def address_from_public_key(public_key: object) -> str:
    if not isinstance(public_key, dict):
        raise ValueError("OQS-backed ML-DSA public key must be an object.")
    public_key_hex = str(public_key.get("public_key_hex", ""))
    if not public_key_hex:
        raise ValueError("OQS-backed ML-DSA public key is missing public_key_hex.")
    return _address_from_public_key_bytes(bytes.fromhex(public_key_hex))


def serialize_keypair(keypair: object) -> object:
    if not isinstance(keypair, OQSMLDSAKeyPair):
        raise ValueError("Invalid keypair for OQS-backed ML-DSA backend.")
    return {
        "mechanism": keypair.mechanism,
        "public_key_hex": keypair.public_key_hex,
        "secret_key_hex": keypair.secret_key_hex,
    }


def deserialize_keypair(payload: object) -> OQSMLDSAKeyPair:
    if not isinstance(payload, dict):
        raise ValueError("OQS-backed ML-DSA key payload must be an object.")
    return OQSMLDSAKeyPair(
        mechanism=str(payload["mechanism"]),
        public_key_hex=str(payload["public_key_hex"]),
        secret_key_hex=str(payload["secret_key_hex"]),
    )


def reserve_signing_material(keypair: object) -> object:
    return None


def sign_with_reservation(keypair: object, message: bytes, reservation: object) -> tuple[object, object]:
    return sign(keypair, message)
