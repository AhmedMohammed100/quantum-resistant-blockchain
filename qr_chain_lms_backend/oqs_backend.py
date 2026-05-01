from __future__ import annotations

from dataclasses import dataclass
import importlib
import os

from qr_blockchain.lamport import sha256_hex

from .contract import EXPECTED_ALGORITHM_FAMILY, EXPECTED_SCHEME_ID, LMS_BACKEND_API_VERSION


OQS_MECHANISM_ENV = "QR_CHAIN_LMS_OQS_MECHANISM"
DEFAULT_OQS_MECHANISM = "LMS_SHA256_H10_W4"

LMS_BACKEND_MANIFEST = {
    "backend_name": "open_quantum_safe_liboqs_python",
    "api_version": LMS_BACKEND_API_VERSION,
    "scheme_id": EXPECTED_SCHEME_ID,
    "algorithm_family": EXPECTED_ALGORITHM_FAMILY,
    "implementation_type": "library_adapter",
    "supports_signing": True,
    "supports_stateful_signing": True,
    "supports_reserved_signing": True,
}


@dataclass
class OQSLMSKeyPair:
    mechanism: str
    public_key_hex: str
    secret_key_hex: str
    signatures_used: int = 0


def _load_oqs() -> object:
    try:
        return importlib.import_module("oqs")
    except ModuleNotFoundError as error:
        raise ValueError(
            "The OQS-backed LMS adapter requires the 'oqs' Python package from liboqs-python."
        ) from error


def _selected_mechanism() -> str:
    return os.getenv(OQS_MECHANISM_ENV, DEFAULT_OQS_MECHANISM).strip() or DEFAULT_OQS_MECHANISM


def _enabled_lms_mechanisms(oqs_module: object) -> list[str]:
    getter = getattr(oqs_module, "get_enabled_stateful_sig_mechanisms", None)
    if not callable(getter):
        raise ValueError("The installed 'oqs' module does not expose get_enabled_stateful_sig_mechanisms().")
    return [str(item) for item in getter() if str(item).upper().startswith("LMS")]


def _ensure_mechanism_supported(oqs_module: object, mechanism: str) -> None:
    enabled = _enabled_lms_mechanisms(oqs_module)
    if mechanism not in enabled:
        if not enabled:
            raise ValueError("The installed OQS runtime does not report any enabled LMS mechanisms.")
        raise ValueError(f"OQS mechanism '{mechanism}' is not enabled. Available LMS mechanisms: {', '.join(enabled)}.")


def backend_info() -> dict[str, object]:
    oqs_module = _load_oqs()
    mechanism = _selected_mechanism()
    _ensure_mechanism_supported(oqs_module, mechanism)
    return {
        "status": "available",
        "backend_module": __name__,
        "backend_name": str(LMS_BACKEND_MANIFEST["backend_name"]),
        "api_version": int(LMS_BACKEND_MANIFEST["api_version"]),
        "scheme_id": str(LMS_BACKEND_MANIFEST["scheme_id"]),
        "algorithm_family": str(LMS_BACKEND_MANIFEST["algorithm_family"]),
        "implementation_type": str(LMS_BACKEND_MANIFEST["implementation_type"]),
        "supports_signing": True,
        "supports_stateful_signing": True,
        "supports_reserved_signing": True,
        "library_module": getattr(oqs_module, "__name__", "oqs"),
        "library_version": getattr(oqs_module, "__version__", "unknown"),
        "selected_mechanism": mechanism,
        "enabled_mechanisms": _enabled_lms_mechanisms(oqs_module),
    }


def generate_keypair() -> OQSLMSKeyPair:
    oqs_module = _load_oqs()
    mechanism = _selected_mechanism()
    _ensure_mechanism_supported(oqs_module, mechanism)
    signer = oqs_module.StatefulSignature(mechanism)
    public_key = signer.generate_keypair()
    return OQSLMSKeyPair(
        mechanism=mechanism,
        public_key_hex=bytes(public_key).hex(),
        secret_key_hex=bytes(signer.export_secret_key()).hex(),
        signatures_used=0,
    )


def derive_address(keypair: object) -> str:
    if not isinstance(keypair, OQSLMSKeyPair):
        raise ValueError("Invalid keypair for OQS-backed LMS backend.")
    return sha256_hex(b"oqs-lms:" + bytes.fromhex(keypair.public_key_hex))


def export_public_key(keypair: object) -> object:
    if not isinstance(keypair, OQSLMSKeyPair):
        raise ValueError("Invalid keypair for OQS-backed LMS backend.")
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
    mechanism = str(public_key.get("mechanism", ""))
    public_key_hex = str(public_key.get("public_key_hex", ""))
    signature_hex = str(signature.get("signature_hex", ""))
    if not mechanism or not public_key_hex or not signature_hex:
        return False
    oqs_module = _load_oqs()
    _ensure_mechanism_supported(oqs_module, mechanism)
    verifier = oqs_module.StatefulSignature(mechanism)
    return bool(verifier.verify(message, bytes.fromhex(signature_hex), bytes.fromhex(public_key_hex)))


def address_from_public_key(public_key: object) -> str:
    if not isinstance(public_key, dict):
        raise ValueError("OQS-backed LMS public key must be an object.")
    public_key_hex = str(public_key.get("public_key_hex", ""))
    if not public_key_hex:
        raise ValueError("OQS-backed LMS public key is missing public_key_hex.")
    return sha256_hex(b"oqs-lms:" + bytes.fromhex(public_key_hex))


def serialize_keypair(keypair: object) -> object:
    if not isinstance(keypair, OQSLMSKeyPair):
        raise ValueError("Invalid keypair for OQS-backed LMS backend.")
    return {
        "mechanism": keypair.mechanism,
        "public_key_hex": keypair.public_key_hex,
        "secret_key_hex": keypair.secret_key_hex,
        "signatures_used": keypair.signatures_used,
    }


def deserialize_keypair(payload: object) -> OQSLMSKeyPair:
    if not isinstance(payload, dict):
        raise ValueError("OQS-backed LMS key payload must be an object.")
    return OQSLMSKeyPair(
        mechanism=str(payload["mechanism"]),
        public_key_hex=str(payload["public_key_hex"]),
        secret_key_hex=str(payload["secret_key_hex"]),
        signatures_used=int(payload.get("signatures_used", 0)),
    )


def reserve_signing_material(keypair: object) -> object:
    if not isinstance(keypair, OQSLMSKeyPair):
        raise ValueError("Invalid keypair for OQS-backed LMS backend.")
    return {"reservation_id": keypair.signatures_used + 1}


def sign_with_reservation(keypair: object, message: bytes, reservation: object) -> tuple[object, object]:
    if not isinstance(keypair, OQSLMSKeyPair):
        raise ValueError("Invalid keypair for OQS-backed LMS backend.")
    if not isinstance(reservation, dict) or "reservation_id" not in reservation:
        raise ValueError("OQS-backed LMS signing requires a reservation token.")
    oqs_module = _load_oqs()
    _ensure_mechanism_supported(oqs_module, keypair.mechanism)
    signer = oqs_module.StatefulSignature(keypair.mechanism)
    signer.import_secret_key(bytes.fromhex(keypair.secret_key_hex))
    signature = signer.sign(message)
    keypair.secret_key_hex = bytes(signer.export_secret_key()).hex()
    keypair.signatures_used += 1
    return export_public_key(keypair), {
        "mechanism": keypair.mechanism,
        "library": "oqs",
        "signature_hex": bytes(signature).hex(),
        "signatures_used": keypair.signatures_used,
    }
