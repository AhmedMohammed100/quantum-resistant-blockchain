from __future__ import annotations

import hashlib
import hmac
import json
import os
from pathlib import Path
import secrets
from typing import Any


SCHEME_ID = "native_test_pq_v1"
API_VERSION = 1


def _load_extension() -> object | None:
    mode = os.getenv("QR_CHAIN_NATIVE_SIGNER_MODE", "deterministic-test").strip().lower()
    if mode in {"extension", "native", "rust"}:
        liboqs_dir = Path(os.getenv("LIBOQS_DIR", str(Path.home() / "_oqs")))
        oqs_bin = liboqs_dir / "bin"
        if oqs_bin.exists() and hasattr(os, "add_dll_directory"):
            os.add_dll_directory(str(oqs_bin))
        try:
            from . import _native  # type: ignore
        except ImportError as error:
            raise ValueError(
                "Native signer extension qr_chain_native_signer._native is not installed. "
                "Build crates/qr_chain_native_signer with the python feature before using native mode."
            ) from error
        return _native
    return None


def _digest_hex(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _canonical(data: object) -> bytes:
    return json.dumps(data, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _native_algorithm() -> str:
    return os.getenv("QR_CHAIN_NATIVE_SIGNER_ALGORITHM", "ML-DSA-65").strip() or "ML-DSA-65"


def backend_info() -> dict[str, object]:
    extension = _load_extension()
    if extension is not None:
        raw_info = extension.backend_info_py()
        try:
            info = json.loads(raw_info)
        except json.JSONDecodeError:
            info = {"raw_native_info": str(raw_info)}
        return {
            "backend_name": "qr_chain_native_signer",
            "backend_module": __name__,
            "api_version": API_VERSION,
            "implementation_mode": "rust_extension",
            "native_extension_loaded": True,
            "liboqs_feature": bool(info.get("backend_mode") == "liboqs"),
            "default_algorithm": _native_algorithm(),
            **info,
        }
    return {
        "backend_name": "qr_chain_native_signer",
        "backend_module": __name__,
        "api_version": API_VERSION,
        "implementation_mode": "deterministic_test",
        "native_extension_loaded": False,
        "liboqs_feature": False,
        "security_notice": "deterministic test backend only; not valid for production funds",
        "rust_crate": "crates/qr_chain_native_signer",
    }


def generate_keypair() -> dict[str, object]:
    seed = secrets.token_hex(32)
    extension = _load_extension()
    if extension is not None:
        if os.getenv("QR_CHAIN_NATIVE_SIGNER_USE_LIBOQS", "true").strip().lower() not in {"0", "false", "no"}:
            algorithm = _native_algorithm()
            public_key, secret_key = extension.generate_oqs_keypair_py(algorithm)
            return {
                "scheme_id": SCHEME_ID,
                "public_key": public_key,
                "secret_key": secret_key,
                "backend": "qr_chain_native_signer",
                "mode": "liboqs",
                "algorithm": algorithm,
            }
        public_key, secret_key = extension.generate_test_keypair_py(seed)
    else:
        secret_key = "native-test-secret-" + _digest_hex(seed.encode("utf-8"))
        public_key = "native-test-public-" + _digest_hex(secret_key.encode("utf-8"))
    return {
        "scheme_id": SCHEME_ID,
        "public_key": public_key,
        "secret_key": secret_key,
        "backend": "qr_chain_native_signer",
        "mode": "deterministic_test",
    }


def export_public_key(keypair: object) -> dict[str, object]:
    if not isinstance(keypair, dict):
        raise ValueError("Native signer keypair must be an object.")
    return {
        "scheme_id": SCHEME_ID,
        "public_key": str(keypair["public_key"]),
        "backend": "qr_chain_native_signer",
        "mode": str(keypair.get("mode", "deterministic_test")),
        "algorithm": str(keypair.get("algorithm", "")),
    }


def address_from_public_key(public_key: object) -> str:
    if not isinstance(public_key, dict):
        raise ValueError("Native signer public key must be an object.")
    return "qbc-native-test-" + _digest_hex(_canonical(public_key))[:40]


def derive_address(keypair: object) -> str:
    return address_from_public_key(export_public_key(keypair))


def sign(keypair: object, message: bytes) -> tuple[dict[str, object], dict[str, object]]:
    if not isinstance(keypair, dict):
        raise ValueError("Native signer keypair must be an object.")
    public_key = export_public_key(keypair)
    extension = _load_extension()
    if extension is not None and str(keypair.get("mode", "")) == "liboqs":
        signature_value = extension.sign_oqs_py(str(keypair.get("algorithm", _native_algorithm())), str(keypair["secret_key"]), message)
    elif extension is not None:
        signature_value = extension.sign_test_py(str(public_key["public_key"]), message)
    else:
        signature_value = hmac.new(
            str(public_key["public_key"]).encode("utf-8"),
            message,
            hashlib.sha256,
        ).hexdigest()
    signature = {
        "scheme_id": SCHEME_ID,
        "signature": signature_value,
        "backend": "qr_chain_native_signer",
        "mode": backend_info()["implementation_mode"],
        "algorithm": str(keypair.get("algorithm", "")),
    }
    return public_key, signature


def verify(message: bytes, signature: object, public_key: object) -> bool:
    if not isinstance(signature, dict) or not isinstance(public_key, dict):
        return False
    extension = _load_extension()
    if extension is not None and str(public_key.get("mode", "")) == "liboqs":
        return bool(
            extension.verify_oqs_py(
                str(public_key.get("algorithm", _native_algorithm())),
                str(public_key.get("public_key", "")),
                message,
                str(signature.get("signature", "")),
            )
        )
    if extension is not None:
        return bool(
            extension.verify_test_py(
                str(public_key.get("public_key", "")),
                message,
                str(signature.get("signature", "")),
            )
        )
    expected = hmac.new(
        str(public_key.get("public_key", "")).encode("utf-8"),
        message,
        hashlib.sha256,
    ).hexdigest()
    return hmac.compare_digest(expected, str(signature.get("signature", "")))


def verify_batch(items: list[dict[str, object]], *, max_workers: int | None = None) -> dict[str, object]:
    extension = _load_extension()
    if extension is None:
        raise ValueError(
            "Native batch verification requires the compiled Rust extension "
            "qr_chain_native_signer._native. Set QR_CHAIN_NATIVE_SIGNER_MODE=extension "
            "after building crates/qr_chain_native_signer."
        )

    prepared_items: list[dict[str, object]] = []
    for item in items:
        message = item.get("message")
        if not isinstance(message, bytes):
            raise ValueError("Native batch verification item 'message' must be bytes.")
        public_key = item.get("public_key")
        signature = item.get("signature")
        if not isinstance(public_key, dict) or not isinstance(signature, dict):
            raise ValueError("Native batch verification requires object public keys and signatures.")
        prepared_items.append(
            {
                "input_index": int(item.get("input_index", len(prepared_items))),
                "message_hex": message.hex(),
                "public_key": public_key,
                "signature": signature,
            }
        )

    payload = {
        "items": prepared_items,
        "max_workers": max_workers,
    }
    raw_result = extension.verify_native_batch_py(json.dumps(payload, sort_keys=True, separators=(",", ":")))
    try:
        result = json.loads(raw_result)
    except json.JSONDecodeError as error:
        raise ValueError("Native batch verification returned invalid JSON.") from error
    if not isinstance(result, dict):
        raise ValueError("Native batch verification returned a non-object result.")
    return result


def serialize_keypair(keypair: object) -> dict[str, object]:
    if not isinstance(keypair, dict):
        raise ValueError("Native signer keypair must be an object.")
    return dict(keypair)


def deserialize_keypair(payload: object) -> dict[str, object]:
    if not isinstance(payload, dict):
        raise ValueError("Native signer key payload must be an object.")
    required = {"scheme_id", "public_key", "secret_key", "backend"}
    missing = sorted(required - set(payload))
    if missing:
        raise ValueError(f"Native signer key payload missing fields: {', '.join(missing)}.")
    return dict(payload)


def reserve_signing_material(keypair: object) -> None:
    return None


def sign_with_reservation(keypair: object, message: bytes, reservation: object) -> tuple[dict[str, object], dict[str, object]]:
    return sign(keypair, message)


__all__ = [
    "address_from_public_key",
    "backend_info",
    "derive_address",
    "deserialize_keypair",
    "export_public_key",
    "generate_keypair",
    "reserve_signing_material",
    "serialize_keypair",
    "sign",
    "sign_with_reservation",
    "verify",
    "verify_batch",
]
