from __future__ import annotations


BACKEND_STATUS = "scaffold_only"
BACKEND_VERSION = "0.1.0"


def _not_integrated(function_name: str) -> ValueError:
    return ValueError(
        "The in-repo XMSS backend scaffold `qr_chain_xmss_backend` is present but no concrete "
        f"XMSS cryptography library is integrated yet. `{function_name}` cannot run until this "
        "module is wired to a real audited backend implementation."
    )


def generate_keypair() -> object:
    raise _not_integrated("generate_keypair")


def derive_address(keypair: object) -> str:
    raise _not_integrated("derive_address")


def sign(keypair: object, message: bytes) -> tuple[object, object]:
    raise _not_integrated("sign")


def serialize_keypair(keypair: object) -> object:
    raise _not_integrated("serialize_keypair")


def deserialize_keypair(payload: object) -> object:
    raise _not_integrated("deserialize_keypair")


def reserve_signing_material(keypair: object) -> object:
    raise _not_integrated("reserve_signing_material")


def sign_with_reservation(keypair: object, message: bytes, reservation: object) -> tuple[object, object]:
    raise _not_integrated("sign_with_reservation")


def verify(message: bytes, signature: object, public_key: object) -> bool:
    raise _not_integrated("verify")


def address_from_public_key(public_key: object) -> str:
    raise _not_integrated("address_from_public_key")
