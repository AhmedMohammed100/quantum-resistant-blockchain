from __future__ import annotations


XMSS_BACKEND_API_VERSION = 1
EXPECTED_SCHEME_ID = "xmss_nist_v1"
EXPECTED_ALGORITHM_FAMILY = "xmss"

REQUIRED_FUNCTIONS = (
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

REQUIRED_MANIFEST_FIELDS = (
    "backend_name",
    "api_version",
    "scheme_id",
    "algorithm_family",
    "implementation_type",
    "supports_signing",
    "supports_stateful_signing",
    "supports_reserved_signing",
)


def _manifest_from_module(module: object) -> dict[str, object]:
    manifest = getattr(module, "XMSS_BACKEND_MANIFEST", None)
    if manifest is None:
        manifest_factory = getattr(module, "backend_manifest", None)
        if callable(manifest_factory):
            manifest = manifest_factory()
    if not isinstance(manifest, dict):
        raise ValueError(
            f"XMSS backend '{getattr(module, '__name__', type(module).__name__)}' must expose "
            "'XMSS_BACKEND_MANIFEST' or backend_manifest()."
        )
    return manifest


def validate_backend_module(module: object) -> dict[str, object]:
    manifest = _manifest_from_module(module)
    missing_fields = [field for field in REQUIRED_MANIFEST_FIELDS if field not in manifest]
    if missing_fields:
        raise ValueError(
            f"XMSS backend '{getattr(module, '__name__', type(module).__name__)}' is missing manifest fields: "
            f"{', '.join(missing_fields)}."
        )

    if int(manifest["api_version"]) != XMSS_BACKEND_API_VERSION:
        raise ValueError(
            f"XMSS backend '{getattr(module, '__name__', type(module).__name__)}' declares unsupported "
            f"api_version {manifest['api_version']}. Expected {XMSS_BACKEND_API_VERSION}."
        )
    if str(manifest["scheme_id"]) != EXPECTED_SCHEME_ID:
        raise ValueError(
            f"XMSS backend '{getattr(module, '__name__', type(module).__name__)}' declares unsupported "
            f"scheme_id '{manifest['scheme_id']}'. Expected '{EXPECTED_SCHEME_ID}'."
        )
    if str(manifest["algorithm_family"]).lower() != EXPECTED_ALGORITHM_FAMILY:
        raise ValueError(
            f"XMSS backend '{getattr(module, '__name__', type(module).__name__)}' declares unsupported "
            f"algorithm_family '{manifest['algorithm_family']}'. Expected '{EXPECTED_ALGORITHM_FAMILY}'."
        )
    if not bool(manifest["supports_signing"]):
        raise ValueError(
            f"XMSS backend '{getattr(module, '__name__', type(module).__name__)}' must support signing."
        )
    if not bool(manifest["supports_stateful_signing"]):
        raise ValueError(
            f"XMSS backend '{getattr(module, '__name__', type(module).__name__)}' must support stateful signing."
        )
    if not bool(manifest["supports_reserved_signing"]):
        raise ValueError(
            f"XMSS backend '{getattr(module, '__name__', type(module).__name__)}' must support reserved signing."
        )

    missing_functions = [
        name
        for name in REQUIRED_FUNCTIONS
        if not callable(getattr(module, name, None))
    ]
    if missing_functions:
        raise ValueError(
            f"XMSS backend '{getattr(module, '__name__', type(module).__name__)}' is missing required callables: "
            f"{', '.join(missing_functions)}."
        )

    return {
        "status": "available",
        "backend_module": getattr(module, "__name__", type(module).__name__),
        "backend_name": str(manifest["backend_name"]),
        "api_version": int(manifest["api_version"]),
        "scheme_id": str(manifest["scheme_id"]),
        "algorithm_family": str(manifest["algorithm_family"]),
        "implementation_type": str(manifest["implementation_type"]),
        "supports_signing": bool(manifest["supports_signing"]),
        "supports_stateful_signing": bool(manifest["supports_stateful_signing"]),
        "supports_reserved_signing": bool(manifest["supports_reserved_signing"]),
    }
