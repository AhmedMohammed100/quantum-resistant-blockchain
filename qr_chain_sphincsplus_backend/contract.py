from __future__ import annotations


SPHINCSPLUS_BACKEND_API_VERSION = 1
EXPECTED_SCHEME_ID = "sphincsplus_v1"
EXPECTED_ALGORITHM_FAMILY = "sphincs+"

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
