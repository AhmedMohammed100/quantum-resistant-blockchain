from __future__ import annotations

from dataclasses import dataclass

from .contract import EXPECTED_ALGORITHM_FAMILY, EXPECTED_SCHEME_ID, XMSS_BACKEND_API_VERSION
from qr_blockchain.lamport import LamportKeyPair, address_from_public_key as lamport_address_from_public_key, sha256_hex, verify_signature


def _normalize_lamport_public_key(public_key: object) -> list[list[str]]:
    if not isinstance(public_key, list):
        raise ValueError("Lamport public key must be a list.")
    return [[str(value) for value in row] for row in public_key]


def _normalize_lamport_signature(signature: object) -> list[str]:
    if not isinstance(signature, list):
        raise ValueError("Lamport signature must be a list.")
    return [str(value) for value in signature]


@dataclass
class ReferenceXMSSKeyPair:
    height: int
    leaf_keypairs: list[LamportKeyPair]
    leaf_hashes: list[str]
    auth_paths: list[list[str]]
    root: str
    next_index: int = 0


XMSS_BACKEND_MANIFEST = {
    "backend_name": "in_repo_reference_xmss",
    "api_version": XMSS_BACKEND_API_VERSION,
    "scheme_id": EXPECTED_SCHEME_ID,
    "algorithm_family": EXPECTED_ALGORITHM_FAMILY,
    "implementation_type": "reference",
    "supports_signing": True,
    "supports_stateful_signing": True,
    "supports_reserved_signing": True,
}


def backend_info() -> dict[str, object]:
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
    }


def _leaf_hash(public_key: tuple[tuple[str, str], ...] | list[list[str]]) -> str:
    return sha256_hex(("leaf:" + lamport_address_from_public_key(public_key)).encode("utf-8"))


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


def generate_keypair(height: int = 4) -> ReferenceXMSSKeyPair:
    if height <= 0:
        raise ValueError("XMSS tree height must be positive.")

    leaf_count = 2 ** height
    leaf_keypairs = [LamportKeyPair.generate() for _ in range(leaf_count)]
    leaf_hashes = [_leaf_hash(keypair.public_key) for keypair in leaf_keypairs]
    root, auth_paths = _build_merkle_tree(leaf_hashes)
    return ReferenceXMSSKeyPair(
        height=height,
        leaf_keypairs=leaf_keypairs,
        leaf_hashes=leaf_hashes,
        auth_paths=auth_paths,
        root=root,
        next_index=0,
    )


def derive_address(keypair: object) -> str:
    if not isinstance(keypair, ReferenceXMSSKeyPair):
        raise ValueError("Invalid keypair for reference XMSS backend.")
    return keypair.root


def export_public_key(keypair: object) -> object:
    if not isinstance(keypair, ReferenceXMSSKeyPair):
        raise ValueError("Invalid keypair for reference XMSS backend.")
    return {
        "root": keypair.root,
        "height": keypair.height,
        "scheme": "xmss_nist_v1",
        "provider": "xmss_nist_v1",
    }


def sign(keypair: object, message: bytes) -> tuple[object, object]:
    reservation = reserve_signing_material(keypair)
    return sign_with_reservation(keypair, message, reservation)


def verify(message: bytes, signature: object, public_key: object) -> bool:
    if not isinstance(public_key, dict) or not isinstance(signature, dict):
        return False

    root = str(public_key.get("root", ""))
    leaf_index = int(signature.get("leaf_index", -1))
    auth_path_raw = signature.get("auth_path", [])
    leaf_public_key_raw = signature.get("leaf_public_key", [])
    lamport_signature_raw = signature.get("lamport_signature", [])

    if leaf_index < 0 or not isinstance(auth_path_raw, list):
        return False

    try:
        leaf_public_key = _normalize_lamport_public_key(leaf_public_key_raw)
        lamport_signature = _normalize_lamport_signature(lamport_signature_raw)
    except ValueError:
        return False

    auth_path = [str(item) for item in auth_path_raw]

    if not verify_signature(message, lamport_signature, leaf_public_key):
        return False

    leaf_hash = _leaf_hash(leaf_public_key)
    derived_root = _root_from_auth_path(leaf_hash, leaf_index, auth_path)
    return derived_root == root


def address_from_public_key(public_key: object) -> str:
    if not isinstance(public_key, dict):
        raise ValueError("XMSS public key must be an object.")
    root = str(public_key.get("root", ""))
    if not root:
        raise ValueError("XMSS public key is missing the Merkle root.")
    return root


def serialize_keypair(keypair: object) -> object:
    if not isinstance(keypair, ReferenceXMSSKeyPair):
        raise ValueError("Invalid keypair for reference XMSS backend.")
    return {
        "height": keypair.height,
        "root": keypair.root,
        "next_index": keypair.next_index,
        "leaf_hashes": list(keypair.leaf_hashes),
        "auth_paths": [list(path) for path in keypair.auth_paths],
        "leaf_keypairs": [
            {
                "private_key": [list(pair) for pair in item.private_key],
                "public_key": [list(pair) for pair in item.public_key],
            }
            for item in keypair.leaf_keypairs
        ],
    }


def deserialize_keypair(payload: object) -> ReferenceXMSSKeyPair:
    if not isinstance(payload, dict):
        raise ValueError("Reference XMSS key payload must be an object.")
    return ReferenceXMSSKeyPair(
        height=int(payload["height"]),
        root=str(payload["root"]),
        next_index=int(payload.get("next_index", 0)),
        leaf_hashes=[str(item) for item in payload.get("leaf_hashes", [])],
        auth_paths=[[str(value) for value in path] for path in payload.get("auth_paths", [])],
        leaf_keypairs=[
            LamportKeyPair(
                private_key=tuple((str(pair[0]), str(pair[1])) for pair in item.get("private_key", [])),
                public_key=tuple((str(pair[0]), str(pair[1])) for pair in item.get("public_key", [])),
            )
            for item in payload.get("leaf_keypairs", [])
        ],
    )


def reserve_signing_material(keypair: object) -> object:
    if not isinstance(keypair, ReferenceXMSSKeyPair):
        raise ValueError("Invalid keypair for reference XMSS backend.")
    if keypair.next_index >= len(keypair.leaf_keypairs):
        raise ValueError("Reference XMSS keypair has exhausted all one-time leaves.")
    leaf_index = keypair.next_index
    keypair.next_index += 1
    return {"leaf_index": leaf_index}


def sign_with_reservation(keypair: object, message: bytes, reservation: object) -> tuple[object, object]:
    if not isinstance(keypair, ReferenceXMSSKeyPair):
        raise ValueError("Invalid keypair for reference XMSS backend.")
    if not isinstance(reservation, dict) or "leaf_index" not in reservation:
        raise ValueError("Reference XMSS signing requires a reserved leaf index.")

    leaf_index = int(reservation["leaf_index"])
    leaf_keypair = keypair.leaf_keypairs[leaf_index]
    signature = {
        "leaf_index": leaf_index,
        "leaf_public_key": [list(row) for row in leaf_keypair.public_key],
        "lamport_signature": leaf_keypair.sign(message),
        "auth_path": list(keypair.auth_paths[leaf_index]),
    }
    return export_public_key(keypair), signature
