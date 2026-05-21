from __future__ import annotations

import hashlib

from .models import canonical_json


def build_peer_frame(
    *,
    protocol_version: str,
    message_type: str,
    payload: dict[str, object],
    auth: dict[str, object] | None = None,
) -> dict[str, object]:
    frame: dict[str, object] = {
        "protocol_version": protocol_version,
        "message_type": message_type,
        "payload": payload,
    }
    if auth is not None:
        frame["auth"] = auth
    frame["frame_digest"] = frame_digest(protocol_version, message_type, payload)
    return frame


def parse_peer_frame(
    frame: dict[str, object],
    *,
    expected_protocol_version: str,
    expected_message_type: str,
) -> tuple[dict[str, object], dict[str, object]]:
    if not isinstance(frame, dict):
        raise ValueError("Peer frame must be an object.")
    protocol_version = str(frame.get("protocol_version", ""))
    if protocol_version != expected_protocol_version:
        raise ValueError("Peer protocol version is not supported.")
    message_type = str(frame.get("message_type", ""))
    if message_type != expected_message_type:
        raise ValueError("Peer frame message type is invalid.")
    payload = frame.get("payload", {})
    if not isinstance(payload, dict):
        raise ValueError("Peer frame payload must be an object.")
    expected_digest = frame_digest(protocol_version, message_type, payload)
    if str(frame.get("frame_digest", "")) != expected_digest:
        raise ValueError("Peer frame digest is invalid.")
    auth = frame.get("auth", {})
    if auth is None:
        auth = {}
    if not isinstance(auth, dict):
        raise ValueError("Peer frame auth must be an object.")
    return payload, auth


def frame_digest(protocol_version: str, message_type: str, payload: dict[str, object]) -> str:
    return hashlib.sha256(
        canonical_json(
            {
                "protocol_version": protocol_version,
                "message_type": message_type,
                "payload": payload,
            }
        ).encode("utf-8")
    ).hexdigest()


def protocol_manifest(
    *,
    chain_id: str,
    peer_protocol_version: str,
    currency: dict[str, object],
    migration_policy: dict[str, object],
) -> dict[str, object]:
    manifest: dict[str, object] = {
        "protocol_name": "Quantum-Resistant Blockchain",
        "protocol_manifest_version": 1,
        "chain_id": chain_id,
        "native_currency": {
            "name": currency["name"],
            "symbol": currency["symbol"],
            "decimals": currency["decimals"],
            "base_unit": currency["base_unit"],
            "max_money": currency["max_money"],
            "allocation_plan": currency.get("allocation_plan", {}),
        },
        "object_versions": {
            "block_version": 2,
            "transaction_version": 1,
            "migration_snapshot_version": 1,
            "source_ingestion_version": 1,
            "approval_artifact_version": 1,
            "peer_frame_protocol": peer_protocol_version,
        },
        "transaction_kinds": ["transfer", "migration_claim"],
        "peer_message_types": [
            "peer_handshake_request",
            "peer_handshake_response",
            "peer_summary_request",
            "peer_summary_response",
            "peer_blocks_request",
            "peer_blocks_response",
        ],
        "migration": {
            "conversion_policy": migration_policy["conversion_policy"],
            "claim_start_height": migration_policy["claim_start_height"],
            "claim_end_height": migration_policy["claim_end_height"],
            "dual_control_start_height": migration_policy["dual_control_start_height"],
            "dual_control_end_height": migration_policy["dual_control_end_height"],
            "allowed_classical_providers": migration_policy["allowed_classical_providers"],
        },
        "security_controls": [
            "chain-bound transaction signatures",
            "provider-resolved PQ signature verification",
            "stateful signer reservations",
            "signed peer handshakes",
            "peer session nonces",
            "canonical frame digests",
            "review-gated migration snapshots",
            "QBC supply cap enforcement",
        ],
    }
    manifest["protocol_manifest_hash"] = hashlib.sha256(canonical_json(manifest).encode("utf-8")).hexdigest()
    return manifest
