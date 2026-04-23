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
