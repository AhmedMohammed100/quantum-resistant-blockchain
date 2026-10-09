from __future__ import annotations

import json
from urllib import parse, request


DEFAULT_MAX_RESPONSE_BYTES = 8 * 1024 * 1024


def normalize_peer_url(url: str) -> str:
    """Normalize a peer base URL and reject ambiguous or credential-bearing URLs.

    Private and loopback addresses are intentionally not banned because local
    development and private-network deployments are supported. Internet-facing
    deployments should additionally enable the peer allowlist.
    """
    if not isinstance(url, str) or not url.strip():
        raise ValueError("Peer URL cannot be empty.")
    if any(ord(char) < 32 or ord(char) == 127 for char in url):
        raise ValueError("Peer URL contains control characters.")
    normalized = url.strip().rstrip("/")
    if not normalized.startswith(("http://", "https://")):
        normalized = f"http://{normalized}"
    try:
        parsed = parse.urlsplit(normalized)
        # Accessing .port also validates malformed/out-of-range port values.
        _ = parsed.port
    except ValueError as error:
        raise ValueError("Peer URL is malformed.") from error
    if parsed.scheme.lower() not in {"http", "https"}:
        raise ValueError("Peer URL scheme must be HTTP or HTTPS.")
    if not parsed.hostname:
        raise ValueError("Peer URL must include a hostname.")
    if parsed.username is not None or parsed.password is not None:
        raise ValueError("Peer URL must not embed credentials.")
    if parsed.query or parsed.fragment:
        raise ValueError("Peer base URL must not include a query or fragment.")
    return normalized


def fetch_json(
    url: str,
    *,
    method: str = "GET",
    payload: dict[str, object] | None = None,
    timeout: float = 10.0,
    max_response_bytes: int = DEFAULT_MAX_RESPONSE_BYTES,
) -> dict[str, object]:
    """Fetch a bounded JSON object from a peer.

    Both Content-Length and the actual read are bounded: Content-Length is
    untrusted and may be missing or incorrect. A response must decode to a
    JSON object because peer API consumers expect object-shaped envelopes.
    """
    if timeout <= 0:
        raise ValueError("Peer request timeout must be positive.")
    if max_response_bytes <= 0:
        raise ValueError("Maximum peer response size must be positive.")

    data = None
    headers = {"Content-Type": "application/json", "Accept": "application/json"}
    if payload is not None:
        data = json.dumps(payload, sort_keys=True).encode("utf-8")
    req = request.Request(url, data=data, headers=headers, method=method)
    with request.urlopen(req, timeout=timeout) as response:
        content_length = response.headers.get("Content-Length")
        if content_length is not None:
            try:
                declared_length = int(content_length)
            except (TypeError, ValueError) as error:
                raise ValueError("Peer response has an invalid Content-Length.") from error
            if declared_length < 0:
                raise ValueError("Peer response has a negative Content-Length.")
            if declared_length > max_response_bytes:
                raise ValueError("Peer response exceeds the configured size limit.")
        body = response.read(max_response_bytes + 1)

    if len(body) > max_response_bytes:
        raise ValueError("Peer response exceeds the configured size limit.")
    if not body:
        return {}
    try:
        decoded = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError("Peer response is not valid UTF-8 JSON.") from error
    if not isinstance(decoded, dict):
        raise ValueError("Peer response JSON must be an object.")
    return decoded


def with_path(base_url: str, path: str) -> str:
    return parse.urljoin(normalize_peer_url(base_url) + "/", path.lstrip("/"))
