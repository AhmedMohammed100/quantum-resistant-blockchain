from __future__ import annotations

import json
from urllib import parse, request


def normalize_peer_url(url: str) -> str:
    normalized = url.strip().rstrip("/")
    if not normalized:
        raise ValueError("Peer URL cannot be empty.")
    if not normalized.startswith("http://") and not normalized.startswith("https://"):
        normalized = f"http://{normalized}"
    return normalized


def fetch_json(url: str, *, method: str = "GET", payload: dict[str, object] | None = None, timeout: float = 10.0) -> dict[str, object]:
    data = None
    headers = {"Content-Type": "application/json", "Accept": "application/json"}
    if payload is not None:
        data = json.dumps(payload, sort_keys=True).encode("utf-8")
    req = request.Request(url, data=data, headers=headers, method=method)
    with request.urlopen(req, timeout=timeout) as response:
        body = response.read()
    return json.loads(body.decode("utf-8")) if body else {}


def with_path(base_url: str, path: str) -> str:
    return parse.urljoin(normalize_peer_url(base_url) + "/", path.lstrip("/"))
