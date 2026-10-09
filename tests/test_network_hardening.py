from __future__ import annotations

import unittest
from unittest.mock import patch

from qr_blockchain.network import fetch_json, normalize_peer_url


class _FakeResponse:
    def __init__(self, body: bytes, headers: dict[str, str] | None = None):
        self._body = body
        self.headers = headers or {}

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, traceback):
        return False

    def read(self, size: int = -1) -> bytes:
        return self._body if size < 0 else self._body[:size]


class PeerResponseHardeningTests(unittest.TestCase):
    def test_accepts_json_object(self) -> None:
        with patch("qr_blockchain.network.request.urlopen", return_value=_FakeResponse(b'{"ok":true}')):
            self.assertEqual(fetch_json("http://peer.invalid/summary"), {"ok": True})

    def test_rejects_oversized_declared_response_before_reading(self) -> None:
        with patch(
            "qr_blockchain.network.request.urlopen",
            return_value=_FakeResponse(b'{"ok":true}', {"Content-Length": "1024"}),
        ):
            with self.assertRaisesRegex(ValueError, "size limit"):
                fetch_json("http://peer.invalid/summary", max_response_bytes=16)

    def test_rejects_oversized_body_when_length_is_missing_or_untrusted(self) -> None:
        with patch(
            "qr_blockchain.network.request.urlopen",
            return_value=_FakeResponse(b"x" * 33),
        ):
            with self.assertRaisesRegex(ValueError, "size limit"):
                fetch_json("http://peer.invalid/summary", max_response_bytes=32)

    def test_rejects_invalid_content_length(self) -> None:
        with patch(
            "qr_blockchain.network.request.urlopen",
            return_value=_FakeResponse(b"{}", {"Content-Length": "unknown"}),
        ):
            with self.assertRaisesRegex(ValueError, "Content-Length"):
                fetch_json("http://peer.invalid/summary")

    def test_rejects_non_object_json_and_invalid_utf8(self) -> None:
        for body in (b"[]", b'"string"', b"\xff"):
            with self.subTest(body=body):
                with patch(
                    "qr_blockchain.network.request.urlopen",
                    return_value=_FakeResponse(body),
                ):
                    with self.assertRaises(ValueError):
                        fetch_json("http://peer.invalid/summary")

    def test_rejects_non_positive_limits(self) -> None:
        with self.assertRaisesRegex(ValueError, "timeout"):
            fetch_json("http://peer.invalid/summary", timeout=0)
        with self.assertRaisesRegex(ValueError, "size"):
            fetch_json("http://peer.invalid/summary", max_response_bytes=0)

    def test_normalizes_bare_host_and_valid_http_urls(self) -> None:
        self.assertEqual(normalize_peer_url("peer.example:8080/"), "http://peer.example:8080")
        self.assertEqual(normalize_peer_url("https://peer.example:8443/api"), "https://peer.example:8443/api")
        self.assertEqual(normalize_peer_url("http://127.0.0.1:8080"), "http://127.0.0.1:8080")

    def test_rejects_ambiguous_or_credential_bearing_peer_urls(self) -> None:
        invalid = (
            "",
            "ftp://peer.example",
            "http://user:password@peer.example",
            "http:///missing-host",
            "http://peer.example:99999",
            "http://peer.example/path?token=secret",
            "http://peer.example/path#fragment",
            "http://peer.example/\nadmin",
        )
        for url in invalid:
            with self.subTest(url=url):
                with self.assertRaises(ValueError):
                    normalize_peer_url(url)


if __name__ == "__main__":
    unittest.main()
