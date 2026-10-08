from __future__ import annotations

import io
import unittest
from unittest.mock import patch

from qr_blockchain.network import fetch_json


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


if __name__ == "__main__":
    unittest.main()
