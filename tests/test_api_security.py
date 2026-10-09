from __future__ import annotations

import io
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from qr_blockchain.api import NodeRequestHandler


class _ResponseCapture:
    def __init__(self) -> None:
        self.calls: list[tuple[object, object, object]] = []

    def __call__(self, status, payload, *, headers=None) -> None:
        self.calls.append((status, payload, headers))


class ApiSecurityTests(unittest.TestCase):
    def make_handler(self, *, bind_host: str, deployment_mode: str, token: str, authorization: str = ""):
        handler = NodeRequestHandler.__new__(NodeRequestHandler)
        handler.service = SimpleNamespace(
            config=SimpleNamespace(
                api_auth_token=token,
                deployment_mode=deployment_mode,
                max_api_request_bytes=64,
                max_public_transaction_requests_per_minute=60,
            )
        )
        handler.server = SimpleNamespace(server_address=(bind_host, 8080))
        handler.headers = {"Authorization": authorization}
        handler.client_address = ("198.51.100.9", 12345)
        handler.rfile = io.BytesIO(b"{}")
        capture = _ResponseCapture()
        handler._respond = capture
        return handler, capture

    def test_development_loopback_does_not_require_operator_token(self) -> None:
        handler, _ = self.make_handler(
            bind_host="127.0.0.1",
            deployment_mode="development",
            token="",
        )
        self.assertFalse(handler._operator_auth_required())
        self.assertTrue(handler._authorize_operator())

    def test_non_loopback_requires_configured_token(self) -> None:
        handler, capture = self.make_handler(
            bind_host="0.0.0.0",
            deployment_mode="development",
            token="secret",
        )
        self.assertTrue(handler._operator_auth_required())
        self.assertFalse(handler._authorize_operator())
        self.assertEqual(capture.calls[-1][0].value, 401)

    def test_bearer_token_is_checked_constant_time(self) -> None:
        handler, _ = self.make_handler(
            bind_host="0.0.0.0",
            deployment_mode="production",
            token="secret",
            authorization="Bearer secret",
        )
        self.assertTrue(handler._authorize_operator())

    def test_production_loopback_requires_operator_token(self) -> None:
        handler, capture = self.make_handler(
            bind_host="127.0.0.1",
            deployment_mode="production",
            token="",
        )
        self.assertTrue(handler._operator_auth_required())
        self.assertFalse(handler._authorize_operator())
        self.assertEqual(capture.calls[-1][0].value, 503)

    def test_rejects_request_body_over_configured_limit(self) -> None:
        handler, _ = self.make_handler(
            bind_host="127.0.0.1", deployment_mode="development", token=""
        )
        handler.headers = {"Content-Length": "65"}
        with self.assertRaisesRegex(ValueError, "size limit"):
            handler._read_json()

    def test_rejects_malformed_and_non_object_json(self) -> None:
        handler, _ = self.make_handler(
            bind_host="127.0.0.1", deployment_mode="development", token=""
        )
        for body in (b"{", b"[]", b"null", b"\xff"):
            with self.subTest(body=body):
                handler.headers = {"Content-Length": str(len(body))}
                handler.rfile = io.BytesIO(body)
                with self.assertRaises(ValueError):
                    handler._read_json()

    def test_public_transaction_rate_limit_is_shared_and_returns_retry_after(self) -> None:
        handler, capture = self.make_handler(
            bind_host="127.0.0.1", deployment_mode="development", token=""
        )
        handler.service.config.max_public_transaction_requests_per_minute = 1
        NodeRequestHandler._transaction_rate_windows = {}
        with patch("qr_blockchain.api.time.monotonic", return_value=100.0):
            self.assertTrue(handler._allow_public_transaction())
            self.assertFalse(handler._allow_public_transaction())
        self.assertEqual(capture.calls[-1][0].value, 429)
        self.assertEqual(capture.calls[-1][2]["Retry-After"], "60")
        NodeRequestHandler._transaction_rate_windows = {}


if __name__ == "__main__":
    unittest.main()
