from __future__ import annotations

import io
import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch

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

    def test_privileged_post_authenticates_before_reading_body(self) -> None:
        handler, capture = self.make_handler(
            bind_host="0.0.0.0",
            deployment_mode="production",
            token="secret",
        )
        handler.path = "/mine"
        handler._read_json = Mock(side_effect=AssertionError("body must not be parsed"))
        handler.close_connection = False

        handler.do_POST()

        handler._read_json.assert_not_called()
        self.assertTrue(handler.close_connection)
        self.assertEqual(capture.calls[-1][0].value, 401)

    def test_privileged_post_reads_body_after_valid_authentication(self) -> None:
        handler, capture = self.make_handler(
            bind_host="0.0.0.0",
            deployment_mode="production",
            token="secret",
            authorization="Bearer secret",
        )
        handler.path = "/mine"
        handler._read_json = Mock(return_value={"miner_address": "miner"})
        block = SimpleNamespace(index=1, block_hash="ab" * 32, transactions=[])
        handler.service.mine_pending_transactions = Mock(return_value=block)

        handler.do_POST()

        handler._read_json.assert_called_once_with()
        handler.service.mine_pending_transactions.assert_called_once_with("miner")
        self.assertEqual(capture.calls[-1][0].value, 201)

    def test_rate_limited_public_post_does_not_read_body_or_keep_connection_open(self) -> None:
        handler, _ = self.make_handler(
            bind_host="127.0.0.1", deployment_mode="development", token=""
        )
        handler.path = "/transactions"
        handler._allow_public_transaction = Mock(return_value=False)
        handler._read_json = Mock(side_effect=AssertionError("body must not be parsed"))
        handler.close_connection = False

        handler.do_POST()

        handler._read_json.assert_not_called()
        self.assertTrue(handler.close_connection)

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

    def test_redis_rate_limit_returns_shared_retry_after(self) -> None:
        handler, capture = self.make_handler(
            bind_host="127.0.0.1", deployment_mode="development", token=""
        )
        handler.service.config.transaction_rate_limit_redis_url = "redis://localhost:6379/0"
        with patch("qr_blockchain.api.enforce_redis_rate_limit", return_value=17) as limiter:
            self.assertFalse(handler._allow_public_transaction())
        self.assertEqual(capture.calls[-1][0].value, 429)
        self.assertEqual(capture.calls[-1][2]["Retry-After"], "17")
        self.assertEqual(limiter.call_args.args[2], 60)

    def test_configured_redis_rate_limit_fails_closed(self) -> None:
        handler, capture = self.make_handler(
            bind_host="127.0.0.1", deployment_mode="development", token=""
        )
        handler.service.config.transaction_rate_limit_redis_url = "redis://localhost:6379/0"
        with patch("qr_blockchain.api.enforce_redis_rate_limit", side_effect=OSError("offline")):
            self.assertFalse(handler._allow_public_transaction())
        self.assertEqual(capture.calls[-1][0].value, 503)
        self.assertEqual(capture.calls[-1][2]["Retry-After"], "5")

    def test_production_requires_shared_rate_limit_backend(self) -> None:
        handler, capture = self.make_handler(
            bind_host="0.0.0.0", deployment_mode="production", token="secret"
        )
        self.assertFalse(handler._allow_public_transaction())
        self.assertEqual(capture.calls[-1][0].value, 503)
        self.assertIn("shared Redis", capture.calls[-1][1]["error"])

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
