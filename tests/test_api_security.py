from __future__ import annotations

import unittest
from types import SimpleNamespace

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
            )
        )
        handler.server = SimpleNamespace(server_address=(bind_host, 8080))
        handler.headers = {"Authorization": authorization}
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


if __name__ == "__main__":
    unittest.main()
