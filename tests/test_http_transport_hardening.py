from __future__ import annotations

import io
from http import HTTPStatus
import threading
import unittest
from email.message import Message
from types import SimpleNamespace
from unittest.mock import patch

from qr_blockchain.api import NodeRequestHandler
from qr_blockchain.network import fetch_json


class _ResponseCapture:
    def __init__(self) -> None:
        self.calls: list[tuple[object, object, object]] = []

    def __call__(self, status, payload, *, headers=None) -> None:
        self.calls.append((status, payload, headers))


class _FakeResponse:
    def __init__(self, body: bytes, headers: dict[str, str] | None = None):
        self.body = body
        self.headers = headers or {}

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, traceback):
        return False

    def read(self, size: int = -1) -> bytes:
        return self.body if size < 0 else self.body[:size]


class HttpTransportHardeningTests(unittest.TestCase):
    def make_handler(self):
        handler = NodeRequestHandler.__new__(NodeRequestHandler)
        handler.service = SimpleNamespace(config=SimpleNamespace(
            max_api_request_bytes=64,
            http_client_timeout_seconds=3.5,
            max_public_transaction_requests_per_minute=60,
            transaction_rate_limit_redis_url="",
        ))
        handler.headers = Message()
        handler.rfile = io.BytesIO(b'{"ok":true}')
        handler.client_address = ("192.0.2.10", 1234)
        capture = _ResponseCapture()
        handler._respond = capture
        return handler, capture

    def test_rejects_transfer_encoding_instead_of_ambiguous_framing(self):
        handler, _ = self.make_handler()
        handler.headers["Transfer-Encoding"] = "chunked"
        handler.headers["Content-Length"] = "2"
        with self.assertRaisesRegex(ValueError, "Transfer-Encoding"):
            handler._read_json()

    def test_rejects_conflicting_content_length_headers(self):
        handler, _ = self.make_handler()
        handler.headers.add_header("Content-Length", "2")
        handler.headers.add_header("Content-Length", "12")
        with self.assertRaisesRegex(ValueError, "Conflicting Content-Length"):
            handler._read_json()

    def test_rejects_non_json_content_type_but_allows_legacy_missing_header(self):
        handler, _ = self.make_handler()
        handler.headers["Content-Type"] = "text/plain"
        with self.assertRaisesRegex(ValueError, "Content-Type"):
            handler._read_json()

        handler, _ = self.make_handler()
        handler.headers["Content-Length"] = str(len(b'{"ok":true}'))
        self.assertEqual(handler._read_json(), {"ok": True})

    def test_response_sets_cache_and_content_sniffing_guards(self):
        handler, _ = self.make_handler()
        statuses = []
        headers = []
        handler.send_response = lambda status: statuses.append(status)
        handler.send_header = lambda name, value: headers.append((name, value))
        handler.end_headers = lambda: None
        handler.wfile = io.BytesIO()
        handler._respond(HTTPStatus.OK, {"status": "ok"})
        observed = dict(headers)
        self.assertEqual(observed["Cache-Control"], "no-store")
        self.assertEqual(observed["X-Content-Type-Options"], "nosniff")
        self.assertEqual(observed["X-Frame-Options"], "DENY")
        self.assertEqual(observed["Referrer-Policy"], "no-referrer")
        self.assertEqual(observed["Content-Type"], "application/json; charset=utf-8")
        self.assertEqual(statuses, [200])

    def test_setup_applies_configured_socket_timeout(self):
        handler, _ = self.make_handler()
        handler.connection = SimpleNamespace(settimeout=lambda value: setattr(handler, "_timeout", value))
        with patch("http.server.BaseHTTPRequestHandler.setup", lambda self: None):
            handler.setup()
        self.assertEqual(handler._timeout, 3.5)

    def test_invalid_timeout_configuration_falls_back_to_safe_default(self):
        handler, _ = self.make_handler()
        handler.service.config.http_client_timeout_seconds = -1
        handler.connection = SimpleNamespace(settimeout=lambda value: setattr(handler, "_timeout", value))
        with patch("http.server.BaseHTTPRequestHandler.setup", lambda self: None):
            handler.setup()
        self.assertEqual(handler._timeout, 10.0)

    def test_peer_redirect_is_not_followed(self):
        class RedirectResponse:
            headers = {"Location": "http://127.0.0.1:8080/admin"}

            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, traceback):
                return False

            def read(self, size=-1):
                return b'{"unexpected":true}'

        with patch("qr_blockchain.network._open_no_redirect", return_value=RedirectResponse()) as opener:
            result = fetch_json("https://peer.example/summary", allowed_hosts=("peer.example",))
        self.assertEqual(result, {"unexpected": True})
        # The no-redirect opener is the only transport path used by fetch_json.
        self.assertEqual(opener.call_count, 1)


class TransactionRateLimitConcurrencyTests(unittest.TestCase):
    def test_parallel_requests_do_not_exceed_shared_local_budget(self):
        handler_type = NodeRequestHandler
        handler_type._transaction_rate_windows = {}
        handler_type._transaction_rate_lock = threading.Lock()
        allowed = []
        handlers = []
        for _ in range(20):
            handler = NodeRequestHandler.__new__(NodeRequestHandler)
            handler.service = SimpleNamespace(config=SimpleNamespace(
                max_public_transaction_requests_per_minute=5,
                transaction_rate_limit_redis_url="",
            ))
            handler.client_address = ("198.51.100.44", 4321)
            handler._respond = lambda status, payload, *, headers=None: None
            handlers.append(handler)

        def attempt(handler):
            allowed.append(handler._allow_public_transaction())

        with patch("qr_blockchain.api.time.monotonic", return_value=100.0):
            threads = [threading.Thread(target=attempt, args=(handler,)) for handler in handlers]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join(timeout=2)
        self.assertTrue(all(not thread.is_alive() for thread in threads))
        self.assertEqual(sum(allowed), 5)
        handler_type._transaction_rate_windows = {}


if __name__ == "__main__":
    unittest.main()
