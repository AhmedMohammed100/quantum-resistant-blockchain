from __future__ import annotations

import unittest
from http.server import BaseHTTPRequestHandler
from unittest.mock import Mock, patch

from qr_blockchain.api import BoundedThreadingHTTPServer


class ApiConcurrencyTests(unittest.TestCase):
    def test_nonpositive_worker_limit_is_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "must be positive"):
            BoundedThreadingHTTPServer(
                ("127.0.0.1", 0),
                BaseHTTPRequestHandler,
                max_concurrent_requests=0,
            )

    def test_full_worker_pool_closes_excess_connection_without_spawning_work(self) -> None:
        server = BoundedThreadingHTTPServer(
            ("127.0.0.1", 0),
            BaseHTTPRequestHandler,
            max_concurrent_requests=1,
        )
        self.addCleanup(server.server_close)
        self.assertTrue(server._request_slots.acquire(blocking=False))
        request = Mock()

        with patch.object(server, "shutdown_request") as shutdown:
            server.process_request(request, ("127.0.0.1", 12345))

        shutdown.assert_called_once_with(request)
        self.assertFalse(server._request_slots.acquire(blocking=False))
        server._request_slots.release()

    def test_worker_slot_is_released_when_request_handler_fails(self) -> None:
        server = BoundedThreadingHTTPServer(
            ("127.0.0.1", 0),
            BaseHTTPRequestHandler,
            max_concurrent_requests=1,
        )
        self.addCleanup(server.server_close)
        self.assertTrue(server._request_slots.acquire(blocking=False))

        with patch.object(server, "finish_request", side_effect=RuntimeError("handler failed")):
            with patch.object(server, "handle_error"):
                with patch.object(server, "shutdown_request"):
                    server.process_request_thread(Mock(), ("127.0.0.1", 12345))

        self.assertTrue(server._request_slots.acquire(blocking=False))
        server._request_slots.release()


if __name__ == "__main__":
    unittest.main()
