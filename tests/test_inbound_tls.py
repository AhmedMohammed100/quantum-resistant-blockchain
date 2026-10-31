from __future__ import annotations

import unittest
from unittest.mock import patch

from qr_blockchain.api import BoundedThreadingHTTPServer
from qr_blockchain.config import NodeConfig


class InboundTlsPolicyTests(unittest.TestCase):
    def test_tls_wraps_accepted_sockets_without_blocking_accept_loop(self) -> None:
        class TlsContext:
            def __init__(self) -> None:
                self.calls = []

            def wrap_socket(self, request, **kwargs):
                self.calls.append((request, kwargs))
                return "wrapped-socket"

        raw_socket = object()
        context = TlsContext()
        server = BoundedThreadingHTTPServer.__new__(BoundedThreadingHTTPServer)
        server._tls_context = context
        with patch("socketserver.TCPServer.get_request", return_value=(raw_socket, ("127.0.0.1", 1234))):
            request, client_address = server.get_request()

        self.assertEqual(request, "wrapped-socket")
        self.assertEqual(client_address, ("127.0.0.1", 1234))
        self.assertEqual(context.calls, [(raw_socket, {
            "server_side": True,
            "do_handshake_on_connect": False,
        })])


    def test_production_non_loopback_listener_requires_tls_material(self) -> None:
        for host in ("0.0.0.0", "192.0.2.10", "::"):
            with self.subTest(host=host):
                config = NodeConfig(deployment_mode="production", host=host)
                with self.assertRaisesRegex(ValueError, "require inbound TLS"):
                    config.validate_inbound_tls()

    def test_production_loopback_listener_can_remain_plain_http(self) -> None:
        for host in ("127.0.0.1", "::1", "localhost"):
            with self.subTest(host=host):
                config = NodeConfig(deployment_mode="production", host=host)
                self.assertFalse(config.validate_inbound_tls())

    def test_development_non_loopback_listener_preserves_explicit_dev_mode(self) -> None:
        config = NodeConfig(deployment_mode="development", host="0.0.0.0")
        self.assertFalse(config.validate_inbound_tls())

    def test_tls_requires_both_certificate_and_private_key(self) -> None:
        config = NodeConfig(
            deployment_mode="production",
            host="0.0.0.0",
            tls_cert_file="server.pem",
        )
        with self.assertRaisesRegex(ValueError, "requires both"):
            config.validate_inbound_tls()

    def test_complete_tls_material_enables_tls(self) -> None:
        config = NodeConfig(
            deployment_mode="production",
            host="0.0.0.0",
            tls_cert_file="server.pem",
            tls_key_file="server-key.pem",
        )
        self.assertTrue(config.validate_inbound_tls())


if __name__ == "__main__":
    unittest.main()
