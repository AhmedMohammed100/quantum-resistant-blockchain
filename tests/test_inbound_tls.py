from __future__ import annotations

import unittest

from qr_blockchain.config import NodeConfig


class InboundTlsPolicyTests(unittest.TestCase):
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
