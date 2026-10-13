from __future__ import annotations

import ssl
import unittest
from unittest.mock import patch

from qr_blockchain.rate_limit import _create_redis_tls_context


class RedisTlsSecurityTests(unittest.TestCase):
    def test_redis_tls_requires_tls_12_or_newer(self) -> None:
        context = _create_redis_tls_context()
        self.assertEqual(context.minimum_version, ssl.TLSVersion.TLSv1_2)

    def test_redis_tls_verifies_certificates_and_hostname(self) -> None:
        context = _create_redis_tls_context()
        self.assertEqual(context.verify_mode, ssl.CERT_REQUIRED)
        self.assertTrue(context.check_hostname)

    def test_tls_context_starts_from_secure_platform_defaults(self) -> None:
        with patch("qr_blockchain.rate_limit.ssl.create_default_context", wraps=ssl.create_default_context) as factory:
            context = _create_redis_tls_context()
        factory.assert_called_once_with()
        self.assertGreaterEqual(context.minimum_version, ssl.TLSVersion.TLSv1_2)


if __name__ == "__main__":
    unittest.main()
