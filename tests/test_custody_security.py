from __future__ import annotations

import os
import unittest

from qr_blockchain.custody import (
    PlaintextCustodyProvider,
    WalletCustodyConfig,
    build_wallet_custody_provider,
)


class WalletCustodyPolicyTests(unittest.TestCase):
    @unittest.skipIf(os.name == "nt", "Windows auto mode uses DPAPI")
    def test_auto_custody_fails_closed_outside_development(self) -> None:
        for deployment_mode in ("production", "staging", "validator"):
            with self.subTest(deployment_mode=deployment_mode):
                with self.assertRaisesRegex(RuntimeError, "no encrypted provider"):
                    build_wallet_custody_provider(
                        WalletCustodyConfig(mode="auto", deployment_mode=deployment_mode)
                    )

    @unittest.skipIf(os.name == "nt", "Windows auto mode uses DPAPI")
    def test_plaintext_custody_is_forbidden_in_production_even_when_explicit(self) -> None:
        with self.assertRaisesRegex(RuntimeError, "forbidden outside development/test"):
            build_wallet_custody_provider(
                WalletCustodyConfig(mode="plaintext", deployment_mode="production")
            )

    def test_explicit_plaintext_custody_remains_available_in_development(self) -> None:
        provider = build_wallet_custody_provider(
            WalletCustodyConfig(mode="plaintext", deployment_mode="development")
        )
        self.assertIsInstance(provider, PlaintextCustodyProvider)
        self.assertIn("warning", provider.status())

    @unittest.skipUnless(os.name == "nt", "DPAPI is only available on Windows")
    def test_windows_auto_custody_uses_dpapi(self) -> None:
        provider = build_wallet_custody_provider(WalletCustodyConfig(mode="auto"))
        self.assertEqual(provider.backend_id, "windows_dpapi")


if __name__ == "__main__":
    unittest.main()
