from __future__ import annotations

import unittest

from qr_blockchain.legacy_networks import validate_legacy_source_binding


class LegacyNetworkValidationTests(unittest.TestCase):
    def test_accepts_bitcoin_base58_source_address(self) -> None:
        validated = validate_legacy_source_binding(
            source_network="legacy-btc-mainnet",
            provider_id="ecdsa_secp256k1_migration_v1",
            classical_address="secp256k1-p2pkh:" + ("1a" * 20),
            source_address="1BoatSLRHtKNngkdXEeobR76b53LETtpyT",
            source_address_format="bitcoin_base58",
        )

        self.assertEqual(validated["source_address_format"], "bitcoin_base58")

    def test_accepts_ethereum_eoa_source_address(self) -> None:
        validated = validate_legacy_source_binding(
            source_network="legacy-eth-mainnet",
            provider_id="ecdsa_secp256k1_migration_v1",
            classical_address="secp256k1-p2pkh:" + ("2b" * 20),
            source_address="0x52908400098527886E0F7030069857D2E4169EE7",
            source_address_format="ethereum_eoa",
        )

        self.assertEqual(validated["source_address_format"], "ethereum_eoa")

    def test_accepts_nested_bitcoin_segwit_source_address(self) -> None:
        validated = validate_legacy_source_binding(
            source_network="legacy-btc-mainnet",
            provider_id="ecdsa_secp256k1_migration_v1",
            classical_address="secp256k1-p2pkh:" + ("2c" * 20),
            source_address="3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy",
            source_address_format="bitcoin_p2sh_p2wpkh",
        )

        self.assertEqual(validated["source_address_format"], "bitcoin_p2sh_p2wpkh")

    def test_rejects_provider_network_mismatch(self) -> None:
        with self.assertRaisesRegex(ValueError, "does not allow migration provider"):
            validate_legacy_source_binding(
                source_network="legacy-rsa-ledger",
                provider_id="ecdsa_secp256k1_migration_v1",
                classical_address="secp256k1-p2pkh:" + ("3c" * 20),
                source_address="1BoatSLRHtKNngkdXEeobR76b53LETtpyT",
                source_address_format="bitcoin_base58",
            )

    def test_rejects_invalid_bitcoin_checksum(self) -> None:
        with self.assertRaisesRegex(ValueError, "checksum"):
            validate_legacy_source_binding(
                source_network="legacy-btc-mainnet",
                provider_id="ecdsa_secp256k1_migration_v1",
                classical_address="secp256k1-p2pkh:" + ("4d" * 20),
                source_address="1BoatSLRHtKNngkdXEeobR76b53LETtpyU",
                source_address_format="bitcoin_base58",
            )


if __name__ == "__main__":
    unittest.main()
