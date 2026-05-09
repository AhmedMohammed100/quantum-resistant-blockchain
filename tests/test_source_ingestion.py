from __future__ import annotations

from pathlib import Path
import json
import shutil
import unittest

from qr_blockchain import NodeConfig, NodeService
import qr_chain_classical_migration_backend_secp256k1 as secp_backend


class SourceExportIngestionTests(unittest.TestCase):
    def make_service(self) -> NodeService:
        root = Path("test_runtime") / self._testMethodName
        if root.exists():
            shutil.rmtree(root)
        root.mkdir(parents=True, exist_ok=True)
        self.addCleanup(lambda: shutil.rmtree(root, ignore_errors=True))
        return NodeService(
            NodeConfig(
                db_path=root / "chain.db",
                wallet_state_db_path=root / "wallet_state.db",
            )
        )

    def secp_public_key(self, private_key: int = 1) -> dict[str, object]:
        point = secp_backend._point_mul(private_key, secp_backend._G)
        assert point is not None
        public_key_bytes = b"\x04" + point[0].to_bytes(32, "big") + point[1].to_bytes(32, "big")
        return {"public_key_hex": public_key_bytes.hex()}

    def test_normalizes_source_export_with_public_key_linkage(self) -> None:
        service = self.make_service()
        public_key = self.secp_public_key()
        source_address = secp_backend.derive_bitcoin_p2pkh_addresses(public_key)[0]

        normalized = service.normalize_source_export_snapshot(
            {
                "source_network": "legacy-btc-mainnet",
                "snapshot_ref": "btc-export-001",
                "generated_at": 250.0,
                "provider_id": "ecdsa_secp256k1_migration_v1",
                "source_address_format": "bitcoin_base58",
                "records": [
                    {
                        "classical_public_key": public_key,
                        "source_address": source_address,
                        "amount": 42,
                    }
                ],
            },
            sign=True,
        )

        entry = normalized["bundle"]["entries"][0]
        self.assertEqual(entry["classical_address"], secp_backend.address_from_public_key(public_key))
        self.assertEqual(entry["source_address"], source_address)
        self.assertIn("envelope", normalized)

    def test_rejects_source_export_with_mismatched_public_key(self) -> None:
        service = self.make_service()
        public_key = self.secp_public_key(1)
        other_public_key = self.secp_public_key(2)
        source_address = secp_backend.derive_bitcoin_p2pkh_addresses(other_public_key)[0]

        with self.assertRaisesRegex(ValueError, "does not own source_address"):
            service.normalize_source_export_snapshot(
                {
                    "source_network": "legacy-btc-mainnet",
                    "snapshot_ref": "btc-export-002",
                    "generated_at": 251.0,
                    "provider_id": "ecdsa_secp256k1_migration_v1",
                    "source_address_format": "bitcoin_base58",
                    "records": [
                        {
                            "classical_public_key": public_key,
                            "source_address": source_address,
                            "amount": 42,
                        }
                    ],
                }
            )

    def test_normalized_source_export_can_be_imported(self) -> None:
        service = self.make_service()
        public_key = self.secp_public_key()
        source_address = secp_backend.derive_bitcoin_p2pkh_addresses(public_key)[0]
        normalized = service.normalize_source_export_snapshot(
            {
                "source_network": "legacy-btc-mainnet",
                "snapshot_ref": "btc-export-003",
                "generated_at": 252.0,
                "provider_id": "ecdsa_secp256k1_migration_v1",
                "source_address_format": "bitcoin_base58",
                "records": [{"classical_public_key": public_key, "source_address": source_address, "amount": 12}],
            }
        )

        imported = service.import_migration_snapshot(normalized["bundle"])

        self.assertEqual(imported["snapshot_ref"], "btc-export-003")
        self.assertEqual(imported["entry_count"], 1)


if __name__ == "__main__":
    unittest.main()
