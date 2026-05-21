from __future__ import annotations

import os
import unittest
from unittest.mock import patch

from qr_blockchain.config import NodeConfig


class NodeConfigTests(unittest.TestCase):
    def test_from_env_overrides_defaults(self) -> None:
        env = {
            "QR_CHAIN_DB_PATH": "runtime/chain.db",
            "QR_CHAIN_DIFFICULTY": "5",
            "QR_CHAIN_MINING_REWARD": "42",
            "QR_CHAIN_CURRENCY_NAME": "Test Quantum Coin",
            "QR_CHAIN_CURRENCY_SYMBOL": "TQC",
            "QR_CHAIN_CURRENCY_DECIMALS": "6",
            "QR_CHAIN_CURRENCY_BASE_UNIT": "atom",
            "QR_CHAIN_GENESIS_SUPPLY_CAP": "1000000",
            "QR_CHAIN_SUBSIDY_HALVING_INTERVAL": "25",
            "QR_CHAIN_MAX_MONEY": "21000000000000",
            "QR_CHAIN_EMISSION_SUPPLY_CAP": "17000000000000",
            "QR_CHAIN_MIGRATION_POOL_CAP": "20000000000000",
            "QR_CHAIN_TREASURY_ALLOCATION_CAP": "7000000000000",
            "QR_CHAIN_SECURITY_RESERVE_CAP": "2000000000000",
            "QR_CHAIN_PUBLIC_GOODS_ALLOCATION_CAP": "1000000000000",
            "QR_CHAIN_MIGRATION_CONVERSION_POLICY": "test_capped_pool",
            "QR_CHAIN_REWARD_RECIPIENT_POLICY": "test_validator_split",
            "QR_CHAIN_HOST": "0.0.0.0",
            "QR_CHAIN_PORT": "9000",
            "QR_CHAIN_ID": "qr-chain-testnet",
            "QR_CHAIN_NODE_ID": "node-7",
            "QR_CHAIN_ADVERTISED_URL": "http://node-7:9000",
            "QR_CHAIN_PEERS": "http://node-a:8080, http://node-b:8080",
            "QR_CHAIN_MAX_ADMITTED_PEERS": "17",
            "QR_CHAIN_PEER_ALLOWLIST": "node-a,http://node-b:8080",
            "QR_CHAIN_PEER_DENYLIST": "node-x,http://node-y:8080",
            "QR_CHAIN_REQUIRE_PEER_ALLOWLIST": "true",
            "QR_CHAIN_MAX_TRANSACTIONS_PER_BLOCK": "77",
            "QR_CHAIN_MAX_PENDING_TRANSACTIONS": "123",
            "QR_CHAIN_MIN_TRANSACTION_FEE": "3",
            "QR_CHAIN_MAX_TRANSACTION_SIZE_BYTES": "8192",
            "QR_CHAIN_MAX_TRANSACTION_INPUTS": "8",
            "QR_CHAIN_MAX_TRANSACTION_OUTPUTS": "9",
            "QR_CHAIN_DEFAULT_SIGNATURE_PROVIDER": "xmss_merkle_lamport_v1",
            "QR_CHAIN_WALLET_STATE_DB_PATH": "runtime/wallet_state.db",
            "QR_CHAIN_WALLET_CUSTODY_MODE": "windows_dpapi",
            "QR_CHAIN_WALLET_CUSTODY_SCOPE": "local_machine",
            "QR_CHAIN_WALLET_RESERVATION_TTL_SECONDS": "45",
            "QR_CHAIN_AUTH_TIME_SKEW_SECONDS": "120",
            "QR_CHAIN_PEER_SESSION_TTL_SECONDS": "1800",
            "QR_CHAIN_PEER_PROTOCOL_VERSION": "qr-peer-v2",
            "QR_CHAIN_MAX_PEER_BLOCKS_PER_REQUEST": "33",
            "QR_CHAIN_MIGRATION_CLAIM_START_HEIGHT": "10",
            "QR_CHAIN_MIGRATION_CLAIM_END_HEIGHT": "50",
            "QR_CHAIN_MIGRATION_DUAL_CONTROL_START_HEIGHT": "12",
            "QR_CHAIN_MIGRATION_DUAL_CONTROL_END_HEIGHT": "40",
            "QR_CHAIN_MIGRATION_DISPUTE_WINDOW_BLOCKS": "144",
            "QR_CHAIN_MIGRATION_SNAPSHOT_REVIEWER_QUORUM": "3",
            "QR_CHAIN_MIGRATION_EMERGENCY_PAUSE": "true",
            "QR_CHAIN_MIGRATION_REQUIRE_SNAPSHOT_SIGNATURES": "true",
            "QR_CHAIN_MIGRATION_ALLOWED_CLASSICAL_PROVIDERS": "ecdsa_secp256k1_migration_v1,rsa_pkcs1v15_sha256_migration_v1",
            "QR_CHAIN_MIGRATION_TRUSTED_SNAPSHOT_SIGNERS": "signer-a,signer-b",
            "QR_CHAIN_MIGRATION_TRUSTED_SNAPSHOT_NODES": "node-a,node-b",
            "QR_CHAIN_PREFERRED_SIGNATURE_PROVIDERS": "sphincsplus_v1,lms_nist_v1,xmss_nist_v1",
            "QR_CHAIN_ALLOWED_SIGNATURE_PROVIDERS": "xmss_nist_v1,sphincsplus_v1",
        }
        with patch.dict(os.environ, env, clear=False):
            config = NodeConfig.from_env()

        self.assertEqual(config.db_path.as_posix(), "runtime/chain.db")
        self.assertEqual(config.difficulty, 5)
        self.assertEqual(config.mining_reward, 42)
        self.assertEqual(config.currency_name, "Test Quantum Coin")
        self.assertEqual(config.currency_symbol, "TQC")
        self.assertEqual(config.currency_decimals, 6)
        self.assertEqual(config.currency_base_unit, "atom")
        self.assertEqual(config.genesis_supply_cap, 1000000)
        self.assertEqual(config.subsidy_halving_interval, 25)
        self.assertEqual(config.max_money, 21000000000000)
        self.assertEqual(config.emission_supply_cap, 17000000000000)
        self.assertEqual(config.migration_pool_cap, 20000000000000)
        self.assertEqual(config.treasury_allocation_cap, 7000000000000)
        self.assertEqual(config.security_reserve_cap, 2000000000000)
        self.assertEqual(config.public_goods_allocation_cap, 1000000000000)
        self.assertEqual(config.migration_conversion_policy, "test_capped_pool")
        self.assertEqual(config.reward_recipient_policy, "test_validator_split")
        self.assertEqual(config.host, "0.0.0.0")
        self.assertEqual(config.port, 9000)
        self.assertEqual(config.chain_id, "qr-chain-testnet")
        self.assertEqual(config.node_id, "node-7")
        self.assertEqual(config.advertised_url, "http://node-7:9000")
        self.assertEqual(config.peers, ("http://node-a:8080", "http://node-b:8080"))
        self.assertEqual(config.max_admitted_peers, 17)
        self.assertEqual(config.peer_allowlist, ("node-a", "http://node-b:8080"))
        self.assertEqual(config.peer_denylist, ("node-x", "http://node-y:8080"))
        self.assertTrue(config.require_peer_allowlist)
        self.assertEqual(config.max_transactions_per_block, 77)
        self.assertEqual(config.max_pending_transactions, 123)
        self.assertEqual(config.min_transaction_fee, 3)
        self.assertEqual(config.max_transaction_size_bytes, 8192)
        self.assertEqual(config.max_transaction_inputs, 8)
        self.assertEqual(config.max_transaction_outputs, 9)
        self.assertEqual(config.default_signature_provider, "xmss_merkle_lamport_v1")
        self.assertEqual(config.wallet_state_db_path.as_posix(), "runtime/wallet_state.db")
        self.assertEqual(config.wallet_custody_mode, "windows_dpapi")
        self.assertEqual(config.wallet_custody_scope, "local_machine")
        self.assertEqual(config.wallet_reservation_ttl_seconds, 45)
        self.assertEqual(config.auth_time_skew_seconds, 120)
        self.assertEqual(config.peer_session_ttl_seconds, 1800)
        self.assertEqual(config.peer_protocol_version, "qr-peer-v2")
        self.assertEqual(config.max_peer_blocks_per_request, 33)
        self.assertEqual(config.migration_claim_start_height, 10)
        self.assertEqual(config.migration_claim_end_height, 50)
        self.assertEqual(config.migration_dual_control_start_height, 12)
        self.assertEqual(config.migration_dual_control_end_height, 40)
        self.assertEqual(config.migration_dispute_window_blocks, 144)
        self.assertEqual(config.migration_snapshot_reviewer_quorum, 3)
        self.assertTrue(config.migration_emergency_pause)
        self.assertTrue(config.migration_require_snapshot_signatures)
        self.assertEqual(
            config.migration_allowed_classical_providers,
            ("ecdsa_secp256k1_migration_v1", "rsa_pkcs1v15_sha256_migration_v1"),
        )
        self.assertEqual(config.migration_trusted_snapshot_signers, ("signer-a", "signer-b"))
        self.assertEqual(config.migration_trusted_snapshot_nodes, ("node-a", "node-b"))
        self.assertEqual(
            config.preferred_signature_providers,
            ("sphincsplus_v1", "lms_nist_v1", "xmss_nist_v1"),
        )
        self.assertEqual(
            config.allowed_signature_providers,
            ("xmss_nist_v1", "sphincsplus_v1"),
        )


if __name__ == "__main__":
    unittest.main()
