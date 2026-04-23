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
            "QR_CHAIN_HOST": "0.0.0.0",
            "QR_CHAIN_PORT": "9000",
            "QR_CHAIN_ID": "qr-chain-testnet",
            "QR_CHAIN_NODE_ID": "node-7",
            "QR_CHAIN_ADVERTISED_URL": "http://node-7:9000",
            "QR_CHAIN_PEERS": "http://node-a:8080, http://node-b:8080",
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
        }
        with patch.dict(os.environ, env, clear=False):
            config = NodeConfig.from_env()

        self.assertEqual(config.db_path.as_posix(), "runtime/chain.db")
        self.assertEqual(config.difficulty, 5)
        self.assertEqual(config.mining_reward, 42)
        self.assertEqual(config.host, "0.0.0.0")
        self.assertEqual(config.port, 9000)
        self.assertEqual(config.chain_id, "qr-chain-testnet")
        self.assertEqual(config.node_id, "node-7")
        self.assertEqual(config.advertised_url, "http://node-7:9000")
        self.assertEqual(config.peers, ("http://node-a:8080", "http://node-b:8080"))
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


if __name__ == "__main__":
    unittest.main()
