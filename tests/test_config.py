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
        }
        with patch.dict(os.environ, env, clear=False):
            config = NodeConfig.from_env()

        self.assertEqual(config.db_path.as_posix(), "runtime/chain.db")
        self.assertEqual(config.difficulty, 5)
        self.assertEqual(config.mining_reward, 42)
        self.assertEqual(config.host, "0.0.0.0")
        self.assertEqual(config.port, 9000)


if __name__ == "__main__":
    unittest.main()
