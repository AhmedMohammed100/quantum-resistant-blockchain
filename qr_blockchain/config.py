from __future__ import annotations

from dataclasses import dataclass
import os
from pathlib import Path


@dataclass(frozen=True)
class NodeConfig:
    db_path: Path = Path("data/chain.db")
    difficulty: int = 3
    mining_reward: int = 30
    host: str = "127.0.0.1"
    port: int = 8080

    @staticmethod
    def from_env() -> "NodeConfig":
        return NodeConfig(
            db_path=Path(os.getenv("QR_CHAIN_DB_PATH", "data/chain.db")),
            difficulty=int(os.getenv("QR_CHAIN_DIFFICULTY", "3")),
            mining_reward=int(os.getenv("QR_CHAIN_MINING_REWARD", "30")),
            host=os.getenv("QR_CHAIN_HOST", "127.0.0.1"),
            port=int(os.getenv("QR_CHAIN_PORT", "8080")),
        )
