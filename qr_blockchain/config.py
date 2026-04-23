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
    chain_id: str = "qr-chain-devnet"
    node_id: str = "node-local"
    advertised_url: str = "http://127.0.0.1:8080"
    peers: tuple[str, ...] = ()
    max_transactions_per_block: int = 500
    max_pending_transactions: int = 2000
    min_transaction_fee: int = 1
    max_transaction_size_bytes: int = 16777216
    max_transaction_inputs: int = 64
    max_transaction_outputs: int = 64
    default_signature_provider: str = "xmss_merkle_lamport_v1"
    wallet_state_db_path: Path = Path("data/wallet_state.db")
    wallet_custody_mode: str = "auto"
    wallet_custody_scope: str = "current_user"
    wallet_reservation_ttl_seconds: int = 60
    auth_time_skew_seconds: int = 300
    peer_session_ttl_seconds: int = 900
    peer_protocol_version: str = "qr-peer-v1"
    max_peer_blocks_per_request: int = 128

    @staticmethod
    def from_env() -> "NodeConfig":
        peers_env = os.getenv("QR_CHAIN_PEERS", "").strip()
        default_provider = os.getenv(
            "QR_CHAIN_DEFAULT_SIGNATURE_PROVIDER",
            os.getenv("QR_CHAIN_DEFAULT_SIGNATURE_SCHEME", "xmss_merkle_lamport_v1"),
        )
        return NodeConfig(
            db_path=Path(os.getenv("QR_CHAIN_DB_PATH", "data/chain.db")),
            difficulty=int(os.getenv("QR_CHAIN_DIFFICULTY", "3")),
            mining_reward=int(os.getenv("QR_CHAIN_MINING_REWARD", "30")),
            host=os.getenv("QR_CHAIN_HOST", "127.0.0.1"),
            port=int(os.getenv("QR_CHAIN_PORT", "8080")),
            chain_id=os.getenv("QR_CHAIN_ID", "qr-chain-devnet"),
            node_id=os.getenv("QR_CHAIN_NODE_ID", "node-local"),
            advertised_url=os.getenv("QR_CHAIN_ADVERTISED_URL", "http://127.0.0.1:8080"),
            peers=tuple(peer.strip() for peer in peers_env.split(",") if peer.strip()),
            max_transactions_per_block=int(os.getenv("QR_CHAIN_MAX_TRANSACTIONS_PER_BLOCK", "500")),
            max_pending_transactions=int(os.getenv("QR_CHAIN_MAX_PENDING_TRANSACTIONS", "2000")),
            min_transaction_fee=int(os.getenv("QR_CHAIN_MIN_TRANSACTION_FEE", "1")),
            max_transaction_size_bytes=int(os.getenv("QR_CHAIN_MAX_TRANSACTION_SIZE_BYTES", "16777216")),
            max_transaction_inputs=int(os.getenv("QR_CHAIN_MAX_TRANSACTION_INPUTS", "64")),
            max_transaction_outputs=int(os.getenv("QR_CHAIN_MAX_TRANSACTION_OUTPUTS", "64")),
            default_signature_provider=default_provider,
            wallet_state_db_path=Path(os.getenv("QR_CHAIN_WALLET_STATE_DB_PATH", "data/wallet_state.db")),
            wallet_custody_mode=os.getenv("QR_CHAIN_WALLET_CUSTODY_MODE", "auto"),
            wallet_custody_scope=os.getenv("QR_CHAIN_WALLET_CUSTODY_SCOPE", "current_user"),
            wallet_reservation_ttl_seconds=int(os.getenv("QR_CHAIN_WALLET_RESERVATION_TTL_SECONDS", "60")),
            auth_time_skew_seconds=int(os.getenv("QR_CHAIN_AUTH_TIME_SKEW_SECONDS", "300")),
            peer_session_ttl_seconds=int(os.getenv("QR_CHAIN_PEER_SESSION_TTL_SECONDS", "900")),
            peer_protocol_version=os.getenv("QR_CHAIN_PEER_PROTOCOL_VERSION", "qr-peer-v1"),
            max_peer_blocks_per_request=int(os.getenv("QR_CHAIN_MAX_PEER_BLOCKS_PER_REQUEST", "128")),
        )
