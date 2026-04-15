from __future__ import annotations

from dataclasses import asdict, dataclass, field
import hashlib
import json
import time


def canonical_json(data: object) -> str:
    return json.dumps(data, sort_keys=True, separators=(",", ":"))


@dataclass(frozen=True)
class TxOutput:
    recipient: str
    amount: int

    @staticmethod
    def from_dict(data: dict[str, object]) -> "TxOutput":
        return TxOutput(recipient=str(data["recipient"]), amount=int(data["amount"]))


@dataclass
class TxInput:
    prev_tx_id: str
    output_index: int
    public_key: list[list[str]] = field(default_factory=list)
    signature: list[str] = field(default_factory=list)

    @staticmethod
    def from_dict(data: dict[str, object]) -> "TxInput":
        return TxInput(
            prev_tx_id=str(data["prev_tx_id"]),
            output_index=int(data["output_index"]),
            public_key=[[str(value) for value in row] for row in data.get("public_key", [])],
            signature=[str(value) for value in data.get("signature", [])],
        )


@dataclass
class Transaction:
    inputs: list[TxInput]
    outputs: list[TxOutput]
    chain_id: str = "qr-chain-devnet"
    signature_scheme: str = "hash_lamport_v1"
    timestamp: float = field(default_factory=lambda: round(time.time(), 6))
    fee: int = 0
    tx_id: str = ""

    def signing_payload(self) -> bytes:
        payload = {
            "inputs": [
                {"prev_tx_id": tx_input.prev_tx_id, "output_index": tx_input.output_index}
                for tx_input in self.inputs
            ],
            "outputs": [asdict(output) for output in self.outputs],
            "chain_id": self.chain_id,
            "signature_scheme": self.signature_scheme,
            "timestamp": self.timestamp,
            "fee": self.fee,
        }
        return canonical_json(payload).encode("utf-8")

    def serialize(self) -> str:
        return canonical_json(
            {
                "inputs": [asdict(tx_input) for tx_input in self.inputs],
                "outputs": [asdict(output) for output in self.outputs],
                "chain_id": self.chain_id,
                "signature_scheme": self.signature_scheme,
                "timestamp": self.timestamp,
                "fee": self.fee,
            }
        )

    def serialize_with_id(self) -> str:
        return canonical_json(
            {
                "inputs": [asdict(tx_input) for tx_input in self.inputs],
                "outputs": [asdict(output) for output in self.outputs],
                "chain_id": self.chain_id,
                "signature_scheme": self.signature_scheme,
                "timestamp": self.timestamp,
                "fee": self.fee,
                "tx_id": self.tx_id,
            }
        )

    def finalize(self) -> None:
        self.tx_id = hashlib.sha256(self.serialize().encode("utf-8")).hexdigest()

    @staticmethod
    def from_dict(data: dict[str, object]) -> "Transaction":
        transaction = Transaction(
            inputs=[TxInput.from_dict(item) for item in data.get("inputs", [])],
            outputs=[TxOutput.from_dict(item) for item in data.get("outputs", [])],
            chain_id=str(data.get("chain_id", "qr-chain-devnet")),
            signature_scheme=str(data.get("signature_scheme", "hash_lamport_v1")),
            timestamp=float(data.get("timestamp", round(time.time(), 6))),
            fee=int(data.get("fee", 0)),
            tx_id=str(data.get("tx_id", "")),
        )
        if not transaction.tx_id:
            transaction.finalize()
        return transaction


@dataclass
class Block:
    index: int
    previous_hash: str
    transactions: list[Transaction]
    miner: str
    difficulty: int
    chain_id: str = "qr-chain-devnet"
    version: int = 2
    timestamp: float = field(default_factory=lambda: round(time.time(), 6))
    nonce: int = 0
    block_hash: str = ""

    def compute_hash(self) -> str:
        payload = {
            "index": self.index,
            "previous_hash": self.previous_hash,
            "transactions": [transaction.serialize_with_id() for transaction in self.transactions],
            "miner": self.miner,
            "difficulty": self.difficulty,
            "chain_id": self.chain_id,
            "version": self.version,
            "timestamp": self.timestamp,
            "nonce": self.nonce,
        }
        return hashlib.sha256(canonical_json(payload).encode("utf-8")).hexdigest()

    def mine(self) -> None:
        target = "0" * self.difficulty
        while True:
            candidate = self.compute_hash()
            if candidate.startswith(target):
                self.block_hash = candidate
                return
            self.nonce += 1

    def to_dict(self) -> dict[str, object]:
        return {
            "index": self.index,
            "previous_hash": self.previous_hash,
            "transactions": [json.loads(transaction.serialize_with_id()) for transaction in self.transactions],
            "miner": self.miner,
            "difficulty": self.difficulty,
            "chain_id": self.chain_id,
            "version": self.version,
            "timestamp": self.timestamp,
            "nonce": self.nonce,
            "block_hash": self.block_hash,
        }

    @staticmethod
    def from_dict(data: dict[str, object]) -> "Block":
        return Block(
            index=int(data["index"]),
            previous_hash=str(data["previous_hash"]),
            transactions=[Transaction.from_dict(item) for item in data.get("transactions", [])],
            miner=str(data["miner"]),
            difficulty=int(data["difficulty"]),
            chain_id=str(data.get("chain_id", "qr-chain-devnet")),
            version=int(data.get("version", 2)),
            timestamp=float(data.get("timestamp", round(time.time(), 6))),
            nonce=int(data.get("nonce", 0)),
            block_hash=str(data.get("block_hash", "")),
        )
