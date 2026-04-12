from __future__ import annotations

from dataclasses import asdict, dataclass, field
import hashlib
import json
import time

from .lamport import LamportKeyPair, sha256_hex, verify_signature


def canonical_json(data: object) -> str:
    return json.dumps(data, sort_keys=True, separators=(",", ":"))


@dataclass
class TxOutput:
    recipient: str
    amount: int


@dataclass
class TxInput:
    prev_tx_id: str
    output_index: int
    public_key: list[list[str]] = field(default_factory=list)
    signature: list[str] = field(default_factory=list)


@dataclass
class Transaction:
    inputs: list[TxInput]
    outputs: list[TxOutput]
    timestamp: float = field(default_factory=lambda: round(time.time(), 6))
    tx_id: str = ""

    def signing_payload(self) -> bytes:
        payload = {
            "inputs": [
                {
                    "prev_tx_id": tx_input.prev_tx_id,
                    "output_index": tx_input.output_index,
                }
                for tx_input in self.inputs
            ],
            "outputs": [asdict(output) for output in self.outputs],
            "timestamp": self.timestamp,
        }
        return canonical_json(payload).encode("utf-8")

    def finalize(self) -> None:
        self.tx_id = hashlib.sha256(self.serialize().encode("utf-8")).hexdigest()

    def serialize(self) -> str:
        return canonical_json(
            {
                "inputs": [asdict(tx_input) for tx_input in self.inputs],
                "outputs": [asdict(output) for output in self.outputs],
                "timestamp": self.timestamp,
            }
        )


@dataclass
class Block:
    index: int
    previous_hash: str
    transactions: list[Transaction]
    miner: str
    difficulty: int
    timestamp: float = field(default_factory=lambda: round(time.time(), 6))
    nonce: int = 0
    block_hash: str = ""

    def compute_hash(self) -> str:
        payload = {
            "index": self.index,
            "previous_hash": self.previous_hash,
            "transactions": [tx.serialize() for tx in self.transactions],
            "miner": self.miner,
            "difficulty": self.difficulty,
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


class Wallet:
    def __init__(self, label: str):
        self.label = label
        self._keys: dict[str, LamportKeyPair] = {}

    def create_address(self) -> str:
        keypair = LamportKeyPair.generate()
        address = keypair.address()
        self._keys[address] = keypair
        return address

    def addresses(self) -> list[str]:
        return list(self._keys.keys())

    def balance(self, blockchain: "Blockchain") -> int:
        return blockchain.balance_for_addresses(self.addresses())

    def create_transaction(self, blockchain: "Blockchain", recipient: str, amount: int) -> Transaction:
        if amount <= 0:
            raise ValueError("Amount must be positive.")

        spendable = blockchain.find_spendable_output(self.addresses(), amount)
        if spendable is None:
            raise ValueError(f"{self.label} does not have a single spendable UTXO covering {amount}.")

        prev_tx_id, output_index, previous_output = spendable
        keypair = self._keys[previous_output.recipient]

        outputs = [TxOutput(recipient=recipient, amount=amount)]
        change = previous_output.amount - amount
        if change > 0:
            outputs.append(TxOutput(recipient=self.create_address(), amount=change))

        tx_input = TxInput(prev_tx_id=prev_tx_id, output_index=output_index)
        transaction = Transaction(inputs=[tx_input], outputs=outputs)

        signing_payload = transaction.signing_payload()
        tx_input.public_key = [list(row) for row in keypair.public_key]
        tx_input.signature = keypair.sign(signing_payload)
        transaction.finalize()
        return transaction


class Blockchain:
    def __init__(self, difficulty: int = 3, mining_reward: int = 25):
        self.difficulty = difficulty
        self.mining_reward = mining_reward
        self.chain: list[Block] = []
        self.pending_transactions: list[Transaction] = []
        self.utxos: dict[tuple[str, int], TxOutput] = {}

    def create_genesis_block(self, initial_allocations: dict[str, int]) -> None:
        if self.chain:
            raise ValueError("Genesis block already exists.")

        genesis_outputs = [
            TxOutput(recipient=address, amount=amount)
            for address, amount in initial_allocations.items()
            if amount > 0
        ]
        genesis_tx = Transaction(inputs=[], outputs=genesis_outputs, timestamp=0.0)
        genesis_tx.finalize()

        genesis_block = Block(
            index=0,
            previous_hash="0" * 64,
            transactions=[genesis_tx],
            miner="genesis",
            difficulty=1,
            timestamp=0.0,
        )
        genesis_block.mine()

        self.chain.append(genesis_block)
        self._apply_transaction(genesis_tx)

    def add_transaction(self, transaction: Transaction) -> None:
        self._validate_transaction(transaction)
        self.pending_transactions.append(transaction)

    def mine_pending_transactions(self, miner_address: str) -> Block:
        if not self.chain:
            raise ValueError("Create a genesis block before mining.")

        reward_tx = Transaction(
            inputs=[],
            outputs=[TxOutput(recipient=miner_address, amount=self.mining_reward)],
        )
        reward_tx.finalize()

        transactions = [reward_tx, *self.pending_transactions]
        block = Block(
            index=len(self.chain),
            previous_hash=self.chain[-1].block_hash,
            transactions=transactions,
            miner=miner_address,
            difficulty=self.difficulty,
        )
        block.mine()

        for transaction in transactions:
            if transaction.inputs:
                self._validate_transaction(transaction)
            self._apply_transaction(transaction)

        self.chain.append(block)
        self.pending_transactions = []
        return block

    def balance_for_address(self, address: str) -> int:
        return sum(output.amount for output in self.utxos.values() if output.recipient == address)

    def balance_for_addresses(self, addresses: list[str]) -> int:
        address_set = set(addresses)
        return sum(output.amount for output in self.utxos.values() if output.recipient in address_set)

    def find_spendable_output(self, addresses: list[str], minimum_amount: int) -> tuple[str, int, TxOutput] | None:
        address_set = set(addresses)
        for (tx_id, output_index), output in self.utxos.items():
            if output.recipient in address_set and output.amount >= minimum_amount:
                return tx_id, output_index, output
        return None

    def summary(self) -> dict[str, object]:
        return {
            "height": len(self.chain),
            "pending_transactions": len(self.pending_transactions),
            "utxo_count": len(self.utxos),
            "latest_block_hash": self.chain[-1].block_hash if self.chain else None,
        }

    def _validate_transaction(self, transaction: Transaction) -> None:
        if not transaction.inputs:
            return

        if not transaction.tx_id:
            raise ValueError("Transaction must be finalized before validation.")

        expected_tx_id = hashlib.sha256(transaction.serialize().encode("utf-8")).hexdigest()
        if expected_tx_id != transaction.tx_id:
            raise ValueError("Transaction hash mismatch.")

        total_input = 0
        consumed_inputs: set[tuple[str, int]] = set()
        signing_payload = transaction.signing_payload()

        for tx_input in transaction.inputs:
            key = (tx_input.prev_tx_id, tx_input.output_index)
            if key in consumed_inputs:
                raise ValueError("Transaction reuses the same input twice.")
            consumed_inputs.add(key)

            previous_output = self.utxos.get(key)
            if previous_output is None:
                raise ValueError(f"Missing referenced UTXO {key}.")

            derived_address = sha256_hex(
                "".join(left + right for left, right in tx_input.public_key).encode("ascii")
            )
            if derived_address != previous_output.recipient:
                raise ValueError("Public key does not match referenced address.")

            if not verify_signature(signing_payload, tx_input.signature, tx_input.public_key):
                raise ValueError("Lamport signature verification failed.")

            total_input += previous_output.amount

        total_output = sum(output.amount for output in transaction.outputs)
        if total_output <= 0:
            raise ValueError("Transaction must create a positive output amount.")
        if total_output > total_input:
            raise ValueError("Transaction spends more than its inputs provide.")
        if any(output.amount <= 0 for output in transaction.outputs):
            raise ValueError("All transaction outputs must be positive.")

    def _apply_transaction(self, transaction: Transaction) -> None:
        for tx_input in transaction.inputs:
            self.utxos.pop((tx_input.prev_tx_id, tx_input.output_index), None)

        for output_index, output in enumerate(transaction.outputs):
            self.utxos[(transaction.tx_id, output_index)] = output
