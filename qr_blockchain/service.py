from __future__ import annotations

import hashlib

from .config import NodeConfig
from .lamport import LamportKeyPair, address_from_public_key, verify_signature
from .models import Block, Transaction, TxInput, TxOutput
from .storage import SQLiteChainStore


class NodeService:
    def __init__(self, config: NodeConfig):
        self.config = config
        self.store = SQLiteChainStore(config.db_path)

    def create_genesis_block(self, initial_allocations: dict[str, int]) -> Block:
        if self.store.block_count():
            raise ValueError("Genesis block already exists.")

        genesis_outputs = [
            TxOutput(recipient=address, amount=amount)
            for address, amount in initial_allocations.items()
            if amount > 0
        ]
        if not genesis_outputs:
            raise ValueError("Genesis block must contain at least one positive allocation.")

        genesis_transaction = Transaction(inputs=[], outputs=genesis_outputs, timestamp=0.0, fee=0)
        genesis_transaction.finalize()

        block = Block(
            index=0,
            previous_hash="0" * 64,
            transactions=[genesis_transaction],
            miner="genesis",
            difficulty=1,
            timestamp=0.0,
        )
        block.mine()
        self.store.apply_block(block)
        return block

    def submit_transaction(self, transaction: Transaction) -> None:
        self._validate_transaction(transaction)
        self._check_pending_double_spends(transaction)
        self.store.save_pending_transaction(transaction)

    def mine_pending_transactions(self, miner_address: str) -> Block:
        latest = self.store.latest_block()
        if latest is None:
            raise ValueError("Create a genesis block before mining.")

        pending = self.store.pending_transactions()
        reward = sum(transaction.fee for transaction in pending) + self.config.mining_reward
        reward_transaction = Transaction(
            inputs=[],
            outputs=[TxOutput(recipient=miner_address, amount=reward)],
            fee=0,
        )
        reward_transaction.finalize()

        block = Block(
            index=int(latest["height"]) + 1,
            previous_hash=str(latest["block_hash"]),
            transactions=[reward_transaction, *pending],
            miner=miner_address,
            difficulty=self.config.difficulty,
        )
        block.mine()
        self.store.apply_block(block)
        return block

    def balance_for_address(self, address: str) -> int:
        return sum(output.amount for _, _, output in self.store.list_utxos([address]))

    def balance_for_addresses(self, addresses: list[str]) -> int:
        return sum(output.amount for _, _, output in self.store.list_utxos(addresses))

    def list_utxos(self, addresses: list[str]) -> list[tuple[str, int, TxOutput]]:
        return self.store.list_utxos(addresses)

    def chain_summary(self) -> dict[str, object]:
        return self.store.summary()

    def select_inputs(self, addresses: list[str], target_amount: int) -> tuple[list[tuple[str, int, TxOutput]], int]:
        selected: list[tuple[str, int, TxOutput]] = []
        running_total = 0
        for tx_id, output_index, output in reversed(self.store.list_utxos(addresses)):
            selected.append((tx_id, output_index, output))
            running_total += output.amount
            if running_total >= target_amount:
                return selected, running_total
        raise ValueError("Insufficient funds.")

    def _validate_transaction(self, transaction: Transaction) -> None:
        if not transaction.tx_id:
            transaction.finalize()
        expected_tx_id = hashlib.sha256(transaction.serialize().encode("utf-8")).hexdigest()
        if transaction.tx_id != expected_tx_id:
            raise ValueError("Transaction hash mismatch.")
        if not transaction.outputs:
            raise ValueError("Transaction must include at least one output.")
        if any(output.amount <= 0 for output in transaction.outputs):
            raise ValueError("All outputs must be positive.")
        if transaction.fee < 0:
            raise ValueError("Transaction fee cannot be negative.")
        if not transaction.inputs:
            return

        seen_inputs: set[tuple[str, int]] = set()
        signing_payload = transaction.signing_payload()
        total_input = 0

        for tx_input in transaction.inputs:
            key = (tx_input.prev_tx_id, tx_input.output_index)
            if key in seen_inputs:
                raise ValueError("Transaction cannot spend the same UTXO twice.")
            seen_inputs.add(key)

            previous_output = self.store.utxo(tx_input.prev_tx_id, tx_input.output_index)
            if previous_output is None:
                raise ValueError(f"Unknown UTXO reference: {key}.")

            if address_from_public_key(tx_input.public_key) != previous_output.recipient:
                raise ValueError("Input public key does not match the referenced address.")
            if not verify_signature(signing_payload, tx_input.signature, tx_input.public_key):
                raise ValueError("Lamport signature verification failed.")

            total_input += previous_output.amount

        total_output = sum(output.amount for output in transaction.outputs)
        if total_output + transaction.fee > total_input:
            raise ValueError("Transaction spends more than its inputs provide.")

    def _check_pending_double_spends(self, candidate: Transaction) -> None:
        candidate_inputs = {(item.prev_tx_id, item.output_index) for item in candidate.inputs}
        if not candidate_inputs:
            return
        for pending in self.store.pending_transactions():
            pending_inputs = {(item.prev_tx_id, item.output_index) for item in pending.inputs}
            if candidate_inputs & pending_inputs:
                raise ValueError("Transaction conflicts with a pending spend.")


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

    def balance(self, service: NodeService) -> int:
        return service.balance_for_addresses(self.addresses())

    def create_transaction(self, service: NodeService, recipient: str, amount: int, fee: int = 1) -> Transaction:
        if amount <= 0:
            raise ValueError("Amount must be positive.")
        if fee < 0:
            raise ValueError("Fee cannot be negative.")

        selected, total_input = service.select_inputs(self.addresses(), amount + fee)
        inputs = [TxInput(prev_tx_id=tx_id, output_index=output_index) for tx_id, output_index, _ in selected]
        outputs = [TxOutput(recipient=recipient, amount=amount)]

        change = total_input - amount - fee
        if change > 0:
            outputs.append(TxOutput(recipient=self.create_address(), amount=change))

        transaction = Transaction(inputs=inputs, outputs=outputs, fee=fee)
        signing_payload = transaction.signing_payload()
        for tx_input, (_, _, previous_output) in zip(transaction.inputs, selected):
            keypair = self._keys[previous_output.recipient]
            tx_input.public_key = [list(row) for row in keypair.public_key]
            tx_input.signature = keypair.sign(signing_payload)
        transaction.finalize()
        return transaction
