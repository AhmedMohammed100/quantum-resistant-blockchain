from __future__ import annotations

import hashlib

from .config import NodeConfig
from .crypto import get_signature_suite
from .models import Block, Transaction, TxInput, TxOutput
from .network import fetch_json, normalize_peer_url, with_path
from .storage import SQLiteChainStore


class NodeService:
    def __init__(self, config: NodeConfig):
        self.config = config
        self.store = SQLiteChainStore(config.db_path)
        for peer in config.peers:
            self.store.add_peer(normalize_peer_url(peer))

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

        genesis_transaction = Transaction(
            inputs=[],
            outputs=genesis_outputs,
            chain_id=self.config.chain_id,
            signature_scheme="hash_lamport_v1",
            timestamp=0.0,
            fee=0,
        )
        genesis_transaction.finalize()

        block = Block(
            index=0,
            previous_hash="0" * 64,
            transactions=[genesis_transaction],
            miner="genesis",
            difficulty=1,
            chain_id=self.config.chain_id,
            version=2,
            timestamp=0.0,
        )
        block.mine()
        self.store.apply_block(block)
        return block

    def submit_transaction(self, transaction: Transaction) -> None:
        self._validate_transaction_against_view(transaction, self.store.all_utxos())
        self._check_pending_double_spends(transaction)
        self.store.save_pending_transaction(transaction)

    def mine_pending_transactions(self, miner_address: str) -> Block:
        latest = self.store.latest_block()
        if latest is None:
            raise ValueError("Create a genesis block before mining.")

        pending = self.store.pending_transactions()[: self.config.max_transactions_per_block]
        reward = sum(transaction.fee for transaction in pending) + self.config.mining_reward
        reward_transaction = Transaction(
            inputs=[],
            outputs=[TxOutput(recipient=miner_address, amount=reward)],
            chain_id=self.config.chain_id,
            signature_scheme="hash_lamport_v1",
            fee=0,
        )
        reward_transaction.finalize()

        block = Block(
            index=int(latest["height"]) + 1,
            previous_hash=str(latest["block_hash"]),
            transactions=[reward_transaction, *pending],
            miner=miner_address,
            difficulty=self.config.difficulty,
            chain_id=self.config.chain_id,
            version=2,
        )
        block.mine()
        self.import_block(block)
        return block

    def import_block(self, block: Block) -> None:
        latest = self.store.latest_block()
        self.validate_block(block, latest["block_hash"] if latest is not None else None)
        self.store.apply_block(block)

    def validate_block(self, block: Block, latest_hash: str | None = None) -> None:
        latest = self.store.latest_block()
        current_height = self.store.block_count()
        expected_previous_hash = "0" * 64 if latest is None else str(latest["block_hash"])
        if latest_hash is not None:
            expected_previous_hash = str(latest_hash)

        if block.chain_id != self.config.chain_id:
            raise ValueError("Block belongs to a different chain.")
        if block.index != current_height:
            raise ValueError("Unexpected block height.")
        if block.previous_hash != expected_previous_hash:
            raise ValueError("Block previous hash mismatch.")
        if block.compute_hash() != block.block_hash:
            raise ValueError("Block hash mismatch.")
        if not block.block_hash.startswith("0" * block.difficulty):
            raise ValueError("Block does not satisfy proof-of-work difficulty.")
        if block.version < 2:
            raise ValueError("Unsupported block version.")
        if not block.transactions:
            raise ValueError("Block must include at least one transaction.")

        if block.index == 0:
            if block.previous_hash != "0" * 64:
                raise ValueError("Genesis block previous hash mismatch.")
            if any(transaction.chain_id != self.config.chain_id for transaction in block.transactions):
                raise ValueError("Genesis block contains a transaction for a different chain.")
            for transaction in block.transactions:
                self._validate_transaction_against_view(transaction, {})
            return

        if block.transactions[0].inputs:
            raise ValueError("First block transaction must be the reward transaction.")

        utxo_view = self.store.all_utxos()
        spent_in_block: set[tuple[str, int]] = set()
        fee_total = 0

        for index, transaction in enumerate(block.transactions):
            self._validate_transaction_against_view(transaction, utxo_view)
            if index == 0:
                continue
            fee_total += transaction.fee
            for tx_input in transaction.inputs:
                key = (tx_input.prev_tx_id, tx_input.output_index)
                if key in spent_in_block:
                    raise ValueError("Block contains a double spend.")
                spent_in_block.add(key)
                utxo_view.pop(key, None)
            for output_index, output in enumerate(transaction.outputs):
                utxo_view[(transaction.tx_id, output_index)] = output

        reward_transaction = block.transactions[0]
        expected_reward = self.config.mining_reward + fee_total
        actual_reward = sum(output.amount for output in reward_transaction.outputs)
        if actual_reward != expected_reward:
            raise ValueError("Reward transaction amount is invalid.")

    def sync_with_peer(self, peer_url: str) -> int:
        normalized = normalize_peer_url(peer_url)
        summary = fetch_json(with_path(normalized, "/chain/summary"))
        remote_height = int(summary.get("height", 0))
        local_height = self.store.block_count()
        imported = 0
        if remote_height <= local_height:
            self.store.add_peer(normalized)
            return imported

        response = fetch_json(with_path(normalized, f"/blocks?start_height={local_height}"))
        for item in response.get("blocks", []):
            block = Block.from_dict(item)
            self.import_block(block)
            imported += 1

        self.store.add_peer(normalized)
        return imported

    def sync_with_peers(self) -> dict[str, int]:
        results: dict[str, int] = {}
        for peer in self.list_peers():
            results[peer] = self.sync_with_peer(peer)
        return results

    def register_peer(self, peer_url: str) -> str:
        normalized = normalize_peer_url(peer_url)
        self.store.add_peer(normalized)
        return normalized

    def list_peers(self) -> list[str]:
        stored = set(self.store.list_peers())
        stored.update(normalize_peer_url(peer) for peer in self.config.peers)
        return sorted(stored)

    def get_blocks_from_height(self, start_height: int) -> list[Block]:
        return self.store.blocks_from_height(start_height)

    def get_block(self, height: int) -> Block | None:
        return self.store.block_at_height(height)

    def balance_for_address(self, address: str) -> int:
        return sum(output.amount for _, _, output in self.store.list_utxos([address]))

    def balance_for_addresses(self, addresses: list[str]) -> int:
        return sum(output.amount for _, _, output in self.store.list_utxos(addresses))

    def list_utxos(self, addresses: list[str]) -> list[tuple[str, int, TxOutput]]:
        return self.store.list_utxos(addresses)

    def chain_summary(self) -> dict[str, object]:
        summary = self.store.summary()
        summary["chain_id"] = self.config.chain_id
        summary["node_id"] = self.config.node_id
        summary["peer_count"] = len(self.list_peers())
        return summary

    def select_inputs(self, addresses: list[str], target_amount: int) -> tuple[list[tuple[str, int, TxOutput]], int]:
        selected: list[tuple[str, int, TxOutput]] = []
        running_total = 0
        for tx_id, output_index, output in reversed(self.store.list_utxos(addresses)):
            selected.append((tx_id, output_index, output))
            running_total += output.amount
            if running_total >= target_amount:
                return selected, running_total
        raise ValueError("Insufficient funds.")

    def _validate_transaction_against_view(
        self,
        transaction: Transaction,
        utxo_view: dict[tuple[str, int], TxOutput],
    ) -> None:
        if not transaction.tx_id:
            transaction.finalize()
        expected_tx_id = hashlib.sha256(transaction.serialize().encode("utf-8")).hexdigest()
        if transaction.tx_id != expected_tx_id:
            raise ValueError("Transaction hash mismatch.")
        if transaction.chain_id != self.config.chain_id:
            raise ValueError("Transaction belongs to a different chain.")
        if not transaction.outputs:
            raise ValueError("Transaction must include at least one output.")
        if any(output.amount <= 0 for output in transaction.outputs):
            raise ValueError("All outputs must be positive.")
        if transaction.fee < 0:
            raise ValueError("Transaction fee cannot be negative.")

        suite = get_signature_suite(transaction.signature_scheme)
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

            previous_output = utxo_view.get(key)
            if previous_output is None:
                raise ValueError(f"Unknown UTXO reference: {key}.")
            if suite.address_from_public_key(tx_input.public_key) != previous_output.recipient:
                raise ValueError("Input public key does not match the referenced address.")
            if not suite.verify(signing_payload, tx_input.signature, tx_input.public_key):
                raise ValueError("Quantum signature verification failed.")
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
    def __init__(self, label: str, signature_scheme: str = "hash_lamport_v1"):
        self.label = label
        self.signature_scheme = signature_scheme
        self._suite = get_signature_suite(signature_scheme)
        self._keys: dict[str, object] = {}

    def create_address(self) -> str:
        keypair = self._suite.generate_keypair()
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

        transaction = Transaction(
            inputs=inputs,
            outputs=outputs,
            chain_id=service.config.chain_id,
            signature_scheme=self.signature_scheme,
            fee=fee,
        )
        signing_payload = transaction.signing_payload()
        for tx_input, (_, _, previous_output) in zip(transaction.inputs, selected):
            keypair = self._keys[previous_output.recipient]
            tx_input.public_key = [list(row) for row in keypair.public_key]
            tx_input.signature = self._suite.sign(keypair, signing_payload)
        transaction.finalize()
        return transaction
