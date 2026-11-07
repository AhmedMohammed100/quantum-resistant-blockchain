"""Offline, read-only replay checks for a linear QBC chain export.

This verifier intentionally does not construct a NodeService or call its block
acceptance path. It cross-checks the structural, transaction, UTXO, and supply
invariants needed to independently review an exported chain.
"""

from __future__ import annotations

import hashlib
import math
from typing import Callable, Iterable

from .models import Block, Transaction, TxOutput, canonical_json
from .verification import verify_transaction_inputs


def _state_root(utxos: dict[tuple[str, int], TxOutput]) -> str:
    # Keep the replay projection local to this verifier so it can check the
    # NodeService's commitment path independently.
    payload = [
        {
            "tx_id": tx_id,
            "output_index": output_index,
            "recipient": output.recipient,
            "amount": output.amount,
        }
        for (tx_id, output_index), output in sorted(utxos.items())
    ]
    return hashlib.sha256(canonical_json(payload).encode("utf-8")).hexdigest()


def verify_chain(
    blocks: Iterable[Block | dict[str, object]],
    *,
    chain_id: str,
    subsidy_at_height: Callable[[int], int],
    difficulty: int,
    state_root_activation_height: int = 0,
    max_money: int | None = None,
    genesis_supply_cap: int | None = None,
    migration_supply_cap: int | None = None,
) -> dict[str, object]:
    """Replay a linear chain export without consulting node storage or service logic.

    The result reports precisely which independent checks were completed.
    Classical source ownership proofs and migration dispute/finality policy are
    purposefully not claimed as verified by this offline structural replay.
    """
    try:
        parsed = [Block.from_dict(item) if isinstance(item, dict) else item for item in blocks]
        issued_supply = _verify_chain(
            parsed,
            chain_id=chain_id,
            subsidy_at_height=subsidy_at_height,
            difficulty=difficulty,
            state_root_activation_height=state_root_activation_height,
            max_money=max_money,
            genesis_supply_cap=genesis_supply_cap,
            migration_supply_cap=migration_supply_cap,
        )
    except (KeyError, TypeError, ValueError, OverflowError) as error:
        return {
            "valid": False,
            "error": str(error),
            "blocks_checked": 0,
            "checks": [],
            "limitations": _LIMITATIONS,
        }

    return {
        "valid": True,
        "blocks_checked": len(parsed),
        "height": parsed[-1].index if parsed else -1,
        "best_head_hash": parsed[-1].block_hash if parsed else "",
        "issued_supply": issued_supply,
        "checks": [
            "block hash, proof of work, chain id, height and parent linkage",
            "transaction identifiers, signatures, UTXO spends, fee accounting and double spends",
            "reward issuance, optional supply caps and UTXO conservation",
            "post-state UTXO roots where required or present",
        ],
        "limitations": _LIMITATIONS,
    }


_LIMITATIONS = [
    "The input is a single linear chain; fork-choice work, omitted side branches, and network finality are not assessed.",
    "Migration claim output structure and uniqueness are checked, but classical source ownership proofs are not re-verified.",
    "Migration escrow, dispute, snapshot provenance, and spendability policy are outside this replay verifier.",
    "Coinbase maturity, transaction size/count resource limits, and other node-local operational limits are not checked.",
    "Signature verification uses the configured QBC signature provider implementation; this is not a cryptographic implementation audit.",
]


def _verify_chain(
    blocks: list[Block],
    *,
    chain_id: str,
    subsidy_at_height: Callable[[int], int],
    difficulty: int,
    state_root_activation_height: int,
    max_money: int | None,
    genesis_supply_cap: int | None,
    migration_supply_cap: int | None,
) -> int:
    if not blocks:
        raise ValueError("Chain export contains no genesis block.")
    if difficulty < 0:
        raise ValueError("Configured difficulty cannot be negative.")

    utxos: dict[tuple[str, int], TxOutput] = {}
    seen_tx_ids: set[str] = set()
    claimed_classical_addresses: set[str] = set()
    issued_supply = 0
    migration_supply = 0
    parent_hash = "0" * 64
    parent_timestamp = -1.0

    for expected_height, block in enumerate(blocks):
        if not isinstance(block, Block):
            raise ValueError(f"Block at position {expected_height} is not a block object.")
        if block.index != expected_height:
            raise ValueError(f"Unexpected block height at position {expected_height}.")
        if block.chain_id != chain_id:
            raise ValueError(f"Block at height {expected_height} belongs to a different chain.")
        expected_difficulty = 1 if expected_height == 0 else difficulty
        if block.difficulty != expected_difficulty:
            raise ValueError(f"Block at height {expected_height} has unexpected difficulty.")
        if not block.block_hash.startswith("0" * expected_difficulty):
            raise ValueError(f"Block at height {expected_height} does not satisfy proof of work.")
        if block.compute_hash() != block.block_hash:
            raise ValueError(f"Block hash mismatch at height {expected_height}.")
        if block.previous_hash != parent_hash:
            raise ValueError(f"Broken parent link at height {expected_height}.")
        if isinstance(block.timestamp, bool) or not isinstance(block.timestamp, (int, float)):
            raise ValueError(f"Block timestamp is invalid at height {expected_height}.")
        if not math.isfinite(block.timestamp) or block.timestamp < 0:
            raise ValueError(f"Block timestamp is invalid at height {expected_height}.")
        if expected_height == 0:
            if block.timestamp != 0 or block.miner != "genesis":
                raise ValueError("Genesis fields are invalid.")
        elif block.timestamp <= parent_timestamp:
            raise ValueError(f"Block timestamp does not advance at height {expected_height}.")
        if block.version < 2:
            raise ValueError(f"Unsupported block version at height {expected_height}.")
        if not block.transactions:
            raise ValueError(f"Block at height {expected_height} contains no transactions.")

        block_fees = 0
        claimed_in_block: set[str] = set()
        if expected_height == 0:
            if len(block.transactions) != 1:
                raise ValueError("Genesis must contain exactly one allocation transaction.")
            genesis = block.transactions[0]
            _check_transaction_id(genesis, expected_height)
            _check_transaction_chain_and_time(genesis, chain_id, block.timestamp, expected_height)
            if genesis.kind != "transfer" or genesis.inputs or genesis.fee != 0 or genesis.timestamp != 0:
                raise ValueError("Genesis allocation transaction fields are invalid.")
            _check_outputs(genesis, expected_height)
            issued_supply = sum(output.amount for output in genesis.outputs)
            if genesis_supply_cap is not None and issued_supply > genesis_supply_cap:
                raise ValueError("Genesis allocation exceeds the supplied genesis cap.")
            if max_money is not None and issued_supply > max_money:
                raise ValueError("Genesis allocation exceeds the supplied max money cap.")
            for output_index, output in enumerate(genesis.outputs):
                utxos[(genesis.tx_id, output_index)] = output
        else:
            reward = block.transactions[0]
            _check_transaction_id(reward, expected_height)
            _check_transaction_chain_and_time(reward, chain_id, block.timestamp, expected_height)
            if (
                reward.kind != "transfer"
                or reward.inputs
                or reward.fee != 0
                or len(reward.outputs) != 1
                or reward.outputs[0].recipient != block.miner
            ):
                raise ValueError(f"Reward transaction is invalid at height {expected_height}.")
            _check_outputs(reward, expected_height)
            for output_index, output in enumerate(reward.outputs):
                utxos[(reward.tx_id, output_index)] = output

            spent: set[tuple[str, int]] = set()
            for transaction in block.transactions[1:]:
                _check_transaction_id(transaction, expected_height)
                _check_transaction_chain_and_time(transaction, chain_id, block.timestamp, expected_height)
                if transaction.kind == "migration_claim":
                    _check_outputs(transaction, expected_height)
                    address = str(transaction.metadata.get("classical_address", ""))
                    if not address or address in claimed_classical_addresses or address in claimed_in_block:
                        raise ValueError(f"Duplicate or missing migration claim source at height {expected_height}.")
                    if transaction.inputs or transaction.fee != 0:
                        raise ValueError(f"Migration claim structure is invalid at height {expected_height}.")
                    claimed_in_block.add(address)
                    amount = sum(output.amount for output in transaction.outputs)
                    migration_supply += amount
                    issued_supply += amount
                    if migration_supply_cap is not None and migration_supply > migration_supply_cap:
                        raise ValueError("Migration claims exceed the supplied migration cap.")
                    for output_index, output in enumerate(transaction.outputs):
                        utxos[(transaction.tx_id, output_index)] = output
                    continue

                if transaction.kind != "transfer" or not transaction.inputs:
                    raise ValueError(f"Transfer transaction structure is invalid at height {expected_height}.")
                _check_outputs(transaction, expected_height)
                if transaction.fee < 0:
                    raise ValueError(f"Negative transaction fee at height {expected_height}.")
                signing_view: dict[tuple[str, int], TxOutput] = {}
                transaction_spends: list[tuple[str, int]] = []
                total_input = 0
                for tx_input in transaction.inputs:
                    key = (tx_input.prev_tx_id, tx_input.output_index)
                    if key in spent:
                        raise ValueError(f"Block double-spends an output at height {expected_height}.")
                    output = utxos.get(key)
                    if output is None:
                        raise ValueError(f"Transaction spends an unavailable output at height {expected_height}.")
                    spent.add(key)
                    transaction_spends.append(key)
                    signing_view[key] = output
                    total_input += output.amount
                verification = verify_transaction_inputs(transaction, signing_view)
                if not verification.verified:
                    raise ValueError(f"Transaction signature failed at height {expected_height}: {verification.failure}")
                total_output = sum(output.amount for output in transaction.outputs)
                if total_output + transaction.fee > total_input:
                    raise ValueError(f"Transaction creates unissued value at height {expected_height}.")
                for key in transaction_spends:
                    utxos.pop(key, None)
                for output_index, output in enumerate(transaction.outputs):
                    utxos[(transaction.tx_id, output_index)] = output
                block_fees += transaction.fee

            expected_reward = int(subsidy_at_height(expected_height)) + block_fees
            if sum(output.amount for output in reward.outputs) != expected_reward:
                raise ValueError(f"Reward amount is invalid at height {expected_height}.")
            # Fees are transferred from existing inputs to the miner; only
            # the scheduled subsidy adds new supply.
            issued_supply += int(subsidy_at_height(expected_height))
            claimed_classical_addresses.update(claimed_in_block)

        if block.version >= 3 or expected_height >= state_root_activation_height:
            if expected_height >= state_root_activation_height and (block.version < 3 or not block.state_root):
                raise ValueError(f"Required state root is missing at height {expected_height}.")
            if block.state_root and block.state_root != _state_root(utxos):
                raise ValueError(f"State root mismatch at height {expected_height}.")

        if max_money is not None and issued_supply > max_money:
            raise ValueError("Chain issuance exceeds the supplied max money cap.")
        if sum(output.amount for output in utxos.values()) != issued_supply:
            raise ValueError(f"UTXO supply does not reconcile at height {expected_height}.")

        for transaction in block.transactions:
            if transaction.tx_id in seen_tx_ids:
                raise ValueError(f"Duplicate transaction identifier at height {expected_height}.")
            seen_tx_ids.add(transaction.tx_id)
        parent_hash = block.block_hash
        parent_timestamp = float(block.timestamp)

    return issued_supply


def _check_transaction_id(transaction: Transaction, height: int) -> None:
    expected = hashlib.sha256(transaction.serialize().encode("utf-8")).hexdigest()
    if not transaction.tx_id or transaction.tx_id != expected:
        raise ValueError(f"Transaction hash mismatch at height {height}.")


def _check_transaction_chain_and_time(
    transaction: Transaction,
    chain_id: str,
    block_timestamp: float,
    height: int,
) -> None:
    if transaction.chain_id != chain_id:
        raise ValueError(f"Transaction belongs to a different chain at height {height}.")
    if (
        isinstance(transaction.timestamp, bool)
        or not isinstance(transaction.timestamp, (int, float))
        or not math.isfinite(transaction.timestamp)
        or transaction.timestamp < 0
        or transaction.timestamp > block_timestamp
    ):
        raise ValueError(f"Transaction timestamp is invalid at height {height}.")


def _check_outputs(transaction: Transaction, height: int) -> None:
    if not transaction.outputs or any(output.amount <= 0 or not output.recipient for output in transaction.outputs):
        raise ValueError(f"Transaction outputs are invalid at height {height}.")

