"""Pure UTXO state projection helpers shared by consensus-facing code."""

from __future__ import annotations

import hashlib

from .models import Block, TxOutput, canonical_json


UtxoKey = tuple[str, int]
UtxoView = dict[UtxoKey, TxOutput]


def project_block_utxos(parent_utxos: UtxoView, block: Block) -> UtxoView:
    """Return the UTXO view after applying this block's inputs and outputs."""
    projected = dict(parent_utxos)
    for transaction in block.transactions:
        for tx_input in transaction.inputs:
            projected.pop((tx_input.prev_tx_id, tx_input.output_index), None)
        for output_index, output in enumerate(transaction.outputs):
            projected[(transaction.tx_id, output_index)] = output
    return projected


def utxo_state_root(utxos: UtxoView) -> str:
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


def state_root_after_block(parent_utxos: UtxoView, block: Block) -> str:
    return utxo_state_root(project_block_utxos(parent_utxos, block))

