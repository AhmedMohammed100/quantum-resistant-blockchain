from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
import importlib
import os

from .crypto import get_signature_verifier
from .models import Transaction, TxOutput


@dataclass(frozen=True)
class InputVerificationTask:
    input_index: int
    address: str
    public_key: object
    signature: object


@dataclass(frozen=True)
class VerificationBatchResult:
    verified: bool
    checked_inputs: int
    worker_count: int
    mode: str
    failure: str = ""


def _verify_one_input(
    *,
    signature_scheme: str,
    signing_payload: bytes,
    task: InputVerificationTask,
) -> tuple[bool, str]:
    provider = get_signature_verifier(signature_scheme)
    if provider.address_from_public_key(task.public_key) != task.address:
        return False, f"input {task.input_index} public key does not match referenced address"
    if not provider.verify(signing_payload, task.signature, task.public_key):
        return False, f"input {task.input_index} quantum signature verification failed"
    return True, ""


def _verify_native_batch(
    *,
    signature_scheme: str,
    signing_payload: bytes,
    tasks: list[InputVerificationTask],
    worker_count: int,
) -> VerificationBatchResult | None:
    if signature_scheme != "native_test_pq_v1":
        return None

    provider = get_signature_verifier(signature_scheme)
    native_signer = importlib.import_module("qr_chain_native_signer")
    native_batch_verify = getattr(native_signer, "verify_batch", None)
    if not callable(native_batch_verify):
        return None

    native_items: list[dict[str, object]] = []
    for task in tasks:
        try:
            if provider.address_from_public_key(task.public_key) != task.address:
                return VerificationBatchResult(
                    verified=False,
                    checked_inputs=len(native_items),
                    worker_count=0,
                    mode="native_precheck",
                    failure=f"input {task.input_index} public key does not match referenced address",
                )
        except ValueError as error:
            return VerificationBatchResult(
                verified=False,
                checked_inputs=len(native_items),
                worker_count=0,
                mode="native_precheck",
                failure=f"input {task.input_index} public key address derivation failed: {error}",
            )
        if not isinstance(task.signature, dict) or task.signature.get("mode") != "rust_extension":
            return None
        native_items.append(
            {
                "input_index": task.input_index,
                "message": signing_payload,
                "public_key": task.public_key,
                "signature": task.signature,
            }
        )

    try:
        result = native_batch_verify(native_items, max_workers=worker_count)
    except ValueError as error:
        if "requires the compiled Rust extension" in str(error) or "_native is not installed" in str(error):
            return None
        return VerificationBatchResult(
            verified=False,
            checked_inputs=len(tasks),
            worker_count=worker_count,
            mode="native_rust_batch",
            failure=f"native batch verification failed: {error}",
        )
    except RuntimeError as error:
        return VerificationBatchResult(
            verified=False,
            checked_inputs=len(tasks),
            worker_count=worker_count,
            mode="native_rust_batch",
            failure=f"native batch verification failed: {error}",
        )

    results = result.get("results", [])
    if not isinstance(results, list) or len(results) != len(tasks):
        return VerificationBatchResult(
            verified=False,
            checked_inputs=len(tasks),
            worker_count=worker_count,
            mode="native_rust_batch",
            failure="native batch verification returned an invalid result set",
        )

    actual_workers = int(result.get("worker_count", worker_count) or worker_count)
    for item in results:
        if not isinstance(item, dict):
            return VerificationBatchResult(
                verified=False,
                checked_inputs=len(tasks),
                worker_count=actual_workers,
                mode="native_rust_batch",
                failure="native batch verification returned a malformed item",
            )
        if not bool(item.get("verified", False)):
            failure = str(item.get("failure", "")) or "native signature verification failed"
            return VerificationBatchResult(
                verified=False,
                checked_inputs=len(tasks),
                worker_count=actual_workers,
                mode="native_rust_batch",
                failure=failure,
            )

    return VerificationBatchResult(
        verified=True,
        checked_inputs=len(tasks),
        worker_count=actual_workers,
        mode="native_rust_batch",
    )


def verify_transaction_inputs(
    transaction: Transaction,
    utxo_view: dict[tuple[str, int], TxOutput],
    *,
    max_workers: int | None = None,
) -> VerificationBatchResult:
    if not transaction.inputs:
        return VerificationBatchResult(verified=True, checked_inputs=0, worker_count=0, mode="empty")

    signing_payload = transaction.signing_payload()
    tasks: list[InputVerificationTask] = []
    seen_inputs: set[tuple[str, int]] = set()

    for input_index, tx_input in enumerate(transaction.inputs):
        key = (tx_input.prev_tx_id, tx_input.output_index)
        if key in seen_inputs:
            return VerificationBatchResult(
                verified=False,
                checked_inputs=len(tasks),
                worker_count=0,
                mode="precheck",
                failure="Transaction cannot spend the same UTXO twice.",
            )
        seen_inputs.add(key)

        previous_output = utxo_view.get(key)
        if previous_output is None:
            return VerificationBatchResult(
                verified=False,
                checked_inputs=len(tasks),
                worker_count=0,
                mode="precheck",
                failure=f"Unknown UTXO reference: {key}.",
            )
        tasks.append(
            InputVerificationTask(
                input_index=input_index,
                address=previous_output.recipient,
                public_key=tx_input.public_key,
                signature=tx_input.signature,
            )
        )

    worker_count = max_workers or min(len(tasks), max(1, os.cpu_count() or 1))
    native_result = _verify_native_batch(
        signature_scheme=transaction.signature_scheme,
        signing_payload=signing_payload,
        tasks=tasks,
        worker_count=worker_count,
    )
    if native_result is not None:
        return native_result

    if len(tasks) == 1 or worker_count <= 1:
        ok, failure = _verify_one_input(
            signature_scheme=transaction.signature_scheme,
            signing_payload=signing_payload,
            task=tasks[0],
        )
        return VerificationBatchResult(
            verified=ok,
            checked_inputs=1,
            worker_count=1,
            mode="single",
            failure=failure,
        )

    with ThreadPoolExecutor(max_workers=worker_count, thread_name_prefix="qbc-verify") as executor:
        results = list(
            executor.map(
                lambda task: _verify_one_input(
                    signature_scheme=transaction.signature_scheme,
                    signing_payload=signing_payload,
                    task=task,
                ),
                tasks,
            )
        )

    for ok, failure in results:
        if not ok:
            return VerificationBatchResult(
                verified=False,
                checked_inputs=len(tasks),
                worker_count=worker_count,
                mode="parallel",
                failure=failure,
            )
    return VerificationBatchResult(
        verified=True,
        checked_inputs=len(tasks),
        worker_count=worker_count,
        mode="parallel",
    )
