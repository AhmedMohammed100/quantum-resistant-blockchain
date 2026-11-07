# Independent chain replay and PQ benchmarks

## Offline chain replay

`qr_blockchain.chain_verifier.verify_chain` replays an exported linear block
sequence without constructing `NodeService` and without calling
`NodeService.validate_block`. It independently checks block linkage, hashes,
proof of work, transaction identifiers, PQ signatures for transfer inputs,
UTXO spends, double spends, reward accounting, optional supply caps, UTXO
conservation, and active state-root commitments.

Migration claim output structure and uniqueness are checked. The offline
verifier does not verify classical source ownership proofs, migration snapshot
provenance, dispute/escrow/finality policy, or production key-provider
certification. The JSON report lists these limits so a successful replay is
not mistaken for a full consensus or security audit. Signature verification
uses the configured provider implementation.

Example:

```python
from qr_blockchain.chain_verifier import verify_chain

report = verify_chain(
    blocks,
    chain_id="qbc-mainnet-candidate",
    subsidy_at_height=policy.subsidy_at_height,
    difficulty=3,
    state_root_activation_height=0,
    max_money=policy.max_money,
)
if not report["valid"]:
    raise ValueError(report["error"])
```

## Real ML-DSA benchmark

The benchmark uses `mldsa65_oqs_v1` by default and fails if the real OQS
backend is unavailable. It reports key generation, signature and verification
rates and serialized sizes, then signs distinct funded transfers, measures
node transaction validation/storage, and repeatedly validates a block
containing those transactions. Mining is outside the block-validation timer.

Install the optional OQS dependency and run:

```powershell
python -m pip install --requirement requirements-oqs.txt
python -m benchmarks.benchmark_node --operations 8 --block-repetitions 5 --output benchmark.json
```

The `PQ Benchmarks` GitHub workflow runs weekly and can be started manually.
Its JSON output is attached as a workflow artifact for comparison across
runners. The measurements are diagnostic data; they do not set consensus
parameters or CI performance thresholds.

## Decomposition boundary

The first `NodeService` extraction is the pure UTXO state projection and root
calculation module (`qr_blockchain.chain_state`). Existing `NodeService` method
names remain as compatibility wrappers. The independent replay and fork
recovery tests are guardrails for the next bounded extraction. Storage and
route changes should follow their separate repository and middleware
boundaries: SQLite transaction ownership stays centralized, and API
authentication/body limits remain enforced before route dispatch.

