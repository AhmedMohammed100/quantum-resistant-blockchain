# Local ML-DSA workload evidence

Run date: 2026-11-09 UTC  
Provider: `mldsa65_oqs_v1` using liboqs 0.16.0 with ML-DSA-65 enabled  
Runtime: Python 3.13.14 on Windows 10 (10.0.19045), Intel64 Family 6 Model 78 Stepping 3

These are diagnostic measurements from one local machine. They are not release thresholds, production-capacity claims, or directly comparable to the Ubuntu/Python 3.11 CI artifacts. The local liboqs build enabled ML-DSA-65 only. The provider was verified available before the real-provider measurements.

## Repeatability at 128 transfers

Each run used 128 signed transfers and 100 validations of a 129-transaction candidate block. Mining time is excluded from block-validation timing.

| Metric | Run 1 | Run 2 | Run 3 | Median | Range |
| --- | ---: | ---: | ---: | ---: | ---: |
| ML-DSA signing (ops/s) | 676.9 | 544.0 | 404.2 | 544.0 | 404.2–676.9 |
| ML-DSA verification (ops/s) | 3,600.5 | 3,100.2 | 1,482.4 | 3,100.2 | 1,482.4–3,600.5 |
| Wallet transaction signing (tx/s) | 24.92 | 18.07 | 25.52 | 24.92 | 18.07–25.52 |
| Node submission, validation and storage (tx/s) | 2.787 | 2.940 | 2.034 | 2.787 | 2.034–2.940 |
| Block validation (blocks/s) | 4.525 | 4.084 | 4.351 | 4.351 | 4.084–4.525 |
| Block transaction verification (tx/s) | 579.3 | 522.8 | 556.9 | 556.9 | 522.8–579.3 |

The spread is material, especially for standalone crypto operations. Use the range as well as the median; more controlled repeated runs are needed before publishing a headline score.

## Larger block workload

The benchmark now allows up to 499 signed transfers, leaving one slot for the reward transaction within the node's 500-entry default block limit.

| Transfers | Block entries | Block validations | Submission rate | Block rate | Transaction verifications |
| ---: | ---: | ---: | ---: | ---: | ---: |
| 256 | 257 | 1 | 2.949 tx/s | 2.289 blocks/s | 585.9 tx/s |
| 499 | 500 | 20 | 2.625 tx/s | 1.472 blocks/s | 734.5 tx/s |

The 256-transfer sample is a pipeline probe with one block validation, so its block rate is especially noisy. The 499-transfer result is the larger representative block measurement. The transfers use real ML-DSA signatures, distinct genesis UTXOs, one recipient, and a fee; the benchmark is still a controlled synthetic workload and does not model a public network's transaction mix.

## Three-node soak and network recovery

The real-ML-DSA soak used three independent node processes (one leader and two validators), mined 60 signed transfers, completed 120 validator syncs, converged all nodes, checked final balances, and replayed all 61 blocks with the independent chain verifier. It passed in 722.9 seconds (0.083 transfers/s on this local runner). Raw report: [`three-node-soak-60.json`](three-node-soak-60.json).

The existing partition, latency, dropped-block-response, recovery, and restart test also passed in 26.6 seconds. That fault-injection test uses the deterministic test signer, so it is network-recovery evidence rather than real-ML-DSA fault-injection evidence.

## Submission-path profile

A `cProfile` run at 64 transfers attributed most submission time to SQLite storage work: `save_pending_transaction` accumulated 14.8 seconds, and managed connection exit/close accumulated 9.5/6.9 seconds. Profiling adds overhead and these figures identify a hotspot, not a clean throughput result. The measured submission rate includes the current per-transaction SQLite durability and mempool-validation path. This is a likely optimization target; any storage change needs transaction-integrity, crash-recovery, and concurrency regression coverage before its new score is compared.

## Reproduction and report inventory

Install the repository's pinned real-OQS requirements and ensure the ML-DSA-65 mechanism is enabled. Then set `QR_CHAIN_DEPLOYMENT_MODE=test`, `QR_CHAIN_MLDSA_BACKEND_MODULE=qr_chain_mldsa_backend`, `QR_CHAIN_MLDSA_OQS_MECHANISM=ML-DSA-65`, and `PYOQS_VERSION=0.16.0` before running:

```powershell
python benchmarks/benchmark_node.py --operations 128 --block-repetitions 100 --output run.json
python benchmarks/benchmark_node.py --operations 499 --block-repetitions 20 --output near-cap.json
```

On this Windows setup, temporary files were directed to a short writable path using `TMP` and `TEMP`; doing so avoided a local SQLite temporary-database open failure during an earlier 256-transfer attempt. This is a runner detail, not a consensus setting.

The raw JSON files preserve the per-run backend metadata and measurements. `library_version` is reported as `unknown` by the adapter even though the locally built native liboqs runtime reported version 0.16.0 at setup time.

