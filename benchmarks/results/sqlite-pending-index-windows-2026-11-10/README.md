# SQLite pending conflict index measurements (Windows, 2026-11-10)

This report records repeatable local workloads for the SQLite pending-transaction conflict-index change. These are machine measurements, not CI thresholds or performance guarantees.

## Change under measurement

Pending submission previously materialized/scanned the pending transaction set to detect conflicting spends and migration claims. The implementation adds indexed pending outpoints and migration claims, backfills existing mempool entries once, and checks/inserts under one SQLite `BEGIN IMMEDIATE` transaction. Removal and best-chain inclusion clean up the same indexes. This closes the race where concurrent submitters could both pass a service-level precheck.

The change does not alter transaction serialization, hashes, consensus validation, or live consensus rules.

## Environment and workloads

- Windows 10, Intel64 Family 6 Model 78, Python 3.13.14
- Real liboqs-backed ML-DSA-65 (`mldsa65_oqs_v1`)
- 128 submitted transactions; block-validation workload repeats validation of a prebuilt block containing 129 transactions 100 times.
- 499 submitted transactions; block-validation workload repeats validation of a prebuilt block containing 500 transactions 20 times.
- Each JSON file includes the benchmark’s exact environment, elapsed times, provider metadata, and workload parameters.

## Node submission results

Node submission includes validation and SQLite storage, with real signatures.

| Workload | Before samples (tx/s) | Before median | After samples (tx/s) | After median |
|---|---:|---:|---:|---:|
| 128 transactions | 2.7869, 2.9396, 2.0340 | 2.7869 | 3.3839, 3.1262, 3.0374 | 3.1262 |
| 499 transactions | 2.6254 (one sample) | n/a | 3.8323 (one sample) | n/a |

The 128-transaction sample sets overlap in range, so treat the change as an encouraging directional result rather than a definitive speedup. The 499-transaction comparison has only one sample per side and is especially preliminary. Benchmark machine load and signature-provider variability affect the result.

## Correctness and regression evidence

- Targeted pending spend, migration-claim, migration-backfill, and concurrent-submit tests: 4 passed.
- The full Python suite ran 318 tests but reported 4 failures and 1 error because Go subprocesses could not access the default Go build cache. Rerunning the affected Go and cross-runtime v2 tests with a writable isolated `GOCACHE` passed all 11 targeted tests. This is not a clean full-suite pass.
- Existing unrelated skips included absent official ACVP vector files and an unavailable built Rust extension.
- Three-node real-ML-DSA soak: 60/60 rounds passed; 120 synchronization operations; all validators converged; independent verifier checked 61 blocks. Runtime was 1,072.9 seconds on a heavily loaded test machine, so this soak is correctness evidence, not a throughput result.

The raw post-change benchmark and soak outputs are stored alongside this report. Pre-change benchmark JSON is in the existing `benchmarks/results/local-windows-ml-dsa-2026-11-09` report set.
