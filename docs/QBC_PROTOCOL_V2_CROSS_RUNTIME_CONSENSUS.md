# QBC v2 Cross-Runtime Consensus Conformance

**Status:** opt-in conformance implementation for the isolated `qbc-pow-fixed@1` profile. It is not a production node or network activation.

The Python consensus node and the independent Go conformance engine now process the same manifest-pinned v2 chain rules. Both implementations validate genesis allocations, strict transfer schemas, transaction IDs and signatures, UTXO ownership and value conservation, block linkage and time bounds, fixed-work proof of work, state roots, manifest-selected size limits, cumulative work, deterministic tie-breaks, and branch reorganization.

The Go library exposes `V2ConsensusNode` with local provider and address-validation callbacks. Its `consensuscheck` command accepts a canonical conformance envelope containing a validated manifest, genesis block, and ordered candidate blocks. The command uses a deliberately test-only HMAC provider to verify the provider callback contract; it is not a supported production provider.

`tests/test_protocol_v2_cross_runtime_consensus.py` submits the same accepted chains and invalid candidates to Python and Go, then compares the selected tip, cumulative work, canonical state root, and UTXO set. Negative cases cover invalid signatures, state-root mismatch, and a manifest-lowered transaction byte limit. Go-native tests separately cover signed value transfer, fee burning, invalid candidates without tip mutation, fork tie-breaks, and reorganization.

This is consensus-rule parity evidence, not a second network implementation: the Go tool validates chains supplied to it and does not implement peer transport or durable storage. The Python loopback tests cover node transport and restart. The v0.1 node path remains unchanged and does not activate v2. Production cryptographic providers and vectors, mixed-version/downgrade integration tests, external review, and a separately approved network launch remain release gates.
