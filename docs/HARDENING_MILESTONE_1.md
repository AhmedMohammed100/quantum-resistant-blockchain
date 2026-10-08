# QBC Hardening Milestone 1

This milestone adds regression coverage for three high-risk boundaries without
changing the v0.1 consensus rules.

## 1. ML-DSA-65 runtime and official NIST ACVP verification vectors

`tests/test_mldsa65_hardening.py` exercises the configured
`mldsa65_oqs_v1` provider when its real OQS runtime is available. It checks the
selected mechanism, a valid sign/verify round trip, modified-message rejection,
wrong-public-key rejection, and malformed-signature rejection.

`tests/test_mldsa65_acvp_vectors.py` verifies the ML-DSA-65 pure external
signature-verification group from the official NIST ACVP `ML-DSA-sigVer-FIPS204`
vector set (vector-set ID 42). It compares each result, including invalid
signatures, with NIST's `expectedResults.json`. The source is pinned to ACVP-Server
commit `a7f283cdc87d2d6dd93c1bac59e5622c5f9f8324`; CI downloads both files from
that exact revision and runs the test with `liboqs-python >= 0.12.0`, which
provides context-aware ML-DSA verification.

To run locally, install `liboqs-python >= 0.12.0`, download the two official
files from the pinned source into a directory, set `QBC_ACVP_DATA_DIR` to that
directory, then run:

```bash
python -m unittest tests.test_mldsa65_acvp_vectors -v
```

These tests provide vector-based regression coverage; they do not constitute a
NIST cryptographic module validation or certification. They currently cover the
ML-DSA-65 pure external sigVer group, not every ACVP mode, pre-hash group,
key-generation group, or signature-generation group.

## 2. Deterministic protocol vectors

`tests/test_protocol_vectors.py` freezes transaction canonical JSON, transaction
ID, and a version-3 block hash that commits to the state root. These fixtures
are intended to catch accidental serialization or hash-preimage changes.
Changing a frozen value requires an explicit protocol-version review, not merely
updating the expected output to make CI pass.

The protocol document currently leaves portable UTXO state-root encoding
implementation-defined. This milestone does not invent a cross-language Merkle
encoding; a separate consensus proposal must define it before a portable
state-root vector can be normative.

## 3. Stateful XMSS signer safety

`tests/test_xmss_signer_safety.py` checks that the reference XMSS-style
signer's one-time leaf index advances after a process-style signer restart and
that two signer instances cannot successfully return the same leaf index under
concurrent use. A rejected concurrent reservation is acceptable; reuse is not.

These tests cover the repository's `xmss_merkle_lamport_v1` reference provider.
It is an XMSS-style Lamport/Merkle construction, not a claim that this provider
implements the standardized XMSS algorithm from RFC 8391. Production use still
requires an audited, standards-conformant stateful provider and external review.

## Local verification

Run the complete test suite:

```bash
python -W error::ResourceWarning -m unittest discover -s tests -v
```

Run the three existing focused suites:

```bash
python -m unittest discover -s tests -p 'test_mldsa65_hardening.py' -v
python -m unittest discover -s tests -p 'test_protocol_vectors.py' -v
python -m unittest discover -s tests -p 'test_xmss_signer_safety.py' -v
```
