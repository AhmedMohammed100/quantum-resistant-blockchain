# QBC Hardening Milestone 1

This milestone adds regression coverage for three high-risk boundaries without
changing the v0.1 consensus rules.

## 1. ML-DSA-65 runtime verification

`tests/test_mldsa65_hardening.py` exercises the configured
`mldsa65_oqs_v1` provider when its real OQS runtime is available. It checks the
selected mechanism, a valid sign/verify round trip, modified-message rejection,
wrong-public-key rejection, and malformed-signature rejection. If the optional
runtime is unavailable, the live test is skipped with the backend reason rather
than silently substituting a test provider.

**Important limitation:** these integration tests are not NIST FIPS 204
known-answer tests (KATs). Official ACVP/KAT input files and their provenance
must be added and validated before claiming KAT coverage or cryptographic
certification. The repository's deterministic native test backend is not a
replacement for ML-DSA.

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

Run only this milestone's tests:

```bash
python -m unittest discover -s tests -p 'test_mldsa65_hardening.py' -v
python -m unittest discover -s tests -p 'test_protocol_vectors.py' -v
python -m unittest discover -s tests -p 'test_xmss_signer_safety.py' -v
```
