# Security Audit Register

**Status:** In progress — internal code review, not an independent security audit.

This register records concrete findings and the evidence required to close them. Passing automated tests does not establish cryptographic certification or production readiness.

## Finding QBC-SEC-001 — XMSS-style leaf-index aliasing

- **Area:** qr_blockchain/crypto.py, XMSSMerkleLamportSignatureProvider.verify
- **Severity:** High (internal assessment; confirm with independent reviewer)
- **Status:** Remediated in branch; CI verification pending
- **Issue:** The verifier previously accepted any non-negative integer leaf index and did not require the authentication path length to equal the public key's tree height. The Merkle path calculation consumes only as many low-order index bits as there are path elements. Consequently, an otherwise valid index i could be changed to i + 2**height while preserving the same path calculation and potentially still verify.
- **Impact:** Different serialized signatures could identify the same one-time leaf. Systems relying on the serialized leaf index to track one-time-signature use could miscount or fail to detect reuse.
- **Correction:** Require a positive bounded tree height, a non-boolean integer leaf index in [0, 2**height), an authentication path of exactly height string elements, and a non-empty string root. Malformed input returns verification failure instead of leaking parsing exceptions.
- **Regression tests:** tests/test_crypto_verification_hardening.py covers index aliasing, out-of-range indices, wrong authentication-path depth, malformed metadata, and valid-signature preservation.
- **Closure evidence required:** Full regression suite and CI matrix pass; independent review confirms the fix and checks all call sites that enforce one-time-leaf uniqueness.

## Audit work still required

The following are open review areas, not claims that vulnerabilities have been found:

1. **Consensus and monetary invariants:** independently review block acceptance, reorganization handling, transaction replay, reward issuance, and every supply-cap path.
2. **Stateful signing and custody:** inspect reservation atomicity, crash recovery, backup/restore, concurrent processes, and key-state rollback.
3. **Cryptographic implementation boundaries:** verify that production configurations cannot select test/reference providers unintentionally; check backend contract validation and algorithm/profile identity.
4. **Migration claims:** review source-address binding, duplicate-claim prevention, snapshot provenance, reviewer quorum, and pause/reorg behavior.
5. **Peer and API boundaries:** review authentication, URL allowlists, request parsing, rate-limit failure behavior, resource bounds, and concurrent requests.
6. **Persistence and recovery:** exercise interrupted commits, stale database restoration, migrations, and reconciliation against independent chain checkpoints.

## Audit discipline

- Preserve a minimal reproducer and a regression test for each confirmed defect.
- Do not change frozen protocol vectors or consensus behavior simply to make tests pass; any necessary protocol change requires separate compatibility review.
- Record severity, exploit preconditions, affected versions, remediation commit, and independent closure evidence.
- Do not describe this project as production-ready or independently audited until the corresponding external review has actually occurred.
