# QBC Cryptographic Implementation Security Audit

**Assessment date:** 2026-11-11  
**Audit scope:** cryptographic provider inventory, untrusted signature verification, stateful OQS signing state, Rust/liboqs FFI input lengths, and available known-answer testing.  
**Scope limits:** source review and regression tests; no formal verification, certification, or independent cryptographic implementation review was performed.

## Executive summary

QBC has two in-repository hash-signature implementations used as reference/compatibility code, several optional adapters, one Rust FFI boundary, and separate classical migration-claim verifiers. The Python binding pin is `liboqs-python==0.16.0.2`; its documented/native build target is liboqs 0.16.0. In the inspected local environment, the actual native runtime reported 0.16.0, ML-DSA-65 was enabled, and no stateful LMS/XMSS mechanisms were enabled. The binding version and native library version are distinct facts.

The cited XMSS issue, CVE-2026-46344, was fixed upstream in liboqs 0.16.0. QBC's optional OQS XMSS adapter now checks the **native** version and refuses versions before 0.16.0. The OQS LMS adapter now requires native liboqs >= 0.17.0 because separate LMS verification and stateful-signing defects affect 0.16.0. This is a deliberate fail-closed compatibility restriction; the repository's ordinary ML-DSA path remains on its existing 0.16.0 target.

A stateful signing review found that the OQS LMS adapter previously generated reservations without binding or consuming the reservation token, and it did not preserve an unfinished reservation in serialized key state. The adapter now uses a single-use token, a per-keypair lock, persistent pending state, and advances the secret state only after successful signing and export. The existing wallet reservation transaction persists the final state on failure so uncertain LMS state cannot silently be retried. A generic optional-backend verification boundary now turns backend exceptions into verification failure.

The Rust stateless liboqs verifier passed signature bytes to C without checking their exact algorithm-defined length. It now rejects short and oversized signatures before the FFI call. This reduces malformed-input exposure but does not replace native fuzzing or sanitizer runs.

## Provider and dependency inventory

| Provider / component | Implementation | Dependency and observed status |
|---|---|---|
| `hash_lamport_v1` | In-repository Lamport one-time signature reference implementation | Pure Python; compatibility provider. |
| `xmss_merkle_lamport_v1` | In-repository Merkle tree of Lamport leaves | Pure Python reference construction. Despite the provider name, this is an XMSS-style construction, **not RFC 8391 XMSS**. It is the default software provider. |
| `native_test_pq_v1` | Rust extension boundary | Optional Rust crate. Deterministic test mode is not production cryptography. The optional liboqs FFI uses stateless `OQS_SIG` APIs and has no LMS/XMSS state. |
| `mldsa65_oqs_v1` | Python adapter to liboqs | `liboqs-python==0.16.0.2`; target native liboqs 0.16.0. ML-DSA-65 is available in the inspected runtime. Official ACVP/FIPS 204 vector CI is present in the repository; this is vector testing, not a compliance claim. |
| `xmss_nist_v1` | External-module adapter; default module is QBC's reference backend | Default is the in-repository Lamport/Merkle construction above, not standards-compliant XMSS. Optional OQS adapter requires a stateful XMSS mechanism and native liboqs >= 0.16.0. No such stateful mechanism was enabled in the inspected local runtime. |
| `lms_nist_v1` | External-module adapter; optional OQS LMS backend | LMS adapter requires an enabled stateful LMS mechanism and now refuses native liboqs below 0.17.0. The inspected local liboqs 0.16.0 runtime had no stateful mechanism enabled, so LMS could not be exercised against native code locally. |
| `sphincsplus_v1` | External-module adapter | liboqs 0.16 removed SPHINCS+; the inspected OQS runtime did not provide it. It remains an optional adapter boundary, not a currently available provider in this environment. |
| RSA migration verifier | In-repository classical migration backend | Python `cryptography`-based RSA PKCS#1 v1.5/SHA-256 claim verification; not a transaction-signing provider. |
| secp256k1 migration verifier | In-repository classical migration backend | Python claim/address verification; not a transaction-signing provider. |

### Version and vulnerability compatibility

- The wrapper pin does not prove which native shared library was loaded. Runtime checks now call native `OQS_version()` in the OQS XMSS and LMS adapters and report that value.
- **CVE-2026-46344:** liboqs versions through 0.15.0 are affected by an XMSS/XMSSMT verification out-of-bounds read under an OID/parameter mismatch; upstream fixed it in 0.16.0. No affected native version was observed locally. An older library could previously have been selected by runtime installation/configuration; the QBC OQS XMSS adapter now blocks it.
- **CVE-2026-104254 / GHSA-wh5q-mpc8-67wf:** the separate LMS verification issue affects versions 0.11 through 0.16 when LMS is built/enabled and may cause an out-of-bounds read on truncated signatures. The QBC LMS adapter now blocks versions before 0.17.0. The inspected local build had no LMS mechanism enabled.
- **CVE-2026-104255 / GHSA-xv6c-h66p-6mfq:** an LMS stateful-signing locking defect can permit LM-OTS state reuse in affected liboqs builds. The adapter's single-use reservations and persistent state guard QBC's own calls; they do not repair an upstream native library. The >=0.17.0 runtime gate avoids relying on affected 0.16.0 native signing code.
- liboqs 0.16.0 removed SPHINCS+, so a configured SPHINCS+ adapter must not be presumed usable simply because the Python binding imports.

These are conditional exposures: the liboqs vulnerabilities require the corresponding native mechanism and call path to be compiled/enabled. The inspected environment did not enable LMS/XMSS stateful mechanisms.

## Verification and state-safety changes

This branch adds the following protections and regression coverage:

1. Native liboqs version parsing/enforcement for OQS XMSS (>= 0.16.0) and LMS (>= 0.17.0); unavailable, malformed, or too-old runtime versions fail closed.
2. Strict LMS public-key scheme/provider/library and signature mechanism/library binding, malformed hex rejection, and controlled failure when the native verifier/runtime fails.
3. Stateful LMS reservation tokens are matched, consumed once, locked per keypair, and persisted through serialization. A failed signing/export leaves the reservation pending and the key blocked pending retirement/recovery; it does not silently sign again from the same serialized state.
4. Existing SQLite wallet reservation handling persists the final serialized key state when a reserved signing attempt fails.
5. External module verifier exceptions become `False` at the transaction verification boundary rather than escaping validation.
6. Rust stateless liboqs verification rejects a public key or signature whose length differs from the selected algorithm's declared length before entering FFI.
7. A deterministic seeded malformed-input regression loop exercises 500 malformed QBC reference-XMSS verification inputs.

These checks cover malformed metadata and serialization/hex shape, algorithm/mechanism mismatch, incorrect and replayed reservations, failed stateful signing, and reservation concurrency on a shared keypair. They do not prove that arbitrary native library inputs are memory safe.

## Reproduction and test status

Run from the repository root:

```sh
python -W error::ResourceWarning -m unittest tests.test_crypto_backend_safety tests.test_xmss_security tests.test_xmss_signer_safety tests.test_crypto_verification_hardening tests.test_mldsa65_hardening -v
cargo test -p qr_chain_native_signer
```

The Python regression tests added in this audit use a deterministic fake OQS API to test version gates and state transitions without claiming native LMS availability. The Rust exact-length helper is unit tested without requiring liboqs. Run native integration separately on a build with the liboqs feature and the corresponding mechanisms enabled.

**Not completed locally:** coverage-guided native fuzzing, AddressSanitizer, direct OQS LMS/XMSS verification, and independent ML-DSA implementation comparison. The local stateful mechanisms were not compiled in, and external ACVP vector data was unavailable to the local runner. The repository's CI includes official ML-DSA ACVP vector checks; passing those vectors does not establish FIPS 204 certification. The research paper recommends KAT-seeded libFuzzer/ASan campaigns for stateful hash-based verification; QBC's deterministic Python corpus here is regression coverage, not an equivalent campaign.

## Prioritized remediation and follow-up

### P0 — Keep optional native stateful paths blocked until compatible

Require a liboqs release that fixes both disclosed LMS defects before enabling OQS LMS. Keep the XMSS native floor at 0.16.0 or later. Do not override the adapter's runtime check in production. Pin and report the native runtime in release/build provenance, not only the Python wheel.

### P1 — Add native fuzzing and sanitizer CI

Build liboqs with LMS/XMSS enabled in an isolated job. Add KAT-seeded fuzz targets for LMS/HSS and XMSS/XMSSMT verification, run with AddressSanitizer, retain minimized regression corpus entries, and test the Rust/Python/native boundaries. Run this only against a patched upstream release/commit and record the precise revision.

### P1 — Add independent ML-DSA cross-implementation verification

Keep the official FIPS 204 ACVP known-answer suite and add generated sign/verify interoperability cases against a separately maintained implementation. Test malformed key/signature lengths, wrong algorithms, truncated/oversized buffers, and provider initialization failures. Never silently fall back to the deterministic test signer or a weaker algorithm.

### P2 — Exercise persistence and process-level concurrency

Add end-to-end tests using the configured OQS LMS backend and SQLite wallet store on a patched native build: restart between reserve/sign, duplicate and expired reservation attempts, two processes reserving the same wallet key, and failures during native signing/state export/SQLite commit. Confirm operational recovery retires uncertain state rather than reusing it.

### P2 — Clarify provider names and availability in operator docs

Clearly distinguish the QBC Lamport/Merkle reference construction from RFC 8391 XMSS and identify which optional adapters are actually enabled by each liboqs build. Publish native runtime version and enabled mechanism list in node diagnostics.

## Sources

- liboqs advisory for CVE-2026-46344: https://github.com/open-quantum-safe/liboqs/security/advisories/GHSA-2wxh-55qf-c7wg
- liboqs 0.16 release notes: https://github.com/open-quantum-safe/liboqs/blob/main/RELEASE.md
- liboqs LMS truncated-verification advisory: https://github.com/open-quantum-safe/liboqs/security/advisories/GHSA-wh5q-mpc8-67wf
- liboqs LMS stateful-signing advisory: https://github.com/open-quantum-safe/liboqs/security/advisories/GHSA-xv6c-h66p-6mfq
- LMS native fix commit: https://github.com/open-quantum-safe/liboqs/commit/5c06c8a57e28d47466925fc86e5cfe777cb999c7
- Research paper, *KAT-Seeded Fuzzing of Stateful Hash-Based Signature Verification in liboqs*, IACR ePrint 2026/1107: https://eprint.iacr.org/2026/1107
- NIST FIPS 204: https://csrc.nist.gov/pubs/fips/204/final

