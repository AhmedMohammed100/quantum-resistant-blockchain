# P2 independent cryptographic and protocol review brief

**Status:** prepared for external reviewer selection and review. No independent reviewer has been engaged, and no independent audit has been performed by this document.  
**Repository baseline:** main at `868a122016f09187e5f8987fe9da9e26186ff890`.  
**Purpose:** give an independent reviewer a bounded, reproducible scope and an explicit evidence checklist. This is not an audit report or certification.

## Review objectives

Obtain independent conclusions about whether QBC's implemented claims and documented protocol rules are supported by the code and reproducible evidence, with priority on consensus safety, cryptographic boundaries, monetary invariants, and migration/stateful-signing risk.

The reviewer should be independent of the implementation and release decisions. The project owner should record reviewer identity/organization, conflicts, scope, source revision, tool versions, limitations, findings, severity rationale, remediation commits, and retest evidence in a signed report or equivalent attributable artifact.

## Proposed scope

### 1. Consensus, transaction validity, and reorganization safety

Review the v0.1 validation and state-transition paths, independent chain verifier, multi-node consensus, fork choice, reorganization rollback/replay, replay protection, and durable state mutation ordering. Evaluate whether rejected blocks/transactions leave state unchanged and whether all nodes make the same decision from the same input.

Review v2 separately as an opt-in isolated test implementation. Confirm schemas, canonical preimages, strict rejection, transaction value conservation, state-root derivation, manifest/genesis binding, peer agreement, work accounting, equal-work tie-break, and restart/reorg behavior. Verify there is no path that implicitly activates v2 or falls back across versions.

### 2. Monetary invariants and economic claims

Trace genesis allocations, subsidy/emission, migration minting, reserve/suballocation caps, fees, rewards/burns, maturity, reorganization, and supply reporting. Distinguish v0.1's configured issuance model from the v2 test profile, which has no post-genesis issuance or miner reward and burns fees. Identify any invariant that is assumed by reports/docs but not enforced on every mutation path.

The reviewer is not asked to endorse economic parameters without an explicit economic-security mandate. If production economics are outside the engagement, state that limitation.

### 3. Cryptographic provider boundaries

Use `docs/CRYPTO_IMPLEMENTATION_SECURITY_AUDIT_2026-11.md` as the internal inventory, then independently verify:
- exact provider identities, code ownership, runtime/native library versions, and enabled mechanisms;
- malformed key/signature handling, parameter/provider mismatch, serialization limits, failure behavior, and no insecure fallback;
- Rust/Python/native FFI size and error boundaries;
- ML-DSA-65 interoperability and known-answer evidence, including what it does and does not establish;
- liboqs XMSS/LMS version gates and whether affected stateful verification/signing paths are unreachable or safely blocked;
- stateful key reservation, persistence, crash recovery, concurrent use, backup/restore, and uncertain-state retirement.

Do not infer that a provider label such as XMSS means RFC 8391 compliance; the internal audit distinguishes QBC's Lamport/Merkle reference construction from standards-based XMSS.

### 4. Migration and operational boundaries

Review `docs/MIGRATION_THREAT_MODEL.md`, migration claim/snapshot verification and governance, source binding, duplicate-claim prevention, dispute pause/reorganization, peer/API authentication and bounds, database recovery, release provenance, and the external-operator soak evidence. Separate code-verifiable guarantees from self-asserted operator or machine evidence.

## Evidence package to provide

For a pinned review revision, provide:
- source archive or immutable commit and repository state;
- relevant CI workflow URLs and run IDs, including cross-implementation ML-DSA tests, ACVP vector workflow, native fuzz/ASan workflow, v2 cross-runtime and node-consensus tests, and soak workflows;
- exact commands, dependency versions, compiler/platform/runtime versions, and retained logs/artifact hashes;
- internal crypto audit, security finding register, migration threat model, v2 normative/test-network/manifest documents, independent chain-verifier specification, and soak runbook;
- minimized reproductions and regression tests for every previously confirmed red-team finding;
- configuration files with secrets removed and a clear list of unavailable native providers, vectors, or test environments.

Do not include private keys, live credentials, production user data, or secret-bearing configuration in the evidence bundle.

## Reviewer deliverables

Ask the reviewer to return:
1. A scope and methodology statement, exact revision, dependencies/tools, and exclusions.
2. A findings table with severity, affected revision/path, preconditions, exploitability, impact, reproducible steps, and evidence.
3. A separate list of design concerns and unverified claims, clearly distinguished from confirmed vulnerabilities.
4. For every finding, a remediation recommendation and a regression test or verification method.
5. A retest of fixes on a named revision, with unresolved items and residual risk.
6. Explicit statements on whether the review included protocol/economic analysis, native memory safety, side-channel/constant-time assessment, independent cryptographic implementation review, and live-network/operational testing.
7. A signed or otherwise attributable final report suitable for release records.

The project must publish the report's scope and limitations. Do not claim formal verification, FIPS compliance, certification, or production readiness from a review unless the reviewer specifically substantiates that claim and the applicable authority supports it.

## Engagement and acceptance checklist

- [ ] Select an independent reviewer with relevant post-quantum cryptography and consensus/protocol experience.
- [ ] Agree scope, exclusions, schedule, deliverables, disclosure and remediation process.
- [ ] Pin the source revision and reproducibility environment.
- [ ] Supply sanitized evidence and answer reviewer questions.
- [ ] Track every finding in `docs/SECURITY_AUDIT_REGISTER.md` with severity, affected revisions, remediation and retest evidence.
- [ ] Require independent retest for remediated high/critical findings.
- [ ] Record unresolved findings and explicit risk acceptance; do not silently mark them closed.
- [ ] Publish or retain the final report according to the agreed disclosure plan.

## Current completion status

This brief makes the P2 review request actionable, but it does not complete the external-review criterion. It remains open until an independent reviewer is engaged, the review and retest are complete, and the evidence is recorded. This repository change does not contact or select a reviewer.
