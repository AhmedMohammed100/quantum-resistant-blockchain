# P2 review: consensus economics and v2 activation

**Review type:** repository evidence review; not an economic-security analysis by an independent specialist.  
**Reviewed base:** main at `868a122016f09187e5f8987fe9da9e26186ff890`.  
**Result:** v0.1 and v2 are distinct models. The isolated v2 profile is internally explicit about zero post-genesis issuance, but it does not yet define production economics. No activation or currency behavior is changed by this review.

## Executive assessment

QBC has two materially different consensus/economic contexts:

1. **Existing v0.1 implementation:** configurable subsidy, halving, genesis/emission/migration caps, and allocation sub-caps. The canonical supply-accounting work treats treasury, security reserve, and public-goods caps as suballocations inside genesis supply rather than additional mintable pools. Existing supply and migration guards/tests are evidence for those implementation invariants; they are not proof of a complete economic security model.
2. **Opt-in v2 `qbc-pow-fixed@1` test profile:** genesis allocations must sum exactly to manifest `max_supply`; genesis is exempt from proof of work; every later block uses fixed difficulty, has no miner reward, no coinbase, no migration claim, and no post-genesis issuance; transaction fees are burned. It is a conformance profile, not a viable production incentive design.

These models must not be combined by implication. The v0.1 subsidy settings do not apply to v2, and v2's no-reward rule does not silently change v0.1.

## Evidence reviewed

- `qr_blockchain/currency.py`: `CurrencyPolicy`, subsidy/halving and emission-cap calculations, and allocation-plan reporting.
- `qr_blockchain/config.py`: configured genesis, emission, migration, treasury, security-reserve, public-goods, and max-money caps.
- `qr_blockchain/service.py`: `consensus_economics_report`, supply checks, and configured reward/maturity reporting.
- `tests/test_currency.py` and supply/consensus tests: existing regression evidence for cap accounting and reward/supply behavior.
- `docs/QBC_PROTOCOL_V2_NORMATIVE.md`, `docs/QBC_PROTOCOL_V2_TESTNET_CONSENSUS.md`, and `docs/QBC_PROTOCOL_V2_MANIFEST_CANDIDATE.md`: opt-in schema, test profile, manifest, and activation rules.
- `tests/test_protocol_v2_node_consensus.py` and cross-runtime manifest tests: isolated conformance evidence, not external approval.

## Findings and required decisions

### E-1 — V2 has no production incentive or attack-cost model (release blocker)

The current v2 test profile burns fees and grants no block reward or issuance after genesis. Fixed difficulty is explicitly for deterministic conformance and is not a production security parameter. Consequently, the profile does not establish who bears ongoing validation/mining costs, what sustains participation, how much adversarial work is affordable, or how security changes as participation changes.

**Disposition:** retain as a test-only rule. Before any value-bearing deployment, commission a separate economic-security design covering the consensus mechanism, attacker cost assumptions, participant incentives, operating costs, issuance/funding, and failure conditions. This review does not choose those parameters.

### E-2 — Legacy cap categories need interpretation at every reporting boundary

The legacy policy exposes genesis, emission, migration, treasury, security-reserve, public-goods, and total-supply caps. The allocation model makes the three named allocations suballocations within the genesis cap; they are not additive issuance categories. Genesis, emission, and migration are distinct mintable sources subject to the overall max-money cap. A report that merely sums every field in `allocation_plan` would double-count nested caps.

**Disposition:** preserve the canonical allocation semantics. Keep a regression assertion that the mintable source categories reconcile to `max_money` under the project's chosen model, while nested allocations are reported separately as suballocations. Any change to source caps or their relationship requires a separately reviewed accounting change and tests.

### E-3 — Genesis-only activation is a safe boundary for the current candidate, not a migration plan

The v2 manifest binds a new chain ID and genesis hash, and peers must agree on protocol version, manifest digest, and genesis. The profile forbids height/time/software activation, fallback, and downgrade. This avoids an implicit v0.1-to-v2 consensus transition, but it does not specify migrating balances, governance approval, or reorganizations between different networks.

**Disposition:** do not reinterpret genesis-only activation as an upgrade mechanism. Any future migration between networks needs its own threat model, snapshot provenance, replay protection, value reconciliation, operator coordination, and independently reviewed procedure.

### E-4 — Economics status labels are readiness signals, not proof

The v0.1 `consensus_economics_report` checks configured caps, halving interval, validator policy, and maturity declaration. Passing those checks means only that selected settings are present and currently within their basic bounds. It does not prove issuance conservation under all traces, sufficient attack cost, liveness, decentralization, fee adequacy, or economic sustainability. Likewise, v2 conformance tests do not establish those properties.

**Disposition:** describe these outputs as configuration/conformance evidence. Do not call either profile economically secure or production-ready based on these checks.

## Normative clarification to resolve before activation

The v2 normative schema's block field table currently says `difficulty` is positive and fixed by the manifest. The test-network profile separately specifies genesis difficulty exactly zero and exempts genesis from proof of work; its non-genesis rule requires the positive configured difficulty. This appears to be a schema-level conditional omission, not evidence that genesis behavior is ambiguous in the test profile.

Before the next schema revision or any activation proposal, clarify the normative field rule explicitly: genesis difficulty is exactly zero; non-genesis difficulty equals the manifest's positive `difficulty_bits`. Add/retain vectors and negative cases for both. Do not change validation behavior or vectors solely through this review.

Other economic parameters intentionally remain unresolved for production: fee policy under large PQ signatures, block-space pricing, participant/validator admission and Sybil resistance, reward or treasury funding, maturity/lockups if rewards are introduced, and long-run budget/security assumptions.

## Activation gate

A production or public value-bearing activation proposal should remain blocked until all of the following have named evidence and independent sign-off:

- A versioned economic model states issuance sources, cap relationships, fees, rewards, burns, reserves, maturity, and overflow behavior.
- Invariant/property tests cover total supply and each mint path over boundary heights, reorgs, replay, migration disputes, and failed commits.
- Consensus parameters have a threat model for adversarial resource cost, participant concentration, liveness, and recovery.
- A manifest pins the reviewed rules and an independently implemented validator agrees on vectors and reject cases.
- Activation, rollback/recovery, operator coordination, and any cross-network migration have separate procedures and review.
- The independent protocol/security review records findings and closure status.

## Scope and compatibility

This is a review artifact only. It does not change v0.1 serialization, hashes, supply rules, live consensus, v2 schemas, test-profile rules, or activation. It does not claim independent economic, protocol, or cryptographic review.
