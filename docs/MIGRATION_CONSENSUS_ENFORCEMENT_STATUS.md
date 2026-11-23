## Migration consensus enforcement implementation status (2026-11-23)

Profile v2 now provides an opt-in deterministic claim-validation path:

- it commits the complete normalized snapshot registry and every migration
  policy value used by claim verification, conversion, dual control, and caps;
- profile and policy digest are pinned in local configuration, included in the
  protocol manifest, and compared during signed peer handshake;
- profile-aware block validation resolves sources from the committed artifact,
  not node-local migration rows;
- public-mode claim validation fails closed without a profile, and public
  profiles must activate at height 1;
- startup revalidates existing canonical migration claims and pool/epoch
  accounting against the pinned profile;
- block validation uses a fixed maximum of the pinned escrow and dispute
  windows for migration output spendability.

This closes the code path that previously let local source rows and policy
settings determine post-activation block validity, provided every validator
pins the same profile and uses compatible verification implementations.
The profile is an out-of-band network parameter; it is not embedded in v0.1
blocks. Operators must agree on its hash before enabling public claims.

Local emergency pause, source quarantine, and dispute records remain
admission and reporting controls; they do not change post-activation block
validity. A profile does not implement on-chain dispute adjudication or a
coordinated network halt. Post-finality fraud recovery and changes to the
registry/policy require a separately specified consensus upgrade.

Do not treat this source change as a production activation. MTH-01 is closed
only for a network where every validator has reviewed and pinned the same
profile, peer handshakes confirm the digest, and cross-node tests prove
matching decisions. Source-export truth, reviewer independence, and external
cryptographic review remain separate release gates.
