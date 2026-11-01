# Consensus Signature Provider Policy

`QR_CHAIN_ALLOWED_SIGNATURE_PROVIDERS` is enforced when a node validates an ordinary transfer's input signatures and migration destination attestations. When the list is non-empty, the provider ID must appear in that list. This applies to mempool admission and imported blocks; the node does not accept an unlisted signature provider merely because it is registered in the software.

Production configuration must include the default signature provider in the allowlist. The production readiness gate rejects a missing allowlist, a default provider outside the allowlist, and demo providers such as `native_test_pq_v1`.

Every node validating the same network must use the same consensus provider allowlist. A different allowlist can cause nodes to accept different transactions or branches. The network's manifest and operator configuration must agree on the provider IDs and implementation versions.

An empty allowlist remains permissive for development and compatibility tests. Do not use it for a public network. This policy does not change transaction encoding, identifiers, signature preimages, block hashes, or existing provider formats.
