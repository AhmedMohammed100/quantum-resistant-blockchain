# QBC v2 test-network manifest candidate

**Status:** opt-in implementation proposal for protocol review. This document
does not activate v2 or define a production network. It leaves v0.1 serialization,
hashes, and consensus behavior unchanged.

The normative v2 specification requires a versioned genesis manifest and lists
the values it must pin, but it does not yet define a complete manifest schema,
digest domain, or encoding vector. This candidate supplies those missing details
for review and tests. They must be approved before any implementation relies on
them for network activation.

## Candidate schema

The manifest is a strict `qbc-cjson-v1` object with exactly these fields:

| Field | Meaning |
| --- | --- |
| `manifest_version` | Integer `1`. |
| `chain_id` | Configured network identifier; at most 64 ASCII bytes. |
| `genesis_hash` | 32-byte lowercase hexadecimal hash. |
| `encoding_profile` | Literal `qbc-cjson-v1`. |
| `transaction_schema_version`, `block_schema_version` | Both integer `2`. |
| `activation` | Exactly `{ "mode": "genesis" }` for this initial test-network candidate. |
| `transaction_kinds` | Nonempty, sorted, unique lowercase tokens; includes `transfer`. Each kind must have a locally registered schema. |
| `signature_providers` | Nonempty list sorted by unique `provider_id`, pinning exact provider version, signing mode, public-key/signature schema tokens, and payload byte maxima. `provider-digest` additionally pins `signing_domain`. |
| `consensus_profile` | Exact `{profile_id, profile_version, parameters}` descriptor resolved by a local profile registry. The profile parameters must pin consensus details such as work, timestamp, reward, and supply rules. |
| `limits` | Exact limits object described below. |
| `manifest_digest` | Lowercase SHA-256 hex digest computed as described below. |

The exact limits object contains positive integer fields `max_transaction_bytes`,
`max_block_bytes`, `max_metadata_bytes`, `max_inputs`, `max_outputs`, and
`max_transactions_per_block`. Current v2 schema ceilings are 1 MiB per
transaction, 4 MiB per block, 16 KiB metadata, 256 inputs, 256 outputs, and
4,096 transactions per block. A manifest may choose smaller bounds. Metadata
cannot exceed the transaction bound, and a transaction cannot exceed the block
bound. Provider key and signature byte maxima cannot exceed the transaction
bound.

Every descriptor rejects unknown fields. Provider and consensus descriptors
must resolve through local registries, and the registered validator is
responsible for rejecting parameters it does not implement. The manifest alone
does not install algorithms or activate the network.

## Digest and fixture vector

Compute `manifest_digest` by removing that field and applying the existing
`qbc-cjson-v1` domain-separated hash with domain string `network-manifest-v2` to
the remaining object. This self-excluding construction gives the fixture below
the digest
`dcaee8df5e114551a305bf44b2a6ee21f53f439faca7f0f05502a3955311649c`.
The matching canonical bytes and digest are asserted in Python and Go tests.
The Go conformance module also independently validates this manifest schema
and has positive and negative cases for network mismatch, unsupported profiles,
unknown fields, activation, and limits. These checks are still opt-in library
calls; they do not activate or connect network nodes.
The fixture profile and schema labels are test values only, not supported
cryptographic providers or production consensus parameters.

`tests/test_protocol_v2_manifest_cross_runtime.py` invokes the Python and Go
validators against the same canonical fixture bytes and configured network
expectations. It checks matching acceptance/digests and matching rejection for
network mismatch and semantic mutations. This is a validator interoperability
gate only: it does not exercise node-to-node transport, transaction/block
acceptance, restart, reorganization, or mixed-version behavior, and it does not
resolve the open protocol choices below.

The validator also requires the manifest chain ID and genesis hash to match
locally configured expectations. This function is a schema/configuration check;
it is not wired into node startup or consensus in this stage.

## Open protocol decisions

The normative document does not define whether to allow activation modes other
than genesis for isolated v2 networks, how `consensus_profile.parameters` are
encoded for each real consensus profile, whether provider IDs or profile IDs
need a global namespace, or whether the listed schema ceilings are final
network-wide maxima. This candidate chooses genesis-only activation, local
versioned registries, and the existing v2 schema ceilings as validation maxima.
Protocol review should resolve these choices before activation work.
