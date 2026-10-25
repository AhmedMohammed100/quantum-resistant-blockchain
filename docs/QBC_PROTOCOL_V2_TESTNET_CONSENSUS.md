# QBC v2 Test-Network Consensus Profile

**Status:** repository-selected candidate rules for isolated v2 test networks; not an independently reviewed production protocol.
**Encoding:** `qbc-cjson-v1`.
**Compatibility:** v0.1 serialization, identifiers, hashes, peer frames, and live consensus are unchanged. V2 is a separate opt-in implementation and chain.

This document closes the schema and activation choices needed by the first interoperable v2 test-network implementation. A deployment must use a new chain ID and genesis. It does not authorize migration or activation on an existing v0.1 network.

## 1. Primitive rules

- JSON is UTF-8 QBC-CJSON-V1. Reject duplicate keys, floats, non-canonical bytes, invalid UTF-8, booleans in integer fields, unknown fields, and integers outside signed 64-bit range.
- Hashes are lowercase 64-character hex. Hash a preimage as SHA-256 of `QBC-CJSON-V1\0 || ASCII(domain) || 0x00 || canonical_json_v1(preimage)`.
- Object key order is insignificant; all arrays are ordered and order-sensitive.
- `chain_id` is exact and case-sensitive. It is required in every transaction and block.
- Schema and size ceilings remain those in `QBC_PROTOCOL_V2_NORMATIVE.md`; a manifest may lower them.

## 2. Transfer transactions

The signed transaction has exactly `version`, `chain_id`, `kind`, `timestamp_us`, `fee`, `inputs`, `outputs`, `metadata`, `signature_scheme`, and `tx_id`. Version is integer 2; the only transaction kind in this profile is `transfer`; timestamp and fee are non-negative signed-64-bit integers. Metadata is exactly the empty object. Transfers have 1–256 inputs and outputs.

Each input has exactly `prev_tx_id`, `output_index`, `public_key`, and `signature`. Each output has exactly `recipient` and `amount`; recipient is a validated network address and amount is a positive signed-64-bit integer. Duplicate input outpoints are invalid. The provider pinned by `signature_scheme` validates its public-key and signature shapes, verifies the signature, and derives the signing address. That address must own the referenced UTXO.

The transaction-ID preimage is the complete transaction with `tx_id` removed, including each provider payload. Its domain is `transaction-v2`.

The signature preimage is exactly the following projection:

```json
{
  "version": 2,
  "chain_id": "...",
  "kind": "transfer",
  "timestamp_us": 0,
  "fee": 0,
  "inputs": [{"prev_tx_id": "...", "output_index": 0}],
  "outputs": [{"recipient": "...", "amount": 1}],
  "metadata": {},
  "signature_scheme": "..."
}
```

For `canonical-bytes`, the provider signs the canonical JSON bytes of this object. For `provider-digest`, it signs the 32 digest bytes returned by `hash_canonical_v1(signing_domain, signature_preimage)`, where `signing_domain` is mandatory in the manifest. All inputs sign the same transaction-wide message. Public keys, signatures, and `tx_id` are excluded from this message.

When applied to state, the sum of referenced input values must equal the sum of output values plus `fee`, with checked signed-64-bit arithmetic. Fees are burned. A transaction ID may appear only once in a chain. A failed check has no state effect.

## 3. Blocks and fixed-work consensus

The block wire object has exactly `version`, `chain_id`, `height`, `previous_hash`, `timestamp_us`, `difficulty`, `nonce`, `miner`, `transactions`, `state_root`, and `block_hash`. The block-hash preimage removes `block_hash` and replaces complete transaction objects with their recomputed transaction-ID strings in the same order. Its domain is `block-v2`.

The initial test-network profile is fixed-work proof of work. Its exact parameters are `difficulty_bits` in `[1, 16]` and `max_timestamp_step_us` in `[1, 120000000]`. Every non-genesis block's `difficulty` must equal `difficulty_bits`; its recomputed `block_hash` must have at least that many leading zero bits. Difficulty does not retarget. Each accepted block contributes `2^difficulty_bits` work. The preferred chain is greatest cumulative work; equal-work tips are resolved by choosing the lexicographically smaller lowercase tip hash. This profile is for deterministic conformance and is not a production security parameter.

For a non-genesis block, height is parent height plus one, `previous_hash` is the parent's block hash, and `timestamp_us` is strictly greater than the parent timestamp and no more than the configured step ahead. Wall-clock time is not a consensus input. `miner` is a valid address but receives no reward. The initial profile has no coinbase, no reward transaction, and no issuance after genesis; fees are burned. Any reward or issuance design requires a separately reviewed schema/profile revision.

Transactions execute in block order against a temporary copy of the parent UTXO state. Repeated transaction IDs and any missing/already-spent input reject the block. Every transaction must pass schema, provider, ownership, and value checks. Only after the complete block succeeds may the new UTXO state, state root, and block be committed.

## 4. State root and genesis

The state-root preimage is the complete post-block UTXO array and is limited to 100,000 entries. Each UTXO has exactly `tx_id`, `output_index`, `recipient`, and `amount`; values are validated as for transaction outputs. Sort by lowercase transaction-ID ASCII bytes, then numeric output index, ascending. Reject duplicate outpoints. Hash the array with domain `state-root-v2`. This is a flat-list commitment, not a Merkle tree.

Genesis is a v2 block at height 0 with an all-zero parent hash, difficulty 0, nonce 0, the reserved miner value `qbc-genesis`, no transactions, and a state root computed from genesis allocations. Each genesis allocation is turned into one UTXO using a deterministic allocation ID:

`hash_canonical_v1("genesis-allocation-v2", {"version":2,"chain_id":chain_id,"allocation_index":i,"recipient":recipient,"amount":amount})`.

Allocation order is fixed by the manifest's `consensus_profile.parameters.genesis_allocations` and sorted by unique recipient address; allocation indexes are zero-based. The initial `qbc-pow-fixed@1` profile has exactly `genesis_timestamp_us`, `difficulty_bits`, `max_timestamp_step_us`, `max_supply`, and `genesis_allocations` parameters. Allocation values must sum exactly to `max_supply`. The manifest's `genesis_hash` must equal the recomputed genesis block hash. Genesis timestamp, fixed-work parameters, allocations, limits, provider set, and transaction kinds are all pinned by the manifest digest. Genesis is exempt from proof of work; its difficulty is exactly zero and its timestamp equals `genesis_timestamp_us`.

## 5. Peer agreement and activation

The only activation mode in this profile is `genesis` on a new, isolated chain ID. There is no height-based activation, time-based activation, software-version activation, downgrade, or fallback. A v2 node validates its local manifest and genesis before listening for v2 consensus messages.

Before exchanging blocks, a peer handshake must agree exactly on protocol version 2, chain ID, manifest digest, and genesis hash. Any mismatch rejects the peer before its transactions or blocks are processed. A v0.1 peer or unversioned frame is not a v2 peer and is rejected; v2 support is never inferred from a v0.1 connection. Existing v0.1 nodes continue their existing rules and do not activate v2.

## 6. Required conformance evidence

The multi-node suite must run at least two independently configured nodes and cover manifest/genesis agreement and mismatch, valid and invalid signed transfers, value conservation, transaction replay and chain-ID replay, block linkage and proof-of-work failure, state-root mismatch, peer version/configuration mismatch, persistence restart, competing forks, deterministic tie-break, and reorganization with state rollback/replay. It must assert rejected messages leave canonical state unchanged. Provider fixtures used by the suite are test-only and do not establish production cryptographic support.

Passing this suite is conformance evidence only. Before any public deployment, the schema and profile still require independent protocol/security review, production provider vectors, external cryptographic review, operational review, and an explicit decision to create a new network.
