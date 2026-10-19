# QBC v2 Consensus Schemas — Stage 2.5 Candidate

**Status:** proposed normative candidate; requires protocol review and is NOT activated.
**Encoding:** `qbc-cjson-v1` (QBC-CJSON-V1).
**Scope:** object schemas and preimages for a future v2 test network only.

This document resolves the design choices raised in Stage 2.4 into a concrete candidate. It does not change v0.1 or activate v2 consensus. Existing `models.canonical_json`, transaction IDs, signature payloads, block hashes, state roots, peer frames, and vectors remain unchanged.

## 1. Decisions proposed for review

1. **Transaction ID:** hash the complete signed transaction preimage, including each input's public-key and signature payload, but excluding `tx_id` itself. This preserves the current implementation's broad identity model. Providers SHOULD use canonical signature encodings; a different valid signature payload produces a different transaction ID.
2. **Block commitment:** hash an ordered array of recomputed transaction-ID strings, not serialized transaction JSON strings. Validate every complete transaction independently before accepting the block.
3. **Signature preimage:** use one flat object with a single `version` and `chain_id`; omit input public keys and signatures. Bind the ordered outpoints, ordered outputs, fee, timestamp, kind, metadata, and signature-scheme identifier.
4. **State root:** hash the canonical flat array of all post-block UTXOs under the `state-root-v2` domain. This is not a Merkle tree and supplies no inclusion proofs.
5. **Version and activation:** every v2 object is explicitly versioned. First deployment is a separate test network with a new chain ID and genesis manifest. Do not add implicit v0.1 fallback after activation.

These choices are reviewable protocol decisions, not a claim of independent approval.

## 2. Shared encoding and primitive rules

- All preimages use `canonical_json_v1` and `hash_canonical_v1(domain, value)`.
- Hash construction is SHA-256 of `b"QBC-CJSON-V1\\x00" + ASCII(domain) + b"\\x00" + canonical_bytes`.
- Digests and transaction IDs are exactly 64 lowercase hexadecimal ASCII characters.
- `version` is the integer `2` for the schemas in this document.
- Integer fields are JSON integers in signed 64-bit range; booleans are not integers. Schema-level constraints further restrict values.
- `timestamp_us` is a non-negative integer count of microseconds since the Unix epoch. No float timestamps or implicit conversions are allowed.
- `chain_id` is an exact, case-sensitive network identifier; it is never inferred from a peer or local default.
- Unknown fields are rejected in v2 consensus objects and preimages. Any extension requires a new explicit schema version.
- Arrays are ordered and order-sensitive. Object member insertion order is irrelevant because canonical encoding sorts keys by UTF-8 bytes.
- JSON parsing must reject duplicate object keys before constructing a map, noncanonical bytes, invalid UTF-8, floats, unsupported types, and integers outside signed 64-bit range.

## 3. Signed transaction wire object

The v2 signed transaction wire object has exactly these top-level fields:

| Field | Type and rule |
|---|---|
| `version` | integer, exactly 2 |
| `chain_id` | non-empty ASCII string, at most 64 bytes |
| `kind` | registered kind token |
| `timestamp_us` | integer, 0 through 2^63−1 |
| `fee` | integer, 0 through 2^63−1 |
| `inputs` | ordered array; ordinary transfer requires 1–256 entries |
| `outputs` | ordered array of 1–256 entries |
| `metadata` | object governed by a kind-specific allowlist; canonical encoding at most 16 KiB |
| `signature_scheme` | registered provider ID, 1–64 lowercase ASCII characters |
| `tx_id` | 64 lowercase hexadecimal characters; omitted from transaction-ID preimage |

Each input has exactly `prev_tx_id`, `output_index`, `public_key`, and `signature`. The outpoint hash must be a valid transaction ID, and `output_index` is a non-negative signed-64-bit integer. Public-key and signature payloads are JSON values supported by the registered provider; their provider-specific schema and size limits must be part of the network manifest. Each output has exactly `recipient` and `amount`; recipient is a non-empty validated address string of at most 256 UTF-8 bytes, and amount is an integer from 1 through 2^63−1.

The canonical encoded signed transaction must not exceed 1 MiB. Implementations must enforce size and collection limits before expensive cryptographic verification. The v2 transfer schema rejects duplicate input outpoints. Kind-specific schemas define special inputless transactions, reward transactions, and migration claims explicitly; they must not bypass these base validation rules by relying on a missing field or an implicit default.

### 3.1 Transaction-ID preimage

The transaction-ID preimage has the same fields as the signed transaction except `tx_id`. It includes provider public-key and signature payloads. The digest is:

`hash_canonical_v1("transaction-v2", transaction_id_preimage)`

The wire object's `tx_id` must equal this digest. A transaction validator must recompute the ID; it must never trust the supplied value.

## 4. Signature preimage

The v2 signature preimage is one flat object with exactly:

- `version`
- `chain_id`
- `kind`
- `timestamp_us`
- `fee`
- `inputs` — ordered outpoints containing only `prev_tx_id` and `output_index`
- `outputs`
- `metadata`
- `signature_scheme`

It excludes `tx_id`, all input public keys, and all input signatures. It includes the transaction schema version and chain ID exactly once each. The digest is:

`hash_canonical_v1("signature-preimage-v2", signature_preimage)`

A provider's signing contract must state whether it signs these exact canonical bytes or a provider-specific digest derived from them. That rule and the provider's public-key/signature encoding must be pinned by the network manifest. Every input of an ordinary transfer verifies against the same transaction-wide signing message. Provider-specific signature validation remains mandatory; the encoding vectors below use clearly marked fixture payloads and do not constitute valid cryptographic signatures.

## 5. Block wire object and block-hash preimage

The v2 block wire object has exactly:

- `version`: integer 2
- `chain_id`: exact network identifier
- `height`: non-negative integer; genesis is height 0
- `previous_hash`: 64 lowercase hex characters; genesis uses 64 zeroes
- `timestamp_us`: non-negative integer microseconds
- `difficulty`: positive integer fixed by the network manifest
- `nonce`: non-negative integer
- `miner`: validated address or a precisely specified genesis marker
- `transactions`: ordered array of complete signed transaction wire objects
- `state_root`: 64 lowercase hexadecimal characters

The canonical encoded block must not exceed 4 MiB and must contain at most 4,096 transactions. The network manifest must set a compatible transaction limit and block limit. Each transaction ID is recomputed and validated before the block hash is checked.

The block-hash preimage contains every block field except `block_hash`; its `transactions` field is instead an ordered array of the recomputed transaction-ID strings. The digest is:

`hash_canonical_v1("block-v2", block_hash_preimage)`

No implementation may substitute serialized transaction strings, nested transaction objects, or an unordered set of transaction IDs. The state root is included for every v2 block. Parent/height continuity, proof of work, reward rules, transaction ordering, duplicate transaction handling, and state transition validity are separately required consensus checks.

## 6. State-root preimage

The preimage is an array containing every unspent output after all transactions in the block have been validated and applied in block order. Each item has exactly:

- `tx_id`: 64 lowercase hexadecimal characters
- `output_index`: non-negative signed-64-bit integer
- `recipient`: validated address string
- `amount`: positive signed-64-bit integer

Sort the array ascending by transaction ID's lowercase ASCII bytes, then by numeric output index. Duplicate outpoints are invalid; implementations must not silently deduplicate them. The root is:

`hash_canonical_v1("state-root-v2", sorted_utxo_array)`

The root of the empty list under this domain is the domain-separated digest of canonical bytes `[]`, not the legacy v0.1 state-root digest. This is a flat-list commitment, not a Merkle tree.

## 7. Consensus validation order

For a candidate v2 transaction/block, validators must at minimum:

1. Strictly parse canonical bytes and reject unknown/missing fields, wrong types, duplicate keys, floats, out-of-range integers, and oversized objects.
2. Verify schema version, chain ID, registered kind/provider, and provider payload shape.
3. Recompute the transaction ID from the defined preimage.
4. Validate each outpoint, reject duplicate inputs, derive addresses from public keys, and verify signatures.
5. Apply value conservation, fees, reward, maturity, supply, and kind-specific rules.
6. For blocks, verify parent and height, timestamp constraints, fixed configured difficulty/proof of work, transaction ordering/uniqueness, and complete state transition.
7. Recompute the state root and block hash and require exact equality with the supplied values.

The final implementation must specify the precise validation ordering where errors could affect state changes. Invalid candidates must not mutate durable chain state.

## 8. Versioned network manifest

A v2 test-network manifest must pin:
- manifest version, chain ID, genesis hash, and canonical encoding profile;
- transaction and block schema versions;
- activation at genesis for the initial test network;
- permitted transaction kinds, signature-provider IDs and exact provider versions;
- fixed difficulty/work calculation, timestamp constraints, reward and supply rules;
- all schema and size limits;
- a deterministic manifest digest and reference vectors.

Nodes must refuse a manifest that disagrees with their configured network. No activation by wall-clock time, peer assertion, or software version. Do not use this candidate to upgrade an existing network without a separate activation specification, boundary/reorganization rules, mixed-version tests, and independent review.

## 9. Candidate vectors and conformance

Vectors H–K in `docs/QBC_PROTOCOL_V2_VECTORS.md` cover:
- H: transaction-ID preimage with fixture public-key/signature payloads;
- I: flat signature preimage;
- J: sorted state-root preimage;
- K: block-hash preimage referencing the transaction ID and state root from H/J.

Python and Go tests must assert exact canonical bytes and domain-separated digest for every vector. The fixture payloads in H are placeholders only: they test encoding and hashing, not cryptographic signature validity. Positive/negative semantic schema tests and full multi-node consensus tests remain required before activation.

## 10. Compatibility and release gate

This candidate is opt-in and does not replace or modify any v0.1 path. Do not merge an activation change solely because these golden-vector tests pass. Before activation, require strict schema validators, negative vectors, provider-specific cryptographic vectors, manifest tests, multi-node and reorganization tests, mixed-version/downgrade tests, and independent protocol/security review.
