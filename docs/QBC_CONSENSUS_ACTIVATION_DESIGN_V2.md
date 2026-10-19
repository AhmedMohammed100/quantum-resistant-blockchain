# Stage 2.4 — Consensus Schema Specification and Activation Readiness

**Status:** design proposal; not normative and not activated.
**Target profile:** proposed QBC version 2 objects using `qbc-cjson-v1`.
**Compatibility rule:** this document does not change QBC v0.1 validation, serialization, hashes, signatures, state roots, peer frames, or network behavior.

## 1. Purpose and exit criteria

Stages 2.1–2.3 establish a portable canonical JSON profile, an independent Go implementation, and representative byte/hash fixtures. This stage identifies the protocol decisions that must be fixed before any consensus code can use that profile.

Do not activate a successor profile until all of the following are true:

1. Normative transaction, block, signature-preimage, and state-root schemas are approved and versioned.
2. Every hashed field and every excluded field is explicit, including the transaction-ID and block-hash preimages.
3. Field types, bounds, required fields, unknown-field policy, array ordering, and semantic checks are normative.
4. Python and an independent implementation pass positive and negative vectors for all consensus objects.
5. Activation is bound to an immutable network manifest and has deterministic mixed-version behavior.
6. The implementation passes regression, adversarial, reorganization, and multi-node conformance tests.
7. A reviewer independent of the implementation author has reviewed the protocol and activation plan.

This is a design gate, not permission to deploy or activate consensus.

## 2. Current compatibility boundary

The current reference implementation in `qr_blockchain/models.py` uses `models.canonical_json` and existing v0.1 preimages. The new encoder in `qr_blockchain/portable_encoding.py` is opt-in and MUST remain separate.

The existing v0.1 behavior includes:
- transaction IDs derived from the current transaction serialization;
- signature payloads that omit per-input public keys and signatures;
- block hashes that commit to canonical serialized transaction storage strings, including transaction IDs;
- a state-root representation based on the existing flat UTXO list;
- float-valued `timestamp` fields in existing objects.

Do not change those rules in place. Any successor implementation must use explicitly versioned objects and explicit activation rules. Existing vectors in `docs/QBC_PROTOCOL_VECTORS_V0_1.md` remain regression fixtures and must not be rewritten to match a successor profile.

## 3. Gaps in the current version-2 fixtures

The vectors in `docs/QBC_PORTABLE_ENCODING_V1.md` are useful encoding tests but are not yet normative object schemas.

### 3.1 Transaction fixture D is not yet a complete signed transaction

Vector D includes version, chain ID, transaction kind, integer-microsecond timestamp, fee, outpoints, outputs, metadata, and signature-scheme identifier. It does not include per-input public-key/signature payloads or a transaction ID.

The current v0.1 transaction-ID preimage includes the input objects' public-key and signature fields, while the signature preimage excludes those fields. A v2 design must explicitly define separate structures for:
- the signed transaction wire/storage object;
- the transaction-ID preimage;
- the signature preimage.

Until that distinction is specified, Vector D must not be described as the complete transaction-ID preimage.

### 3.2 Block fixture E does not match the current block model

Vector E uses `height` and commits to an array of transaction-ID references. The current `Block` model uses `index`, includes `miner`, and constructs its block-hash preimage using canonical serialized transaction storage JSON strings. These are different commitment designs.

The v2 protocol must choose one representation, specify it exactly, and publish matching vectors. It must not accidentally mix the vector's transaction-ID list with the legacy serialized-transaction-string rule.

### 3.3 Signature fixture F needs a precise signing contract

Vector F has an outer version and a nested transaction object. The nested object omits a second `version` field. The protocol must state whether the outer version alone identifies the signature schema, whether the chain ID is bound exactly once, and how provider-specific signature encodings are represented outside the preimage.

### 3.4 State-root fixture G needs complete validation rules

Vector G demonstrates canonical bytes and a domain-separated digest. The normative rules still need to define duplicate outpoint handling, hash-string syntax, amount bounds, sorting and comparison semantics, and how the state is derived from an ordered block execution. A hash vector alone does not establish that all nodes construct the same UTXO set.

## 4. Proposed schema separation (for review)

The following is a proposal for discussion, not a final schema.

### 4.1 Signed transaction wire object

Define a versioned signed transaction object with:
- `version`: required integer, exactly the supported transaction schema version;
- `chain_id`: required exact network identifier;
- `kind`: required registered transaction kind;
- `timestamp_us`: required signed 64-bit integer under `qbc-cjson-v1`;
- `fee`: required non-negative integer in quarks;
- `inputs`: ordered array of inputs; each input contains an outpoint and the provider-defined public-key/signature values needed for verification;
- `outputs`: ordered array of outputs, each with an address and positive integer amount;
- `metadata`: required object with a kind-specific allowlist of keys;
- `signature_scheme`: required registered provider identifier;
- `tx_id`: required lowercase 64-character hexadecimal value in the wire/storage form, excluded from its own ID preimage.

The final specification must set limits for input/output counts, string lengths, metadata size, total encoded object size, integer ranges, and each provider's public-key/signature shape. It must reject unknown top-level and nested fields unless a specific extension mechanism is explicitly versioned. It must not coerce strings to integers, booleans to integers, missing values to defaults, or floating-point values to integer timestamps.

### 4.2 Transaction-ID preimage

The protocol must state exactly which fields are hashed. Recommended baseline: use a dedicated transaction-ID object containing the transaction schema version and every consensus-relevant signed transaction field except `tx_id`, including the provider payloads that are part of the signed transaction. Use a dedicated domain such as `transaction-v2`.

If the project instead intends transaction IDs to exclude signatures, that is a substantive protocol choice: it affects malleability, identity, duplicate detection, and references. Do not make that choice implicitly in an implementation. The selected rule must be covered by positive and negative vectors.

### 4.3 Signature preimage

Define one transaction-wide signature preimage for each supported signing contract. At minimum, bind:
- schema version and chain ID;
- transaction kind and timestamp;
- ordered input outpoints (not public keys or signatures);
- ordered outputs;
- fee, metadata, and signature scheme.

The final design must specify whether each provider signs the same bytes directly or a provider-specific domain-separated digest of those bytes. It must specify exact public-key/signature encodings and reject unsupported or ambiguous encodings. All inputs in a transaction must verify against the exact same transaction-wide message unless a separately versioned transaction kind says otherwise.

### 4.4 Block wire object and block-hash preimage

The block schema must explicitly define:
- version, chain ID, height/index naming, parent hash, timestamp in integer microseconds, difficulty, nonce, miner/reward recipient, ordered transactions, and state root;
- the exact difference between wire fields and hashed preimage fields;
- whether the block commitment contains ordered transaction IDs or canonical serialized transaction objects;
- the exact rule for the genesis parent and genesis hash;
- whether the state root is included for every block of the new version;
- bounds and canonical syntax for every integer and digest.

**Recommendation for a new version:** commit to the ordered list of recomputed transaction IDs in the block hash preimage, while validating each complete transaction body separately. This is simpler to reproduce across languages than embedding serialized JSON strings. It is a proposed new-version rule, not a change to v0.1.

Do not use both a transaction-ID list and serialized transaction strings as competing interpretations. The chosen rule needs a dedicated `block-v2` vector and mutation tests proving that changing order, transaction IDs, parent, height, nonce, or state root changes the block hash as specified.

### 4.5 State-root preimage

For the flat-list commitment currently proposed, define each UTXO entry with exactly:
- `tx_id`: lowercase 64-character transaction ID;
- `output_index`: non-negative bounded integer;
- `recipient`: exact validated address string;
- `amount`: positive bounded integer number of quarks.

Sort entries by raw lowercase ASCII transaction-ID bytes, then by numeric output index, ascending. Reject duplicate outpoints. Derive the complete post-block UTXO view by applying transactions in block order, validating spends, outputs, fees, and rewards before calculating the root. Use the dedicated `state-root-v2` domain only if the final schema approves it. Document explicitly that this is a flat-list hash and not a Merkle tree.

## 5. Strict validation requirements

A successor schema validator must reject, rather than normalize:
- missing required fields, unknown fields, duplicate JSON keys, wrong JSON types, and invalid UTF-8;
- floats, integers outside the agreed range, negative fees, zero/negative output amounts, and invalid timestamp values;
- non-lowercase, malformed, truncated, or overlong digest strings;
- duplicate inputs within a transaction and duplicate UTXO outpoints in a state snapshot;
- inconsistent transaction IDs, wrong chain IDs, unsupported versions or signature schemes;
- invalid signature/provider payload shapes and failed address derivation/signature verification;
- block parent/height inconsistencies, wrong difficulty, invalid proof of work, and incorrect post-block state roots;
- any schema-version downgrade or mixed-version object not explicitly allowed by the activation policy.

Bounds must be selected based on implementation safety and network requirements, then documented as protocol parameters. Avoid arbitrary limits that are undocumented or different between implementations.

## 6. Network manifest and activation policy

A network manifest for a successor profile must be immutable for a given network and include at least:
- network/chain ID and genesis block hash;
- protocol version and canonical encoding profile identifier;
- activation rule (genesis for a new network, or an explicitly agreed height for an existing network);
- allowed transaction/block versions and signature-provider IDs;
- difficulty/work rules, reward and supply parameters, timestamp rules, and state-root rules;
- a manifest format/version and a published digest.

Nodes must reject a manifest that is inconsistent with their configured network. Nodes must not infer activation from software version, local wall-clock time, peer claims, or the mere presence of a new field.

For an existing chain, an activation height is safe only if the entire network agrees on the exact height and transition semantics before reaching it. Define whether the activation block itself uses the old or new rules, how reorgs crossing the activation boundary are validated, and how nodes behave if they have not upgraded. Do not allow nodes to silently fall back to v0.1 validation after activation.

**Recommended rollout:** first use a separate test network with a new chain ID and genesis manifest. Do not activate the new encoding on a network holding value until conformance, reorganization behavior, and an independent review are complete. A rollback after blocks are accepted under new consensus rules is not a routine software rollback; it may require a coordinated network reset or an explicit consensus migration.

## 7. Required conformance suite before activation

The suite must cover both exact encodings/hashes and semantic validation:
- all published vectors A–G, with clarified/renamed fixtures where needed;
- full signed transaction wire object, transaction-ID preimage, signature preimage, block preimage, and state-root preimage;
- field-order invariance for objects, while proving that ordered arrays remain order-sensitive;
- unknown fields, missing fields, duplicate keys, invalid UTF-8, floats, overflow, malformed hashes, duplicate outpoints, and unsupported versions;
- mutations to each consensus-relevant field and confirmation that the expected hash/validation result changes;
- transaction replay across chain IDs, signature replay, transaction-ID malleability cases, duplicate transaction inclusion, and invalid reward/supply cases;
- competing branches, equal-work tie-breaks, reorgs, activation-boundary reorgs, and nodes running mixed software versions;
- identical results from Python and at least one independent implementation, including rejection behavior rather than only matching positive vectors.

Every test vector must publish the logical object, exact canonical bytes (or an unambiguous hex encoding), domain, preimage definition, expected digest, and expected accept/reject result.

## 8. Implementation sequence after this design is approved

1. Resolve and document the schema choices in Sections 3–4.
2. Publish normative schemas and corrected vectors; retain old vectors as historical fixtures if names or semantics change.
3. Implement strict schema validators as opt-in functions with no callers in live consensus.
4. Add Python and independent-language tests for both accepted and rejected cases.
5. Add a versioned test-network manifest and end-to-end multi-node conformance tests.
6. Run adversarial, reorganization, downgrade, and mixed-version tests.
7. Obtain independent protocol/security review and record findings.
8. Only then propose a separate activation PR with explicit network-specific activation rules.

## 9. Non-goals

This stage does not:
- switch the live node to `qbc-cjson-v1`;
- alter `qr_blockchain/models.py` hashing or signing behavior;
- change existing transaction IDs, block hashes, state roots, or peer frames;
- claim the protocol is production-ready or quantum-safe solely because ML-DSA vectors pass;
- authorize accepting real funds or upgrading an existing network.

## 10. Review checklist

- [ ] Confirm whether transaction IDs include provider public-key/signature payloads.
- [ ] Confirm whether v2 block commitments use ordered transaction IDs or serialized transaction objects.
- [ ] Confirm the exact signed transaction wire schema versus transaction-ID and signature preimages.
- [ ] Confirm field bounds, unknown-field policy, metadata rules, and provider encodings.
- [ ] Confirm state-root ordering, duplicate handling, and integer limits.
- [ ] Confirm new-test-network-first rollout and mixed-version/reorg behavior.
- [ ] Approve normative schemas before implementing activation.
