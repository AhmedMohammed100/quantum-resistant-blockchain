package qbccjson

import (
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"sort"
)

const (
	v2GenesisMiner = "qbc-genesis"
	v2ZeroHash     = "0000000000000000000000000000000000000000000000000000000000000000"
	v2MaxUTXOs     = 100000
)

type V2Outpoint struct {
	TxID        string
	OutputIndex int64
}

type V2UTXO struct {
	TxID        string `json:"tx_id"`
	OutputIndex int64  `json:"output_index"`
	Recipient   string `json:"recipient"`
	Amount      int64  `json:"amount"`
}

type V2GenesisAllocation struct {
	Recipient string
	Amount    int64
}

type V2ProviderConfig struct {
	SigningMode       string
	SigningDomain     string
	MaxPublicKeyBytes int64
	MaxSignatureBytes int64
	Verify            func(publicKey any, signature any, message []byte) (string, error)
}

type V2SchemaLimits struct {
	MaxTransactionBytes     int64
	MaxBlockBytes           int64
	MaxMetadataBytes        int64
	MaxInputs               int64
	MaxOutputs              int64
	MaxTransactionsPerBlock int64
}

// V2ConsensusConfig must come from a locally validated, manifest-pinned profile.
// Provider verification and address syntax are supplied by the local registry.
type V2ConsensusConfig struct {
	ChainID            string
	GenesisHash        string
	DifficultyBits     int64
	MaxTimestampStepUS int64
	MaxSupply          int64
	GenesisTimestampUS int64
	GenesisAllocations []V2GenesisAllocation
	Providers          map[string]V2ProviderConfig
	Limits             V2SchemaLimits
	AddressValidator   func(string) bool
}

type V2ConsensusNode struct {
	config      V2ConsensusConfig
	blocks      map[string]map[string]any
	states      map[string]map[V2Outpoint]V2UTXO
	branchTxIDs map[string]map[string]bool
	work        map[string]uint64
	tipHash     string
}

func NewV2ConsensusNode(config V2ConsensusConfig, genesis map[string]any) (*V2ConsensusNode, error) {
	if config.ChainID == "" || config.AddressValidator == nil || len(config.Providers) == 0 {
		return nil, errors.New("v2 consensus config is incomplete")
	}
	if config.DifficultyBits < 1 || config.DifficultyBits > 16 {
		return nil, errors.New("difficulty_bits must be in [1, 16]")
	}
	if config.MaxTimestampStepUS < 1 || config.MaxTimestampStepUS > 120000000 {
		return nil, errors.New("max_timestamp_step_us must be in [1, 120000000]")
	}
	if config.MaxSupply < 1 || config.GenesisTimestampUS < 0 {
		return nil, errors.New("invalid v2 supply or genesis timestamp")
	}
	if config.Limits.MaxTransactionBytes < 1 || config.Limits.MaxTransactionBytes > 1<<20 || config.Limits.MaxBlockBytes < config.Limits.MaxTransactionBytes || config.Limits.MaxBlockBytes > 4<<20 || config.Limits.MaxMetadataBytes < 1 || config.Limits.MaxMetadataBytes > 16<<10 || config.Limits.MaxMetadataBytes > config.Limits.MaxTransactionBytes || config.Limits.MaxInputs < 1 || config.Limits.MaxInputs > 256 || config.Limits.MaxOutputs < 1 || config.Limits.MaxOutputs > 256 || config.Limits.MaxTransactionsPerBlock < 1 || config.Limits.MaxTransactionsPerBlock > 4096 {
		return nil, errors.New("v2 manifest schema limits are invalid")
	}
	node := &V2ConsensusNode{
		config: config, blocks: map[string]map[string]any{},
		states:      map[string]map[V2Outpoint]V2UTXO{},
		branchTxIDs: map[string]map[string]bool{}, work: map[string]uint64{},
	}
	state, err := node.genesisState()
	if err != nil {
		return nil, err
	}
	root, err := v2StateRoot(state, config.AddressValidator)
	if err != nil {
		return nil, err
	}
	if err := validateV2Genesis(genesis, config, root); err != nil {
		return nil, err
	}
	hash, err := v2BlockHash(genesis, nil)
	if err != nil {
		return nil, err
	}
	if hash != config.GenesisHash {
		return nil, errors.New("genesis block hash does not match configured manifest")
	}
	node.blocks[hash] = cloneV2Map(genesis)
	node.states[hash] = state
	node.branchTxIDs[hash] = map[string]bool{}
	node.work[hash] = 0
	node.tipHash = hash
	return node, nil
}

func (n *V2ConsensusNode) TipHash() string { return n.tipHash }
func (n *V2ConsensusNode) TipWork() uint64 { return n.work[n.tipHash] }

func (n *V2ConsensusNode) StateRoot() (string, error) {
	return v2StateRoot(n.states[n.tipHash], n.config.AddressValidator)
}

func (n *V2ConsensusNode) State() []V2UTXO {
	return orderedV2UTXOs(n.states[n.tipHash])
}

func (n *V2ConsensusNode) AcceptBlock(candidate map[string]any) (bool, error) {
	parentHash, ok := candidate["previous_hash"].(string)
	if !ok {
		return false, errors.New("previous_hash must be a string")
	}
	parent, exists := n.blocks[parentHash]
	if !exists {
		return false, errors.New("block parent is unknown")
	}
	if err := exactV2Object(candidate, "version", "chain_id", "height", "previous_hash", "timestamp_us", "difficulty", "nonce", "miner", "transactions", "state_root", "block_hash"); err != nil {
		return false, err
	}
	encodedBlock, err := CanonicalJSONV1(candidate)
	if err != nil || int64(len(encodedBlock)) > n.config.Limits.MaxBlockBytes {
		return false, errors.New("block exceeds manifest byte limit or is not encodable")
	}
	if err := exactVersion(candidate["version"], 2, "version"); err != nil {
		return false, err
	}
	if candidate["chain_id"] != n.config.ChainID {
		return false, errors.New("chain_id does not match configured network")
	}
	height, err := v2NonNegativeInt(candidate["height"], "height")
	if err != nil {
		return false, err
	}
	parentHeight, err := v2NonNegativeInt(parent["height"], "parent height")
	if err != nil || parentHeight == math.MaxInt64 || height != parentHeight+1 {
		return false, errors.New("block height must be parent height plus one")
	}
	timestamp, err := v2NonNegativeInt(candidate["timestamp_us"], "timestamp_us")
	if err != nil {
		return false, err
	}
	parentTime, err := v2NonNegativeInt(parent["timestamp_us"], "parent timestamp")
	if err != nil || timestamp <= parentTime || timestamp-parentTime > n.config.MaxTimestampStepUS {
		return false, errors.New("block timestamp violates configured parent-time step")
	}
	difficulty, err := v2NonNegativeInt(candidate["difficulty"], "difficulty")
	if err != nil || difficulty != n.config.DifficultyBits {
		return false, errors.New("block difficulty does not match fixed network difficulty")
	}
	if _, err = v2NonNegativeInt(candidate["nonce"], "nonce"); err != nil {
		return false, err
	}
	miner, err := boundedString(candidate["miner"], "miner", 256, false)
	if err != nil || !n.config.AddressValidator(miner) {
		return false, errors.New("miner address is invalid")
	}
	transactions, ok := candidate["transactions"].([]any)
	if !ok || int64(len(transactions)) > n.config.Limits.MaxTransactionsPerBlock {
		return false, errors.New("block transaction count exceeds manifest limit")
	}
	state := cloneV2State(n.states[parentHash])
	ids := make([]string, 0, len(transactions))
	seen := map[string]bool{}
	for _, raw := range transactions {
		tx, ok := raw.(map[string]any)
		if !ok {
			return false, errors.New("transaction must be an object")
		}
		encodedTx, err := CanonicalJSONV1(tx)
		if err != nil || int64(len(encodedTx)) > n.config.Limits.MaxTransactionBytes {
			return false, errors.New("transaction exceeds manifest byte limit or is not encodable")
		}
		txID, owners, err := n.validateTransaction(tx)
		if err != nil {
			return false, err
		}
		if n.branchTxIDs[parentHash][txID] || seen[txID] {
			return false, errors.New("transaction ID is already present on this branch")
		}
		seen[txID] = true
		ids = append(ids, txID)
		state, err = n.applyTransfer(tx, txID, owners, state)
		if err != nil {
			return false, err
		}
	}
	total := int64(0)
	for _, coin := range state {
		if coin.Amount > math.MaxInt64-total {
			return false, errors.New("post-block state total overflows signed 64-bit range")
		}
		total += coin.Amount
	}
	if total > n.config.MaxSupply {
		return false, errors.New("post-block state exceeds manifest max_supply")
	}
	root, err := v2StateRoot(state, n.config.AddressValidator)
	if err != nil {
		return false, err
	}
	if candidate["state_root"] != root {
		return false, errors.New("state_root does not match block state transition")
	}
	hash, err := v2BlockHash(candidate, ids)
	if err != nil {
		return false, err
	}
	if !v2MeetsDifficulty(hash, n.config.DifficultyBits) {
		return false, errors.New("block hash does not satisfy fixed proof of work")
	}
	if _, exists := n.blocks[hash]; exists {
		return false, nil
	}
	blockWork := uint64(1) << n.config.DifficultyBits
	if n.work[parentHash] > ^uint64(0)-blockWork {
		return false, errors.New("cumulative chain work overflows uint64")
	}
	n.blocks[hash] = cloneV2Map(candidate)
	n.states[hash] = state
	branch := cloneV2Set(n.branchTxIDs[parentHash])
	for id := range seen {
		branch[id] = true
	}
	n.branchTxIDs[hash] = branch
	n.work[hash] = n.work[parentHash] + blockWork
	if n.work[hash] > n.work[n.tipHash] || (n.work[hash] == n.work[n.tipHash] && hash < n.tipHash) {
		n.tipHash = hash
	}
	return true, nil
}

func (n *V2ConsensusNode) genesisState() (map[V2Outpoint]V2UTXO, error) {
	if len(n.config.GenesisAllocations) == 0 || len(n.config.GenesisAllocations) > v2MaxUTXOs {
		return nil, errors.New("genesis allocation count is invalid")
	}
	state := make(map[V2Outpoint]V2UTXO, len(n.config.GenesisAllocations))
	var total int64
	last := ""
	for index, allocation := range n.config.GenesisAllocations {
		if allocation.Recipient <= last || !n.config.AddressValidator(allocation.Recipient) || allocation.Amount <= 0 || allocation.Amount > math.MaxInt64-total {
			return nil, errors.New("genesis allocations are invalid, unsorted, or overflow")
		}
		last = allocation.Recipient
		total += allocation.Amount
		preimage := map[string]any{"version": int64(2), "chain_id": n.config.ChainID, "allocation_index": int64(index), "recipient": allocation.Recipient, "amount": allocation.Amount}
		id, err := HashCanonicalV1("genesis-allocation-v2", preimage)
		if err != nil {
			return nil, err
		}
		outpoint := V2Outpoint{TxID: id, OutputIndex: 0}
		state[outpoint] = V2UTXO{TxID: id, OutputIndex: 0, Recipient: allocation.Recipient, Amount: allocation.Amount}
	}
	if total != n.config.MaxSupply {
		return nil, errors.New("genesis allocations must sum to manifest max_supply")
	}
	return state, nil
}

func validateV2Genesis(block map[string]any, config V2ConsensusConfig, stateRoot string) error {
	if err := exactV2Object(block, "version", "chain_id", "height", "previous_hash", "timestamp_us", "difficulty", "nonce", "miner", "transactions", "state_root", "block_hash"); err != nil {
		return err
	}
	if err := exactVersion(block["version"], 2, "version"); err != nil {
		return err
	}
	if block["chain_id"] != config.ChainID || block["height"] != int64(0) || block["previous_hash"] != v2ZeroHash || block["timestamp_us"] != config.GenesisTimestampUS || block["difficulty"] != int64(0) || block["nonce"] != int64(0) || block["miner"] != v2GenesisMiner {
		return errors.New("genesis block fields do not match configured genesis rules")
	}
	transactions, ok := block["transactions"].([]any)
	if !ok || len(transactions) != 0 {
		return errors.New("genesis block must have no transactions")
	}
	if block["state_root"] != stateRoot {
		return errors.New("genesis state_root does not match configured allocations")
	}
	return nil
}

func (n *V2ConsensusNode) validateTransaction(tx map[string]any) (string, []string, error) {
	if err := exactV2Object(tx, "version", "chain_id", "kind", "timestamp_us", "fee", "inputs", "outputs", "metadata", "signature_scheme", "tx_id"); err != nil {
		return "", nil, err
	}
	if err := exactVersion(tx["version"], 2, "version"); err != nil {
		return "", nil, err
	}
	if tx["chain_id"] != n.config.ChainID {
		return "", nil, errors.New("chain_id does not match configured network")
	}
	if tx["kind"] != "transfer" {
		return "", nil, errors.New("only transfer transactions are supported by qbc-pow-fixed@1")
	}
	fee, err := v2NonNegativeInt(tx["fee"], "fee")
	if err != nil {
		return "", nil, err
	}
	if _, err = v2NonNegativeInt(tx["timestamp_us"], "timestamp_us"); err != nil {
		return "", nil, err
	}
	metadata, ok := tx["metadata"].(map[string]any)
	if !ok || len(metadata) != 0 {
		return "", nil, errors.New("transfer metadata must be an empty object")
	}
	encodedMetadata, err := CanonicalJSONV1(metadata)
	if err != nil || int64(len(encodedMetadata)) > n.config.Limits.MaxMetadataBytes {
		return "", nil, errors.New("metadata exceeds manifest byte limit")
	}
	scheme, err := boundedString(tx["signature_scheme"], "signature_scheme", 64, true)
	if err != nil {
		return "", nil, err
	}
	provider, ok := n.config.Providers[scheme]
	if !ok || provider.Verify == nil {
		return "", nil, errors.New("signature provider is not locally registered")
	}
	inputs, ok := tx["inputs"].([]any)
	if !ok || len(inputs) < 1 || int64(len(inputs)) > n.config.Limits.MaxInputs {
		return "", nil, errors.New("transfer input count exceeds manifest limit")
	}
	outputs, ok := tx["outputs"].([]any)
	if !ok || len(outputs) < 1 || int64(len(outputs)) > n.config.Limits.MaxOutputs {
		return "", nil, errors.New("transfer output count exceeds manifest limit")
	}
	preimage := v2SignaturePreimage(tx, inputs)
	message, err := v2SignatureMessage(preimage, provider)
	if err != nil {
		return "", nil, err
	}
	owners := make([]string, 0, len(inputs))
	seenOutpoints := map[V2Outpoint]bool{}
	for _, raw := range inputs {
		input, ok := raw.(map[string]any)
		if !ok {
			return "", nil, errors.New("transaction input must be an object")
		}
		if err := exactV2Object(input, "prev_tx_id", "output_index", "public_key", "signature"); err != nil {
			return "", nil, err
		}
		encodedKey, keyErr := CanonicalJSONV1(input["public_key"])
		encodedSignature, signatureErr := CanonicalJSONV1(input["signature"])
		if keyErr != nil || int64(len(encodedKey)) > provider.MaxPublicKeyBytes || signatureErr != nil || int64(len(encodedSignature)) > provider.MaxSignatureBytes {
			return "", nil, errors.New("provider payload exceeds manifest byte maximum")
		}
		txid, err := digestString(input["prev_tx_id"], "prev_tx_id")
		if err != nil {
			return "", nil, err
		}
		index, err := v2NonNegativeInt(input["output_index"], "output_index")
		if err != nil {
			return "", nil, err
		}
		outpoint := V2Outpoint{TxID: txid, OutputIndex: index}
		if seenOutpoints[outpoint] {
			return "", nil, errors.New("duplicate input outpoint")
		}
		seenOutpoints[outpoint] = true
		owner, err := provider.Verify(input["public_key"], input["signature"], message)
		if err != nil {
			return "", nil, fmt.Errorf("signature verification failed: %w", err)
		}
		if !n.config.AddressValidator(owner) {
			return "", nil, errors.New("provider-derived address is invalid")
		}
		owners = append(owners, owner)
	}
	for _, raw := range outputs {
		output, ok := raw.(map[string]any)
		if !ok {
			return "", nil, errors.New("transaction output must be an object")
		}
		if err := exactV2Object(output, "recipient", "amount"); err != nil {
			return "", nil, err
		}
		recipient, err := boundedString(output["recipient"], "recipient", 256, false)
		if err != nil || !n.config.AddressValidator(recipient) {
			return "", nil, errors.New("recipient address is invalid")
		}
		amount, err := positiveInt(output["amount"], "amount")
		if err != nil {
			return "", nil, err
		}
		if amount > math.MaxInt64 {
			return "", nil, errors.New("amount out of range")
		}
	}
	withoutID := cloneV2Map(tx)
	delete(withoutID, "tx_id")
	computedID, err := HashCanonicalV1("transaction-v2", withoutID)
	if err != nil {
		return "", nil, err
	}
	providedID, err := digestString(tx["tx_id"], "tx_id")
	if err != nil || computedID != providedID {
		return "", nil, errors.New("tx_id does not match signed transaction preimage")
	}
	_ = fee
	return computedID, owners, nil
}

func (n *V2ConsensusNode) applyTransfer(tx map[string]any, txID string, owners []string, parent map[V2Outpoint]V2UTXO) (map[V2Outpoint]V2UTXO, error) {
	inputs := tx["inputs"].([]any)
	outputs := tx["outputs"].([]any)
	if len(inputs) != len(owners) {
		return nil, errors.New("input owner count mismatch")
	}
	state := cloneV2State(parent)
	var inputTotal, outputTotal int64
	spent := make([]V2Outpoint, 0, len(inputs))
	for i, raw := range inputs {
		input := raw.(map[string]any)
		index, _ := v2NonNegativeInt(input["output_index"], "output_index")
		outpoint := V2Outpoint{TxID: input["prev_tx_id"].(string), OutputIndex: index}
		coin, exists := state[outpoint]
		if !exists {
			return nil, errors.New("transfer input is missing or already spent")
		}
		if coin.Recipient != owners[i] {
			return nil, errors.New("input signer does not own referenced UTXO")
		}
		if coin.Amount > math.MaxInt64-inputTotal {
			return nil, errors.New("input sum overflow")
		}
		inputTotal += coin.Amount
		spent = append(spent, outpoint)
	}
	for _, raw := range outputs {
		amount := raw.(map[string]any)["amount"].(int64)
		if amount > math.MaxInt64-outputTotal {
			return nil, errors.New("output sum overflow")
		}
		outputTotal += amount
	}
	fee := tx["fee"].(int64)
	if fee > math.MaxInt64-outputTotal || inputTotal != outputTotal+fee {
		return nil, errors.New("input value must equal outputs plus burned fee")
	}
	for _, outpoint := range spent {
		delete(state, outpoint)
	}
	for index, raw := range outputs {
		output := raw.(map[string]any)
		outpoint := V2Outpoint{TxID: txID, OutputIndex: int64(index)}
		if _, exists := state[outpoint]; exists {
			return nil, errors.New("transaction duplicates an existing UTXO outpoint")
		}
		state[outpoint] = V2UTXO{TxID: txID, OutputIndex: int64(index), Recipient: output["recipient"].(string), Amount: output["amount"].(int64)}
	}
	if len(state) > v2MaxUTXOs {
		return nil, errors.New("state-root preimage exceeds 100000 UTXOs")
	}
	return state, nil
}

func v2SignaturePreimage(tx map[string]any, inputs []any) map[string]any {
	outpoints := make([]any, 0, len(inputs))
	for _, raw := range inputs {
		input := raw.(map[string]any)
		outpoints = append(outpoints, map[string]any{"prev_tx_id": input["prev_tx_id"], "output_index": input["output_index"]})
	}
	return map[string]any{"version": tx["version"], "chain_id": tx["chain_id"], "kind": tx["kind"], "timestamp_us": tx["timestamp_us"], "fee": tx["fee"], "inputs": outpoints, "outputs": tx["outputs"], "metadata": tx["metadata"], "signature_scheme": tx["signature_scheme"]}
}

func v2SignatureMessage(preimage map[string]any, provider V2ProviderConfig) ([]byte, error) {
	encoded, err := CanonicalJSONV1(preimage)
	if err != nil {
		return nil, err
	}
	switch provider.SigningMode {
	case "canonical-bytes":
		if provider.SigningDomain != "" {
			return nil, errors.New("canonical-bytes provider must not set a signing domain")
		}
		return encoded, nil
	case "provider-digest":
		if provider.SigningDomain == "" {
			return nil, errors.New("provider-digest provider requires a signing domain")
		}
		digest, err := HashCanonicalV1(provider.SigningDomain, preimage)
		if err != nil {
			return nil, err
		}
		return hex.DecodeString(digest)
	default:
		return nil, errors.New("unsupported provider signing mode")
	}
}

func v2StateRoot(state map[V2Outpoint]V2UTXO, addressValid func(string) bool) (string, error) {
	if len(state) > v2MaxUTXOs {
		return "", errors.New("state-root preimage exceeds 100000 UTXOs")
	}
	items := orderedV2UTXOs(state)
	preimage := make([]any, 0, len(items))
	for _, item := range items {
		if _, err := digestString(item.TxID, "tx_id"); err != nil {
			return "", err
		}
		if item.OutputIndex < 0 || item.Amount < 1 || item.Recipient == "" || !addressValid(item.Recipient) {
			return "", errors.New("invalid state UTXO")
		}
		preimage = append(preimage, map[string]any{"tx_id": item.TxID, "output_index": item.OutputIndex, "recipient": item.Recipient, "amount": item.Amount})
	}
	return HashCanonicalV1("state-root-v2", preimage)
}

func v2BlockHash(block map[string]any, transactionIDs []string) (string, error) {
	preimage := cloneV2Map(block)
	delete(preimage, "block_hash")
	ids := make([]any, len(transactionIDs))
	for i, id := range transactionIDs {
		ids[i] = id
	}
	preimage["transactions"] = ids
	return HashCanonicalV1("block-v2", preimage)
}

func v2MeetsDifficulty(hash string, bits int64) bool {
	raw, err := hex.DecodeString(hash)
	if err != nil {
		return false
	}
	whole, rem := bits/8, bits%8
	for i := int64(0); i < whole; i++ {
		if raw[i] != 0 {
			return false
		}
	}
	return rem == 0 || raw[whole]>>(8-rem) == 0
}

func orderedV2UTXOs(state map[V2Outpoint]V2UTXO) []V2UTXO {
	items := make([]V2UTXO, 0, len(state))
	for _, item := range state {
		items = append(items, item)
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].TxID != items[j].TxID {
			return items[i].TxID < items[j].TxID
		}
		return items[i].OutputIndex < items[j].OutputIndex
	})
	return items
}

func v2NonNegativeInt(value any, name string) (int64, error) {
	n, ok := integerValue(value)
	if !ok || n < 0 {
		return 0, fmt.Errorf("%s must be a non-negative signed 64-bit integer", name)
	}
	return n, nil
}

func exactV2Object(value any, fields ...string) error {
	wanted := keySet(fields...)
	_, err := exactObject(value, wanted, "v2 object")
	return err
}

func cloneV2State(source map[V2Outpoint]V2UTXO) map[V2Outpoint]V2UTXO {
	out := make(map[V2Outpoint]V2UTXO, len(source))
	for key, value := range source {
		out[key] = value
	}
	return out
}

func cloneV2Set(source map[string]bool) map[string]bool {
	out := make(map[string]bool, len(source))
	for key, value := range source {
		out[key] = value
	}
	return out
}

func cloneV2Map(source map[string]any) map[string]any {
	out := make(map[string]any, len(source))
	for key, value := range source {
		out[key] = value
	}
	return out
}
