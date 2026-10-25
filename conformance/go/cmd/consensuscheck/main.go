// Command consensuscheck validates a v2 chain with the independent Go profile
// implementation and a test-only HMAC provider. It is a conformance tool, not
// a production node or cryptographic provider.
package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	qbccjson "github.com/AhmedMohammed100/quantum-resistant-blockchain/conformance/go"
)

var fixtureSecret = []byte("test-only-not-a-production-key")

func main() {
	raw, err := io.ReadAll(io.LimitReader(os.Stdin, (64<<20)+1))
	if err != nil {
		fail(err)
	}
	if len(raw) > 64<<20 {
		fail(errors.New("conformance envelope exceeds 64 MiB"))
	}
	value, err := qbccjson.ParseCanonicalJSONV1(raw)
	if err != nil {
		fail(err)
	}
	envelope, ok := value.(map[string]any)
	if !ok {
		fail(errors.New("conformance envelope must be an object"))
	}
	if err := exact(envelope, "manifest", "genesis_block", "blocks"); err != nil {
		fail(err)
	}
	manifest, ok := envelope["manifest"].(map[string]any)
	if !ok {
		fail(errors.New("manifest must be an object"))
	}
	genesis, ok := envelope["genesis_block"].(map[string]any)
	if !ok {
		fail(errors.New("genesis_block must be an object"))
	}
	blocks, ok := envelope["blocks"].([]any)
	if !ok {
		fail(errors.New("blocks must be an array"))
	}
	chainID, ok := manifest["chain_id"].(string)
	if !ok {
		fail(errors.New("manifest chain_id must be a string"))
	}
	genesisHash, ok := genesis["block_hash"].(string)
	if !ok {
		fail(errors.New("genesis block_hash must be a string"))
	}
	providerProfiles := map[qbccjson.V2ManifestProfileKey]qbccjson.V2ManifestDescriptorValidator{
		{ID: "fixture_hmac", Version: "1.0.0"}: func(profile map[string]any) error {
			if profile["signing_mode"] != "canonical-bytes" {
				return errors.New("fixture profile only supports canonical-bytes")
			}
			return nil
		},
	}
	consensusProfiles := map[qbccjson.V2ManifestProfileKey]qbccjson.V2ManifestDescriptorValidator{
		{ID: "qbc-pow-fixed", Version: "1"}: validateFixedProfile,
	}
	digest, err := qbccjson.ValidateV2NetworkManifest(
		manifest, chainID, genesisHash, map[string]bool{"transfer": true}, providerProfiles, consensusProfiles,
	)
	if err != nil {
		fail(err)
	}
	_ = digest
	parameters := manifest["consensus_profile"].(map[string]any)["parameters"].(map[string]any)
	allocationsRaw := parameters["genesis_allocations"].([]any)
	allocations := make([]qbccjson.V2GenesisAllocation, 0, len(allocationsRaw))
	for _, rawAllocation := range allocationsRaw {
		allocation := rawAllocation.(map[string]any)
		allocations = append(allocations, qbccjson.V2GenesisAllocation{Recipient: allocation["recipient"].(string), Amount: allocation["amount"].(int64)})
	}
	providerEntries := manifest["signature_providers"].([]any)
	provider := providerEntries[0].(map[string]any)
	providerConfig := qbccjson.V2ProviderConfig{SigningMode: provider["signing_mode"].(string), MaxPublicKeyBytes: provider["max_public_key_bytes"].(int64), MaxSignatureBytes: provider["max_signature_bytes"].(int64), Verify: verifyFixtureHMAC}
	if domain, ok := provider["signing_domain"].(string); ok {
		providerConfig.SigningDomain = domain
	}
	limits := manifest["limits"].(map[string]any)
	config := qbccjson.V2ConsensusConfig{
		ChainID: chainID, GenesisHash: genesisHash,
		DifficultyBits:     parameters["difficulty_bits"].(int64),
		MaxTimestampStepUS: parameters["max_timestamp_step_us"].(int64),
		MaxSupply:          parameters["max_supply"].(int64),
		GenesisTimestampUS: parameters["genesis_timestamp_us"].(int64),
		GenesisAllocations: allocations,
		Providers:          map[string]qbccjson.V2ProviderConfig{provider["provider_id"].(string): providerConfig},
		Limits:             qbccjson.V2SchemaLimits{MaxTransactionBytes: limits["max_transaction_bytes"].(int64), MaxBlockBytes: limits["max_block_bytes"].(int64), MaxMetadataBytes: limits["max_metadata_bytes"].(int64), MaxInputs: limits["max_inputs"].(int64), MaxOutputs: limits["max_outputs"].(int64), MaxTransactionsPerBlock: limits["max_transactions_per_block"].(int64)},
		AddressValidator:   func(address string) bool { return len(address) <= 256 && strings.HasPrefix(address, "qbc1") },
	}
	node, err := qbccjson.NewV2ConsensusNode(config, genesis)
	if err != nil {
		fail(err)
	}
	for i, rawBlock := range blocks {
		block, ok := rawBlock.(map[string]any)
		if !ok {
			fail(fmt.Errorf("block %d must be an object", i))
		}
		if _, err := node.AcceptBlock(block); err != nil {
			fail(fmt.Errorf("block %d: %w", i, err))
		}
	}
	root, err := node.StateRoot()
	if err != nil {
		fail(err)
	}
	state := make([]any, 0)
	for _, item := range node.State() {
		state = append(state, map[string]any{"tx_id": item.TxID, "output_index": item.OutputIndex, "recipient": item.Recipient, "amount": item.Amount})
	}
	result := map[string]any{"tip_hash": node.TipHash(), "work": fmt.Sprintf("%d", node.TipWork()), "state_root": root, "utxos": state}
	encoded, err := qbccjson.CanonicalJSONV1(result)
	if err != nil {
		fail(err)
	}
	if _, err = os.Stdout.Write(encoded); err != nil {
		fail(err)
	}
	os.Stdout.Write([]byte("\n"))
}

func validateFixedProfile(profile map[string]any) error {
	if err := exact(profile, "difficulty_bits", "max_timestamp_step_us", "max_supply", "genesis_timestamp_us", "genesis_allocations"); err != nil {
		return err
	}
	bits, ok := profile["difficulty_bits"].(int64)
	if !ok || bits < 1 || bits > 16 {
		return errors.New("unsupported difficulty_bits")
	}
	step, ok := profile["max_timestamp_step_us"].(int64)
	if !ok || step < 1 || step > 120000000 {
		return errors.New("unsupported max_timestamp_step_us")
	}
	supply, ok := profile["max_supply"].(int64)
	if !ok || supply < 1 {
		return errors.New("invalid max_supply")
	}
	if timestamp, ok := profile["genesis_timestamp_us"].(int64); !ok || timestamp < 0 {
		return errors.New("invalid genesis_timestamp_us")
	}
	allocations, ok := profile["genesis_allocations"].([]any)
	if !ok || len(allocations) == 0 || len(allocations) > 100000 {
		return errors.New("invalid genesis_allocations")
	}
	total := int64(0)
	previous := ""
	for _, raw := range allocations {
		allocation, ok := raw.(map[string]any)
		if !ok || exact(allocation, "recipient", "amount") != nil {
			return errors.New("invalid genesis allocation object")
		}
		recipient, ok := allocation["recipient"].(string)
		amount, amountOK := allocation["amount"].(int64)
		if !ok || !strings.HasPrefix(recipient, "qbc1") || recipient <= previous || !amountOK || amount <= 0 || amount > int64(^uint64(0)>>1)-total {
			return errors.New("invalid, unsorted, or overflowing genesis allocations")
		}
		previous = recipient
		total += amount
	}
	if total != supply {
		return errors.New("genesis allocations must sum to max_supply")
	}
	return nil
}

func verifyFixtureHMAC(publicKey any, signature any, message []byte) (string, error) {
	key, ok := publicKey.(map[string]any)
	if !ok || len(key) != 1 {
		return "", errors.New("fixture public key shape is invalid")
	}
	owner, ok := key["owner"].(string)
	if !ok || !map[string]bool{"alice": true, "bob": true, "carol": true, "miner": true}[owner] {
		return "", errors.New("fixture public key owner is unknown")
	}
	sig, ok := signature.(string)
	if !ok {
		return "", errors.New("fixture signature shape is invalid")
	}
	mac := hmac.New(sha256.New, fixtureSecret)
	mac.Write(message)
	if !hmac.Equal([]byte(sig), []byte(hex.EncodeToString(mac.Sum(nil)))) {
		return "", errors.New("fixture signature is invalid")
	}
	return "qbc1" + owner, nil
}

func exact(object map[string]any, fields ...string) error {
	if len(object) != len(fields) {
		return errors.New("conformance envelope fields mismatch")
	}
	for _, field := range fields {
		if _, ok := object[field]; !ok {
			return fmt.Errorf("conformance envelope missing %s", field)
		}
	}
	return nil
}

func fail(err error) { fmt.Fprintln(os.Stderr, err); os.Exit(1) }
