package qbccjson

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
)

const (
	v2TestChainID           = "qbc-v2-cross-runtime"
	v2TestGenesisTime int64 = 1700000000000000
	v2TestDifficulty  int64 = 4
	v2TestSupply      int64 = 1000
)

var v2TestSecret = []byte("test-only-not-a-production-key")

func v2TestAddress(address string) bool { return strings.HasPrefix(address, "qbc1") }

func v2TestProvider(publicKey, signature any, message []byte) (string, error) {
	key, ok := publicKey.(map[string]any)
	if !ok {
		return "", errors.New("bad fixture key")
	}
	owner, ok := key["owner"].(string)
	if !ok || !map[string]bool{"alice": true, "bob": true, "carol": true, "miner": true}[owner] {
		return "", errors.New("unknown fixture key owner")
	}
	sig, ok := signature.(string)
	if !ok {
		return "", errors.New("bad fixture signature")
	}
	mac := hmac.New(sha256.New, v2TestSecret)
	mac.Write(message)
	if !hmac.Equal([]byte(sig), []byte(hex.EncodeToString(mac.Sum(nil)))) {
		return "", errors.New("signature is invalid")
	}
	return "qbc1" + owner, nil
}

func v2TestNode(t *testing.T) (*V2ConsensusNode, map[string]any) {
	t.Helper()
	config := V2ConsensusConfig{
		ChainID: v2TestChainID, DifficultyBits: v2TestDifficulty,
		MaxTimestampStepUS: 120000000, MaxSupply: v2TestSupply,
		GenesisTimestampUS: v2TestGenesisTime,
		GenesisAllocations: []V2GenesisAllocation{{Recipient: "qbc1alice", Amount: v2TestSupply}},
		Providers:          map[string]V2ProviderConfig{"fixture_hmac": {SigningMode: "canonical-bytes", MaxPublicKeyBytes: 128, MaxSignatureBytes: 128, Verify: v2TestProvider}},
		Limits:             V2SchemaLimits{MaxTransactionBytes: 1 << 20, MaxBlockBytes: 4 << 20, MaxMetadataBytes: 16 << 10, MaxInputs: 256, MaxOutputs: 256, MaxTransactionsPerBlock: 4096},
		AddressValidator:   v2TestAddress,
	}
	probe := &V2ConsensusNode{config: config}
	state, err := probe.genesisState()
	if err != nil {
		t.Fatal(err)
	}
	root, err := v2StateRoot(state, v2TestAddress)
	if err != nil {
		t.Fatal(err)
	}
	genesis := map[string]any{"version": int64(2), "chain_id": v2TestChainID, "height": int64(0), "previous_hash": v2ZeroHash, "timestamp_us": v2TestGenesisTime, "difficulty": int64(0), "nonce": int64(0), "miner": v2GenesisMiner, "transactions": []any{}, "state_root": root}
	hash, err := v2BlockHash(genesis, nil)
	if err != nil {
		t.Fatal(err)
	}
	genesis["block_hash"] = hash
	config.GenesisHash = hash
	node, err := NewV2ConsensusNode(config, genesis)
	if err != nil {
		t.Fatal(err)
	}
	return node, genesis
}

func v2TestTransfer(t *testing.T, previous string, amount, fee int64) map[string]any {
	t.Helper()
	input := map[string]any{"prev_tx_id": previous, "output_index": int64(0), "public_key": map[string]any{"owner": "alice"}, "signature": ""}
	tx := map[string]any{"version": int64(2), "chain_id": v2TestChainID, "kind": "transfer", "timestamp_us": v2TestGenesisTime + 1, "fee": fee, "inputs": []any{input}, "outputs": []any{map[string]any{"recipient": "qbc1bob", "amount": amount}}, "metadata": map[string]any{}, "signature_scheme": "fixture_hmac"}
	preimage := v2SignaturePreimage(tx, tx["inputs"].([]any))
	message, err := v2SignatureMessage(preimage, V2ProviderConfig{SigningMode: "canonical-bytes"})
	if err != nil {
		t.Fatal(err)
	}
	mac := hmac.New(sha256.New, v2TestSecret)
	mac.Write(message)
	input["signature"] = hex.EncodeToString(mac.Sum(nil))
	idPreimage := cloneV2Map(tx)
	id, err := HashCanonicalV1("transaction-v2", idPreimage)
	if err != nil {
		t.Fatal(err)
	}
	tx["tx_id"] = id
	return tx
}

func v2TestBlock(t *testing.T, node *V2ConsensusNode, parent map[string]any, txs []any, timestampDelta int64, requireLess string) map[string]any {
	t.Helper()
	state := cloneV2State(node.states[parent["block_hash"].(string)])
	ids := make([]string, 0, len(txs))
	for _, raw := range txs {
		tx := raw.(map[string]any)
		id, owners, err := node.validateTransaction(tx)
		if err != nil {
			t.Fatal(err)
		}
		state, err = node.applyTransfer(tx, id, owners, state)
		if err != nil {
			t.Fatal(err)
		}
		ids = append(ids, id)
	}
	root, err := v2StateRoot(state, v2TestAddress)
	if err != nil {
		t.Fatal(err)
	}
	block := map[string]any{"version": int64(2), "chain_id": v2TestChainID, "height": parent["height"].(int64) + 1, "previous_hash": parent["block_hash"], "timestamp_us": parent["timestamp_us"].(int64) + timestampDelta, "difficulty": v2TestDifficulty, "nonce": int64(0), "miner": "qbc1miner", "transactions": txs, "state_root": root}
	for {
		hash, err := v2BlockHash(block, ids)
		if err != nil {
			t.Fatal(err)
		}
		if v2MeetsDifficulty(hash, v2TestDifficulty) && (requireLess == "" || hash < requireLess) {
			block["block_hash"] = hash
			return block
		}
		block["nonce"] = block["nonce"].(int64) + 1
	}
}

func v2MineCandidate(t *testing.T, block map[string]any, transactions []any) map[string]any {
	t.Helper()
	block["transactions"] = transactions
	ids := make([]string, 0, len(transactions))
	for _, raw := range transactions {
		ids = append(ids, raw.(map[string]any)["tx_id"].(string))
	}
	block["nonce"] = int64(0)
	for {
		hash, err := v2BlockHash(block, ids)
		if err != nil {
			t.Fatal(err)
		}
		if v2MeetsDifficulty(hash, v2TestDifficulty) {
			block["block_hash"] = hash
			return block
		}
		block["nonce"] = block["nonce"].(int64) + 1
	}
}

func TestV2ConsensusAcceptsSignedTransferAndBurnsFee(t *testing.T) {
	node, genesis := v2TestNode(t)
	coin := node.State()[0]
	tx := v2TestTransfer(t, coin.TxID, 990, 10)
	block := v2TestBlock(t, node, genesis, []any{tx}, 1, "")
	accepted, err := node.AcceptBlock(block)
	if err != nil || !accepted {
		t.Fatalf("accept block: accepted=%t err=%v", accepted, err)
	}
	if node.TipHash() != block["block_hash"] || node.TipWork() != 1<<v2TestDifficulty {
		t.Fatal("canonical tip/work mismatch")
	}
	state := node.State()
	if len(state) != 1 || state[0].Recipient != "qbc1bob" || state[0].Amount != 990 {
		t.Fatalf("unexpected state: %+v", state)
	}
}

func TestV2ConsensusRejectsBadSignatureAndValueWithoutChangingTip(t *testing.T) {
	node, genesis := v2TestNode(t)
	coin := node.State()[0]
	badSig := v2TestTransfer(t, coin.TxID, 990, 10)
	badSig["inputs"].([]any)[0].(map[string]any)["signature"] = strings.Repeat("0", 64)
	idPreimage := cloneV2Map(badSig)
	delete(idPreimage, "tx_id")
	badID, _ := HashCanonicalV1("transaction-v2", idPreimage)
	badSig["tx_id"] = badID
	block := v2MineCandidate(t, v2TestBlock(t, node, genesis, nil, 1, ""), []any{badSig})
	before := node.TipHash()
	if _, err := node.AcceptBlock(block); err == nil || !strings.Contains(err.Error(), "signature") {
		t.Fatalf("expected signature rejection, got %v", err)
	}
	if node.TipHash() != before {
		t.Fatal("invalid block changed tip")
	}
	badValue := v2TestTransfer(t, coin.TxID, 999, 10)
	block = v2MineCandidate(t, v2TestBlock(t, node, genesis, nil, 1, ""), []any{badValue})
	if _, err := node.AcceptBlock(block); err == nil || !strings.Contains(err.Error(), "outputs plus burned fee") {
		t.Fatalf("expected value rejection, got %v", err)
	}
	if node.TipHash() != before {
		t.Fatal("invalid value block changed tip")
	}
}

func TestV2ConsensusReorganizationAndDeterministicTieBreak(t *testing.T) {
	node, genesis := v2TestNode(t)
	coin := node.State()[0]
	spend := v2TestTransfer(t, coin.TxID, 990, 10)
	branchA := v2TestBlock(t, node, genesis, []any{spend}, 1, "")
	if _, err := node.AcceptBlock(branchA); err != nil {
		t.Fatal(err)
	}
	branchB := v2TestBlock(t, node, genesis, nil, 1, branchA["block_hash"].(string))
	if _, err := node.AcceptBlock(branchB); err != nil {
		t.Fatal(err)
	}
	if node.TipHash() != branchB["block_hash"] || node.State()[0].Amount != v2TestSupply {
		t.Fatal("equal-work lower-hash tie-break failed")
	}
	branchB2 := v2TestBlock(t, node, branchB, nil, 1, "")
	if _, err := node.AcceptBlock(branchB2); err != nil {
		t.Fatal(err)
	}
	if node.TipHash() != branchB2["block_hash"] || node.State()[0].Amount != v2TestSupply {
		t.Fatal("longer-work reorganization failed")
	}
}

func TestV2ConsensusRejectsWrongChainIDAndStateRoot(t *testing.T) {
	node, genesis := v2TestNode(t)
	badChain := v2TestBlock(t, node, genesis, nil, 1, "")
	badChain["chain_id"] = "foreign"
	if _, err := node.AcceptBlock(badChain); err == nil || !strings.Contains(err.Error(), "chain_id") {
		t.Fatalf("expected chain ID rejection, got %v", err)
	}
	badRoot := v2TestBlock(t, node, genesis, nil, 1, "")
	badRoot["state_root"] = strings.Repeat("f", 64)
	if _, err := node.AcceptBlock(badRoot); err == nil || !strings.Contains(err.Error(), "state_root") {
		t.Fatalf("expected root rejection, got %v", err)
	}
}
