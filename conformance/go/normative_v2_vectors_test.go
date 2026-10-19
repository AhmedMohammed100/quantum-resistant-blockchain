package qbccjson

import (
	"bytes"
	"strings"
	"testing"
)

func TestNormativeV2HTransactionIDPreimage(t *testing.T) {
	txID := strings.Repeat("a", 64)
	value := map[string]any{
		"version": int64(2), "chain_id": "qr-chain-devnet", "kind": "transfer",
		"timestamp_us": int64(1700000000123456), "fee": int64(2),
		"inputs": []any{map[string]any{
			"prev_tx_id": txID, "output_index": int64(1),
			"public_key": map[string]any{"fixture": "pk-alice"},
			"signature": map[string]any{"fixture": "sig-alice"},
		}},
		"outputs": []any{map[string]any{"recipient": "qbc1alice", "amount": int64(100)}},
		"metadata": map[string]any{}, "signature_scheme": "mldsa65",
	}
	want := []byte("{\"chain_id\":\"qr-chain-devnet\",\"fee\":2,\"inputs\":[{\"output_index\":1,\"prev_tx_id\":\"" + txID + "\",\"public_key\":{\"fixture\":\"pk-alice\"},\"signature\":{\"fixture\":\"sig-alice\"}}],\"kind\":\"transfer\",\"metadata\":{},\"outputs\":[{\"amount\":100,\"recipient\":\"qbc1alice\"}],\"signature_scheme\":\"mldsa65\",\"timestamp_us\":1700000000123456,\"version\":2}")
	assertNormativeV2Vector(t, "transaction-v2", value, want, "01f8a81008a8bde0e793b5e5ca8c569e9c95ffe31fdd473283752f218201a5d0")
}

func TestNormativeV2IVFlatSignaturePreimage(t *testing.T) {
	txID := strings.Repeat("a", 64)
	value := map[string]any{
		"version": int64(2), "chain_id": "qr-chain-devnet", "kind": "transfer",
		"timestamp_us": int64(1700000000123456), "fee": int64(2),
		"inputs": []any{map[string]any{"prev_tx_id": txID, "output_index": int64(1)}},
		"outputs": []any{map[string]any{"recipient": "qbc1alice", "amount": int64(100)}},
		"metadata": map[string]any{}, "signature_scheme": "mldsa65",
	}
	want := []byte("{\"chain_id\":\"qr-chain-devnet\",\"fee\":2,\"inputs\":[{\"output_index\":1,\"prev_tx_id\":\"" + txID + "\"}],\"kind\":\"transfer\",\"metadata\":{},\"outputs\":[{\"amount\":100,\"recipient\":\"qbc1alice\"}],\"signature_scheme\":\"mldsa65\",\"timestamp_us\":1700000000123456,\"version\":2}")
	assertNormativeV2Vector(t, "signature-preimage-v2", value, want, "b0bea7b13223c0d6bd1ba90e9908ccf6dbb8394827df2bc68a80d3447c56d3f1")
}

func TestNormativeV2JStateRootPreimage(t *testing.T) {
	value := []any{
		map[string]any{"tx_id": strings.Repeat("a", 64), "output_index": int64(1), "recipient": "qbc1alice", "amount": int64(100)},
		map[string]any{"tx_id": strings.Repeat("b", 64), "output_index": int64(0), "recipient": "qbc1bob", "amount": int64(50)},
	}
	want := []byte("[{\"amount\":100,\"output_index\":1,\"recipient\":\"qbc1alice\",\"tx_id\":\"" + strings.Repeat("a", 64) + "\"},{\"amount\":50,\"output_index\":0,\"recipient\":\"qbc1bob\",\"tx_id\":\"" + strings.Repeat("b", 64) + "\"}]")
	assertNormativeV2Vector(t, "state-root-v2", value, want, "14239324cd984646f8169f15ec490d4599b0d8ec4e6c1dac3635a1f8946d18d3")
}

func TestNormativeV2KBlockHashPreimage(t *testing.T) {
	value := map[string]any{
		"version": int64(2), "chain_id": "qr-chain-devnet", "height": int64(7),
		"previous_hash": strings.Repeat("b", 64), "timestamp_us": int64(1700000001123456),
		"difficulty": int64(2), "nonce": int64(9), "miner": "qbc1miner",
		"transactions": []any{"01f8a81008a8bde0e793b5e5ca8c569e9c95ffe31fdd473283752f218201a5d0"},
		"state_root": "14239324cd984646f8169f15ec490d4599b0d8ec4e6c1dac3635a1f8946d18d3",
	}
	want := []byte("{\"chain_id\":\"qr-chain-devnet\",\"difficulty\":2,\"height\":7,\"miner\":\"qbc1miner\",\"nonce\":9,\"previous_hash\":\"" + strings.Repeat("b", 64) + "\",\"state_root\":\"14239324cd984646f8169f15ec490d4599b0d8ec4e6c1dac3635a1f8946d18d3\",\"timestamp_us\":1700000001123456,\"transactions\":[\"01f8a81008a8bde0e793b5e5ca8c569e9c95ffe31fdd473283752f218201a5d0\"],\"version\":2}")
	assertNormativeV2Vector(t, "block-v2", value, want, "8409f50017640fea77542ad9bfffe42a173b9d740f6381ab805c4f485d810ac4")
}

func assertNormativeV2Vector(t *testing.T, domain string, value any, wantBytes []byte, wantHash string) {
	t.Helper()
	gotBytes, err := CanonicalJSONV1(value)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(gotBytes, wantBytes) {
		t.Fatalf("%s canonical bytes mismatch:\n got %s\nwant %s", domain, gotBytes, wantBytes)
	}
	gotHash, err := HashCanonicalV1(domain, value)
	if err != nil {
		t.Fatal(err)
	}
	if gotHash != wantHash {
		t.Fatalf("%s hash mismatch: got %s want %s", domain, gotHash, wantHash)
	}
}
