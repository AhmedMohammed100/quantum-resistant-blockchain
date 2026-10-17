package qbccjson

import (
	"bytes"
	"strings"
	"testing"
)

func TestVersionedTransactionSchemaVector(t *testing.T) {
	txID := strings.Repeat("a", 64)
	value := map[string]any{
		"version": int64(2), "chain_id": "qr-chain-devnet", "kind": "transfer",
		"timestamp_us": int64(1700000000123456), "fee": int64(2),
		"inputs": []any{map[string]any{"prev_tx_id": txID, "output_index": int64(1)}},
		"outputs": []any{map[string]any{"recipient": "qbc1alice", "amount": int64(100)}},
		"metadata": map[string]any{}, "signature_scheme": "mldsa65",
	}
	want := []byte("{\"chain_id\":\"qr-chain-devnet\",\"fee\":2,\"inputs\":[{\"output_index\":1,\"prev_tx_id\":\"" + txID + "\"}],\"kind\":\"transfer\",\"metadata\":{},\"outputs\":[{\"amount\":100,\"recipient\":\"qbc1alice\"}],\"signature_scheme\":\"mldsa65\",\"timestamp_us\":1700000000123456,\"version\":2}")
	assertSchemaVector(t, "transaction-v2", value, want, "898a1b493358e23d7bce1bd4b9cb3f2b45471b8e48f048569a04d98a39e79398")
}

func TestVersionedBlockSchemaVector(t *testing.T) {
	value := map[string]any{
		"version": int64(2), "chain_id": "qr-chain-devnet", "height": int64(7),
		"previous_hash": strings.Repeat("b", 64), "timestamp_us": int64(1700000001123456),
		"difficulty": int64(2), "nonce": int64(9),
		"transactions": []any{map[string]any{"tx_id": strings.Repeat("d", 64)}},
		"state_root": strings.Repeat("c", 64),
	}
	want := []byte("{\"chain_id\":\"qr-chain-devnet\",\"difficulty\":2,\"height\":7,\"nonce\":9,\"previous_hash\":\"" + strings.Repeat("b", 64) + "\",\"state_root\":\"" + strings.Repeat("c", 64) + "\",\"timestamp_us\":1700000001123456,\"transactions\":[{\"tx_id\":\"" + strings.Repeat("d", 64) + "\"}],\"version\":2}")
	assertSchemaVector(t, "block-v2", value, want, "e265097b5b46d1ca8a55f3fddf04a2c3cee5657e80f614fbc0e95006f9112481")
}

func TestSignaturePreimageSchemaVector(t *testing.T) {
	txID := strings.Repeat("a", 64)
	transaction := map[string]any{
		"version": int64(2), "kind": "transfer", "fee": int64(2),
		"timestamp_us": int64(1700000000123456),
		"inputs": []any{map[string]any{"prev_tx_id": txID, "output_index": int64(1)}},
		"outputs": []any{map[string]any{"recipient": "qbc1alice", "amount": int64(100)}},
		"metadata": map[string]any{}, "signature_scheme": "mldsa65",
	}
	value := map[string]any{"version": int64(2), "chain_id": "qr-chain-devnet", "transaction": transaction}
	want := []byte("{\"chain_id\":\"qr-chain-devnet\",\"transaction\":{\"fee\":2,\"inputs\":[{\"output_index\":1,\"prev_tx_id\":\"" + txID + "\"}],\"kind\":\"transfer\",\"metadata\":{},\"outputs\":[{\"amount\":100,\"recipient\":\"qbc1alice\"}],\"signature_scheme\":\"mldsa65\",\"timestamp_us\":1700000000123456,\"version\":2},\"version\":2}")
	assertSchemaVector(t, "signature-preimage-v2", value, want, "b5f703c9ae8298cdf633254078bf82ef4b2c7b34fd8f78474d74afe70628aab9")
}

func TestStateRootSchemaVector(t *testing.T) {
	value := []any{
		map[string]any{"tx_id": strings.Repeat("a", 64), "output_index": int64(1), "recipient": "qbc1alice", "amount": int64(100)},
		map[string]any{"tx_id": strings.Repeat("b", 64), "output_index": int64(0), "recipient": "qbc1bob", "amount": int64(50)},
	}
	want := []byte("[{\"amount\":100,\"output_index\":1,\"recipient\":\"qbc1alice\",\"tx_id\":\"" + strings.Repeat("a", 64) + "\"},{\"amount\":50,\"output_index\":0,\"recipient\":\"qbc1bob\",\"tx_id\":\"" + strings.Repeat("b", 64) + "\"}]")
	assertSchemaVector(t, "state-root-v2", value, want, "14239324cd984646f8169f15ec490d4599b0d8ec4e6c1dac3635a1f8946d18d3")
}

func assertSchemaVector(t *testing.T, domain string, value any, wantBytes []byte, wantHash string) {
	t.Helper()
	gotBytes, err := CanonicalJSONV1(value)
	if err != nil { t.Fatal(err) }
	if !bytes.Equal(gotBytes, wantBytes) {
		t.Fatalf("%s canonical bytes mismatch:\n got %s\nwant %s", domain, gotBytes, wantBytes)
	}
	gotHash, err := HashCanonicalV1(domain, value)
	if err != nil { t.Fatal(err) }
	if gotHash != wantHash { t.Fatalf("%s hash mismatch: got %s want %s", domain, gotHash, wantHash) }
}
