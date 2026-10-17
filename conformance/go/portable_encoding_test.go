package qbccjson

import (
	"bytes"
	"testing"
)

func TestPublishedVectorA(t *testing.T) {
	value := map[string]any{
		"z": int64(0),
		"a": "é\n",
		"n": int64(-12),
		"b": true,
	}
	want := []byte("{\"a\":\"é\\u000a\",\"b\":true,\"n\":-12,\"z\":0}")
	got, err := CanonicalJSONV1(value)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("canonical bytes mismatch:\n got %s\nwant %s", got, want)
	}
	hash, err := HashCanonicalV1("test-vector", value)
	if err != nil {
		t.Fatal(err)
	}
	const wantHash = "80895643fef93bf20130c21775db0765051092bdc393f17d8627a3e615b2a0a2"
	if hash != wantHash {
		t.Fatalf("hash mismatch: got %s want %s", hash, wantHash)
	}
}

func TestPublishedVectorB(t *testing.T) {
	value := map[string]any{
		"timestamp_us": int64(1700000000123456),
		"chain_id": "qr-chain-devnet",
		"ok": true,
	}
	want := []byte("{\"chain_id\":\"qr-chain-devnet\",\"ok\":true,\"timestamp_us\":1700000000123456}")
	got, err := CanonicalJSONV1(value)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("canonical bytes mismatch:\n got %s\nwant %s", got, want)
	}
	hash, err := HashCanonicalV1("test-vector", value)
	if err != nil {
		t.Fatal(err)
	}
	const wantHash = "cdec297e501cac92be6bfeaae2439cfb694e7dd2dcae9f63ca2df866b9923a3c"
	if hash != wantHash {
		t.Fatalf("hash mismatch: got %s want %s", hash, wantHash)
	}
}

func TestPublishedVectorC(t *testing.T) {
	got, err := CanonicalJSONV1(map[string]any{})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, []byte("{}")) {
		t.Fatalf("canonical bytes mismatch: got %q", got)
	}
	// Vector C intentionally hashes the canonical bytes alone, without a domain.
	const wantHash = "44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a"
	if gotHash := sha256Hex(got); gotHash != wantHash {
		t.Fatalf("SHA-256 mismatch: got %s want %s", gotHash, wantHash)
	}
}

func TestInsertionOrderDoesNotMatter(t *testing.T) {
	a := map[string]any{"z": []any{int64(1), nil, false}, "a": map[string]any{"β": int64(2), "a": int64(1)}}
	b := map[string]any{"a": map[string]any{"a": int64(1), "β": int64(2)}, "z": []any{int64(1), nil, false}}
	ab, err := CanonicalJSONV1(a)
	if err != nil { t.Fatal(err) }
	bb, err := CanonicalJSONV1(b)
	if err != nil { t.Fatal(err) }
	if !bytes.Equal(ab, bb) { t.Fatalf("insertion order changed encoding: %q != %q", ab, bb) }
	ah, err := HashCanonicalV1("fixture", a)
	if err != nil { t.Fatal(err) }
	bh, err := HashCanonicalV1("fixture", b)
	if err != nil { t.Fatal(err) }
	if ah != bh { t.Fatalf("insertion order changed hash: %s != %s", ah, bh) }
}

func TestRejectsInvalidInputs(t *testing.T) {
	for _, value := range []any{float64(1), uint64(1), []byte("bytes"), map[any]any{"x": int64(1)}} {
		if _, err := CanonicalJSONV1(value); err == nil {
			t.Errorf("expected unsupported input rejection for %T", value)
		}
	}
	if _, err := HashCanonicalV1("Upper", map[string]any{}); err == nil {
		t.Error("expected invalid domain rejection")
	}
	if _, err := ParseCanonicalJSONV1([]byte("{\"a\":1,\"a\":2}")); err == nil {
		t.Error("expected duplicate key rejection")
	}
	for _, raw := range [][]byte{
		[]byte("{ \"a\":1}"),
		[]byte("{\"b\":1,\"a\":2}"),
		[]byte("{\"a\":1.0}"),
		[]byte("{\"a\":\"\\n\"}"),
		[]byte("\"\\ud800\""),
		{0xff},
	} {
		if _, err := ParseCanonicalJSONV1(raw); err == nil {
			t.Errorf("expected noncanonical/invalid JSON rejection: %q", raw)
		}
	}
}
