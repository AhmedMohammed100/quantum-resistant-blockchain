// qbc-mldsa-crosscheck exchanges raw FIPS 204 ML-DSA-65 keys and signatures
// with QBC's liboqs adapter. It is a conformance-test helper, not a signer for
// production use. Cloudflare CIRCL v1.6.0 is pinned in this module.
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
)

type request struct {
	Operation     string `json:"operation"`
	MessageHex    string `json:"message_hex"`
	PublicKeyHex  string `json:"public_key_hex"`
	SignatureHex  string `json:"signature_hex"`
}

type response struct {
	Implementation string `json:"implementation"`
	Valid          bool   `json:"valid"`
	PublicKeyHex   string `json:"public_key_hex,omitempty"`
	SignatureHex   string `json:"signature_hex,omitempty"`
}

const implementation = "cloudflare/circl/sign/mldsa/mldsa65@v1.6.0"

func decodeHex(value string) ([]byte, error) {
	return hex.DecodeString(value)
}

func run(req request) (response, error) {
	switch req.Operation {
	case "verify":
		message, err := decodeHex(req.MessageHex)
		if err != nil {
			return response{}, fmt.Errorf("decode message: %w", err)
		}
		publicKeyBytes, err := decodeHex(req.PublicKeyHex)
		if err != nil {
			return response{Implementation: implementation}, nil
		}
		signature, err := decodeHex(req.SignatureHex)
		if err != nil || len(publicKeyBytes) != mldsa65.PublicKeySize || len(signature) != mldsa65.SignatureSize {
			return response{Implementation: implementation}, nil
		}
		var publicKey mldsa65.PublicKey
		if err := publicKey.UnmarshalBinary(publicKeyBytes); err != nil {
			return response{Implementation: implementation}, nil
		}
		return response{
			Implementation: implementation,
			Valid:          mldsa65.Verify(&publicKey, message, nil, signature),
		}, nil

	case "sign":
		message, err := decodeHex(req.MessageHex)
		if err != nil {
			return response{}, fmt.Errorf("decode message: %w", err)
		}
		// Fixed test-only seed makes the independent implementation repeatable.
		seedDigest := sha256.Sum256([]byte("QBC CIRCL ML-DSA-65 interop test key v1"))
		var seed [mldsa65.SeedSize]byte
		copy(seed[:], seedDigest[:])
		publicKey, privateKey := mldsa65.NewKeyFromSeed(&seed)
		signature := make([]byte, mldsa65.SignatureSize)
		if err := mldsa65.SignTo(privateKey, message, nil, false, signature); err != nil {
			return response{}, fmt.Errorf("sign with CIRCL: %w", err)
		}
		return response{
			Implementation: implementation,
			Valid:           mldsa65.Verify(publicKey, message, nil, signature),
			PublicKeyHex:    hex.EncodeToString(publicKey.Bytes()),
			SignatureHex:    hex.EncodeToString(signature),
		}, nil

	default:
		return response{}, errors.New("operation must be sign or verify")
	}
}

func main() {
	decoder := json.NewDecoder(io.LimitReader(os.Stdin, 2<<20))
	decoder.DisallowUnknownFields()
	var req request
	if err := decoder.Decode(&req); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	result, err := run(req)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	if err := json.NewEncoder(os.Stdout).Encode(result); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
}
