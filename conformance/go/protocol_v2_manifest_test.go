package qbccjson

import (
	"errors"
	"strings"
	"testing"
)

var errFixtureProfile = errors.New("fixture profile rejected descriptor")

func manifestFixture() map[string]any {
	manifest := map[string]any{
		"manifest_version":           int64(1),
		"chain_id":                   "qbc-v2-fixture",
		"genesis_hash":               strings.Repeat("a", 64),
		"encoding_profile":           "qbc-cjson-v1",
		"transaction_schema_version": int64(2),
		"block_schema_version":       int64(2),
		"activation":                 map[string]any{"mode": "genesis"},
		"transaction_kinds":          []any{"transfer"},
		"signature_providers": []any{map[string]any{
			"provider_id": "fixture_pq_v1", "provider_version": "1.0.0",
			"signing_mode": "canonical-bytes", "public_key_schema": "fixture-key-v1",
			"signature_schema": "fixture-signature-v1", "max_public_key_bytes": int64(4096),
			"max_signature_bytes": int64(4096),
		}},
		"consensus_profile": map[string]any{
			"profile_id": "fixture-pow", "profile_version": "1",
			"parameters": map[string]any{"fixture": "consensus-parameters"},
		},
		"limits": map[string]any{
			"max_transaction_bytes": int64(1 << 20), "max_block_bytes": int64(4 << 20),
			"max_metadata_bytes": int64(16 << 10), "max_inputs": int64(256),
			"max_outputs": int64(256), "max_transactions_per_block": int64(4096),
		},
	}
	refreshManifestDigest(manifest)
	return manifest
}

func manifestProfiles() (
	map[string]bool,
	map[V2ManifestProfileKey]V2ManifestDescriptorValidator,
	map[V2ManifestProfileKey]V2ManifestDescriptorValidator,
) {
	return map[string]bool{"transfer": true},
		map[V2ManifestProfileKey]V2ManifestDescriptorValidator{
			{ID: "fixture_pq_v1", Version: "1.0.0"}: func(map[string]any) error { return nil },
		},
		map[V2ManifestProfileKey]V2ManifestDescriptorValidator{
			{ID: "fixture-pow", Version: "1"}: func(map[string]any) error { return nil },
		}
}

func validateManifestFixture(manifest any) (string, error) {
	kinds, providers, consensus := manifestProfiles()
	return ValidateV2NetworkManifest(manifest, "qbc-v2-fixture", strings.Repeat("a", 64), kinds, providers, consensus)
}

func refreshManifestDigest(manifest map[string]any) {
	delete(manifest, "manifest_digest")
	digest, err := HashCanonicalV1("network-manifest-v2", manifest)
	if err != nil {
		panic(err)
	}
	manifest["manifest_digest"] = digest
}

func requireManifestError(t *testing.T, manifest any, expected string) {
	t.Helper()
	_, err := validateManifestFixture(manifest)
	if err == nil || !strings.Contains(err.Error(), expected) {
		t.Fatalf("expected error containing %q, got %v", expected, err)
	}
}

func TestV2NetworkManifestAcceptsPublishedFixture(t *testing.T) {
	manifest := manifestFixture()
	digest, err := validateManifestFixture(manifest)
	if err != nil {
		t.Fatal(err)
	}
	if digest != "dcaee8df5e114551a305bf44b2a6ee21f53f439faca7f0f05502a3955311649c" {
		t.Fatalf("manifest digest mismatch: got %s", digest)
	}
}

func TestV2NetworkManifestAcceptsProviderDigestDescriptor(t *testing.T) {
	manifest := manifestFixture()
	provider := manifest["signature_providers"].([]any)[0].(map[string]any)
	provider["signing_mode"] = "provider-digest"
	provider["signing_domain"] = "transaction-v2"
	refreshManifestDigest(manifest)
	if _, err := validateManifestFixture(manifest); err != nil {
		t.Fatal(err)
	}
}

func TestV2NetworkManifestRejectsUnknownMissingAndWrongVersionFields(t *testing.T) {
	manifest := manifestFixture()
	manifest["unexpected"] = "no extras"
	refreshManifestDigest(manifest)
	requireManifestError(t, manifest, "fields mismatch")

	manifest = manifestFixture()
	delete(manifest, "genesis_hash")
	refreshManifestDigest(manifest)
	requireManifestError(t, manifest, "fields mismatch")

	manifest = manifestFixture()
	manifest["transaction_schema_version"] = true
	refreshManifestDigest(manifest)
	requireManifestError(t, manifest, "transaction_schema_version must be integer 2")
}

func TestV2NetworkManifestRejectsConfiguredNetworkMismatch(t *testing.T) {
	manifest := manifestFixture()
	kinds, providers, consensus := manifestProfiles()
	if _, err := ValidateV2NetworkManifest(manifest, "other-network", strings.Repeat("a", 64), kinds, providers, consensus); err == nil || !strings.Contains(err.Error(), "chain_id") {
		t.Fatalf("expected chain ID mismatch, got %v", err)
	}
	if _, err := ValidateV2NetworkManifest(manifest, "qbc-v2-fixture", strings.Repeat("b", 64), kinds, providers, consensus); err == nil || !strings.Contains(err.Error(), "genesis_hash") {
		t.Fatalf("expected genesis mismatch, got %v", err)
	}
}

func TestV2NetworkManifestRejectsInvalidActivationAndKinds(t *testing.T) {
	manifest := manifestFixture()
	manifest["activation"] = map[string]any{"mode": "height"}
	refreshManifestDigest(manifest)
	requireManifestError(t, manifest, "must activate at genesis")

	manifest = manifestFixture()
	manifest["transaction_kinds"] = []any{"reward", "transfer"}
	refreshManifestDigest(manifest)
	requireManifestError(t, manifest, "has no local schema")

	manifest = manifestFixture()
	manifest["transaction_kinds"] = []any{"transfer", "transfer"}
	refreshManifestDigest(manifest)
	requireManifestError(t, manifest, "sorted and unique")
}

func TestV2NetworkManifestRejectsProviderAndConsensusProfileMismatches(t *testing.T) {
	manifest := manifestFixture()
	kinds, _, consensus := manifestProfiles()
	if _, err := ValidateV2NetworkManifest(manifest, "qbc-v2-fixture", strings.Repeat("a", 64), kinds, nil, consensus); err == nil || !strings.Contains(err.Error(), "provider profile") {
		t.Fatalf("expected unknown provider rejection, got %v", err)
	}

	manifest = manifestFixture()
	kinds, providers, _ := manifestProfiles()
	if _, err := ValidateV2NetworkManifest(manifest, "qbc-v2-fixture", strings.Repeat("a", 64), kinds, providers, nil); err == nil || !strings.Contains(err.Error(), "consensus profile") {
		t.Fatalf("expected unknown consensus profile rejection, got %v", err)
	}

	manifest = manifestFixture()
	providers[V2ManifestProfileKey{ID: "fixture_pq_v1", Version: "1.0.0"}] = func(map[string]any) error { return errFixtureProfile }
	if _, err := ValidateV2NetworkManifest(manifest, "qbc-v2-fixture", strings.Repeat("a", 64), kinds, providers, consensus); err == nil || !strings.Contains(err.Error(), "rejected descriptor") {
		t.Fatalf("expected provider callback rejection, got %v", err)
	}
}

func TestV2NetworkManifestRejectsMalformedProviderAndLimits(t *testing.T) {
	manifest := manifestFixture()
	providers := manifest["signature_providers"].([]any)
	provider := providers[0].(map[string]any)
	provider["signing_domain"] = "unexpected"
	refreshManifestDigest(manifest)
	requireManifestError(t, manifest, "fields mismatch")

	manifest = manifestFixture()
	manifest["limits"].(map[string]any)["max_block_bytes"] = int64((4 << 20) + 1)
	refreshManifestDigest(manifest)
	requireManifestError(t, manifest, "normative v2 ceiling")

	manifest = manifestFixture()
	manifest["limits"].(map[string]any)["max_transaction_bytes"] = int64(8 << 10)
	manifest["limits"].(map[string]any)["max_metadata_bytes"] = int64(16 << 10)
	refreshManifestDigest(manifest)
	requireManifestError(t, manifest, "max_metadata_bytes cannot exceed")

	manifest = manifestFixture()
	manifest["signature_providers"].([]any)[0].(map[string]any)["max_signature_bytes"] = int64(1<<20 + 1)
	refreshManifestDigest(manifest)
	requireManifestError(t, manifest, "max_signature_bytes cannot exceed")
}

func TestV2NetworkManifestRejectsInvalidDigest(t *testing.T) {
	manifest := manifestFixture()
	manifest["manifest_digest"] = strings.Repeat("0", 64)
	requireManifestError(t, manifest, "manifest_digest does not match")
}

func TestV2NetworkManifestProfileValidatorsReceiveCopies(t *testing.T) {
	manifest := manifestFixture()
	profile := manifest["consensus_profile"].(map[string]any)["parameters"].(map[string]any)
	kinds, providers, consensus := manifestProfiles()
	consensus[V2ManifestProfileKey{ID: "fixture-pow", Version: "1"}] = func(parameters map[string]any) error {
		parameters["mutated"] = true
		return nil
	}
	if _, err := ValidateV2NetworkManifest(manifest, "qbc-v2-fixture", strings.Repeat("a", 64), kinds, providers, consensus); err != nil {
		t.Fatal(err)
	}
	if _, exists := profile["mutated"]; exists {
		t.Fatal("consensus profile callback mutated the input manifest")
	}
}
