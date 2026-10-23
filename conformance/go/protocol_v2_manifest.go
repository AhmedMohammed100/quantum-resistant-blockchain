package qbccjson

import (
	"fmt"
	"regexp"
	"sort"
)

// V2ManifestProfileKey identifies an exact locally supported profile release.
type V2ManifestProfileKey struct {
	ID      string
	Version string
}

// V2ManifestDescriptorValidator validates the profile-specific meaning of a
// manifest descriptor. The validator receives a defensive copy.
type V2ManifestDescriptorValidator func(map[string]any) error

var (
	v2ManifestTokenPattern    = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,63}$`)
	v2ManifestProviderPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9_.-]{0,63}$`)
	v2ManifestVersionPattern  = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9.+_-]{0,63}$`)
	v2ManifestDigestPattern   = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

var (
	v2ManifestFields = keySet(
		"manifest_version", "chain_id", "genesis_hash", "encoding_profile",
		"transaction_schema_version", "block_schema_version", "activation",
		"transaction_kinds", "signature_providers", "consensus_profile", "limits",
		"manifest_digest",
	)
	v2LimitFields = keySet(
		"max_transaction_bytes", "max_block_bytes", "max_metadata_bytes",
		"max_inputs", "max_outputs", "max_transactions_per_block",
	)
	v2ProviderFields = keySet(
		"provider_id", "provider_version", "signing_mode", "public_key_schema",
		"signature_schema", "max_public_key_bytes", "max_signature_bytes",
	)
)

// ValidateV2NetworkManifest implements the opt-in candidate manifest checks
// independently of the Python implementation. It validates the shared
// structural rules and requires exact local provider/consensus profile entries.
// It does not activate a network or select consensus rules.
func ValidateV2NetworkManifest(
	manifest any,
	expectedChainID string,
	expectedGenesisHash string,
	supportedKinds map[string]bool,
	providerProfiles map[V2ManifestProfileKey]V2ManifestDescriptorValidator,
	consensusProfiles map[V2ManifestProfileKey]V2ManifestDescriptorValidator,
) (string, error) {
	value, err := exactObject(manifest, v2ManifestFields, "network manifest")
	if err != nil {
		return "", err
	}
	if err := exactVersion(value["manifest_version"], 1, "manifest_version"); err != nil {
		return "", err
	}
	if err := exactVersion(value["transaction_schema_version"], 2, "transaction_schema_version"); err != nil {
		return "", err
	}
	if err := exactVersion(value["block_schema_version"], 2, "block_schema_version"); err != nil {
		return "", err
	}
	chainID, err := boundedString(value["chain_id"], "chain_id", 64, true)
	if err != nil {
		return "", err
	}
	if chainID != expectedChainID {
		return "", fmt.Errorf("manifest chain_id does not match configured network")
	}
	genesisHash, err := digestString(value["genesis_hash"], "genesis_hash")
	if err != nil {
		return "", err
	}
	if genesisHash != expectedGenesisHash {
		return "", fmt.Errorf("manifest genesis_hash does not match configured network")
	}
	if value["encoding_profile"] != "qbc-cjson-v1" {
		return "", fmt.Errorf("encoding_profile must be qbc-cjson-v1")
	}
	activation, err := exactObject(value["activation"], keySet("mode"), "activation")
	if err != nil {
		return "", err
	}
	if activation["mode"] != "genesis" {
		return "", fmt.Errorf("the v2 test-network manifest must activate at genesis")
	}

	kinds, ok := value["transaction_kinds"].([]any)
	if !ok || len(kinds) == 0 {
		return "", fmt.Errorf("transaction_kinds must be a non-empty array")
	}
	kindNames := make([]string, 0, len(kinds))
	for _, item := range kinds {
		kind, err := boundedString(item, "transaction kind", 64, true)
		if err != nil {
			return "", err
		}
		if !v2ManifestTokenPattern.MatchString(kind) {
			return "", fmt.Errorf("transaction kind must be a lowercase token")
		}
		if !supportedKinds[kind] {
			return "", fmt.Errorf("transaction kind %q has no local schema", kind)
		}
		kindNames = append(kindNames, kind)
	}
	if !sortedUnique(kindNames) {
		return "", fmt.Errorf("transaction_kinds must be sorted and unique")
	}
	if !contains(kindNames, "transfer") {
		return "", fmt.Errorf("transaction_kinds must include transfer")
	}

	providers, ok := value["signature_providers"].([]any)
	if !ok || len(providers) == 0 {
		return "", fmt.Errorf("signature_providers must be a non-empty array")
	}
	providerIDs := make([]string, 0, len(providers))
	providerEntries := make([]map[string]any, 0, len(providers))
	for _, item := range providers {
		entry, ok := item.(map[string]any)
		if !ok {
			return "", fmt.Errorf("signature provider descriptor must be an object")
		}
		fields := cloneKeySet(v2ProviderFields)
		if entry["signing_mode"] == "provider-digest" {
			fields["signing_domain"] = true
		}
		entry, err = exactObject(entry, fields, "signature provider descriptor")
		if err != nil {
			return "", err
		}
		providerID, err := boundedString(entry["provider_id"], "provider_id", 64, true)
		if err != nil {
			return "", err
		}
		providerVersion, err := boundedString(entry["provider_version"], "provider_version", 64, true)
		if err != nil {
			return "", err
		}
		if !v2ManifestProviderPattern.MatchString(providerID) {
			return "", fmt.Errorf("provider_id must be a lowercase ASCII identifier")
		}
		if !v2ManifestVersionPattern.MatchString(providerVersion) {
			return "", fmt.Errorf("provider_version must be an exact version token")
		}
		mode, ok := entry["signing_mode"].(string)
		if !ok || (mode != "canonical-bytes" && mode != "provider-digest") {
			return "", fmt.Errorf("signing_mode must be canonical-bytes or provider-digest")
		}
		if mode == "provider-digest" {
			domain, err := boundedString(entry["signing_domain"], "signing_domain", 64, true)
			if err != nil {
				return "", err
			}
			if !v2ManifestTokenPattern.MatchString(domain) {
				return "", fmt.Errorf("signing_domain must be a lowercase token")
			}
		}
		for _, field := range []string{"public_key_schema", "signature_schema"} {
			schema, err := boundedString(entry[field], field, 64, true)
			if err != nil {
				return "", err
			}
			if !v2ManifestTokenPattern.MatchString(schema) {
				return "", fmt.Errorf("%s must be a lowercase token", field)
			}
		}
		publicKeyBytes, err := positiveInt(entry["max_public_key_bytes"], "max_public_key_bytes")
		if err != nil {
			return "", err
		}
		signatureBytes, err := positiveInt(entry["max_signature_bytes"], "max_signature_bytes")
		if err != nil {
			return "", err
		}
		key := V2ManifestProfileKey{ID: providerID, Version: providerVersion}
		validator, exists := providerProfiles[key]
		if !exists || validator == nil {
			return "", fmt.Errorf("signature provider profile %q@%q is not supported locally", providerID, providerVersion)
		}
		if err := validator(cloneObject(entry)); err != nil {
			return "", fmt.Errorf("signature provider profile %q@%q rejected descriptor: %w", providerID, providerVersion, err)
		}
		entry["max_public_key_bytes"] = publicKeyBytes
		entry["max_signature_bytes"] = signatureBytes
		providerIDs = append(providerIDs, providerID)
		providerEntries = append(providerEntries, entry)
	}
	if !sortedUnique(providerIDs) {
		return "", fmt.Errorf("signature_providers must be sorted by provider_id and unique")
	}

	profile, err := exactObject(value["consensus_profile"], keySet("profile_id", "profile_version", "parameters"), "consensus_profile")
	if err != nil {
		return "", err
	}
	profileID, err := boundedString(profile["profile_id"], "consensus profile ID", 64, true)
	if err != nil {
		return "", err
	}
	profileVersion, err := boundedString(profile["profile_version"], "consensus profile version", 64, true)
	if err != nil {
		return "", err
	}
	if !v2ManifestTokenPattern.MatchString(profileID) || !v2ManifestVersionPattern.MatchString(profileVersion) {
		return "", fmt.Errorf("consensus profile ID/version is malformed")
	}
	parameters, ok := profile["parameters"].(map[string]any)
	if !ok {
		return "", fmt.Errorf("consensus profile parameters must be an object")
	}
	profileKey := V2ManifestProfileKey{ID: profileID, Version: profileVersion}
	profileValidator, exists := consensusProfiles[profileKey]
	if !exists || profileValidator == nil {
		return "", fmt.Errorf("consensus profile %q@%q is not supported locally", profileID, profileVersion)
	}
	if err := profileValidator(cloneObject(parameters)); err != nil {
		return "", fmt.Errorf("consensus profile %q@%q rejected parameters: %w", profileID, profileVersion, err)
	}

	limits, err := exactObject(value["limits"], v2LimitFields, "v2 schema limits")
	if err != nil {
		return "", err
	}
	ceilings := map[string]int64{
		"max_transaction_bytes":      1 << 20,
		"max_block_bytes":            4 << 20,
		"max_metadata_bytes":         16 << 10,
		"max_inputs":                 256,
		"max_outputs":                256,
		"max_transactions_per_block": 4096,
	}
	limitValues := make(map[string]int64, len(ceilings))
	for name, ceiling := range ceilings {
		limit, err := positiveInt(limits[name], name)
		if err != nil {
			return "", err
		}
		if limit > ceiling {
			return "", fmt.Errorf("%s exceeds the normative v2 ceiling %d", name, ceiling)
		}
		limitValues[name] = limit
	}
	if limitValues["max_metadata_bytes"] > limitValues["max_transaction_bytes"] {
		return "", fmt.Errorf("max_metadata_bytes cannot exceed max_transaction_bytes")
	}
	if limitValues["max_transaction_bytes"] > limitValues["max_block_bytes"] {
		return "", fmt.Errorf("max_transaction_bytes cannot exceed max_block_bytes")
	}
	for _, entry := range providerEntries {
		if entry["max_public_key_bytes"].(int64) > limitValues["max_transaction_bytes"] {
			return "", fmt.Errorf("max_public_key_bytes cannot exceed max_transaction_bytes")
		}
		if entry["max_signature_bytes"].(int64) > limitValues["max_transaction_bytes"] {
			return "", fmt.Errorf("max_signature_bytes cannot exceed max_transaction_bytes")
		}
	}

	manifestDigest, err := digestString(value["manifest_digest"], "manifest_digest")
	if err != nil {
		return "", err
	}
	body := cloneObject(value)
	delete(body, "manifest_digest")
	computed, err := HashCanonicalV1("network-manifest-v2", body)
	if err != nil {
		return "", fmt.Errorf("manifest is not qbc-cjson-v1 encodable: %w", err)
	}
	if manifestDigest != computed {
		return "", fmt.Errorf("manifest_digest does not match canonical manifest")
	}
	return computed, nil
}

func exactObject(value any, fields map[string]bool, name string) (map[string]any, error) {
	object, ok := value.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("%s must be an object", name)
	}
	missing := make([]string, 0)
	unknown := make([]string, 0)
	for field := range fields {
		if _, exists := object[field]; !exists {
			missing = append(missing, field)
		}
	}
	for field := range object {
		if !fields[field] {
			unknown = append(unknown, field)
		}
	}
	if len(missing) > 0 || len(unknown) > 0 {
		sort.Strings(missing)
		sort.Strings(unknown)
		return nil, fmt.Errorf("%s fields mismatch (missing=%v, unknown=%v)", name, missing, unknown)
	}
	return object, nil
}

func keySet(keys ...string) map[string]bool {
	set := make(map[string]bool, len(keys))
	for _, key := range keys {
		set[key] = true
	}
	return set
}

func cloneKeySet(source map[string]bool) map[string]bool {
	result := make(map[string]bool, len(source))
	for key, value := range source {
		result[key] = value
	}
	return result
}

func exactVersion(value any, want int64, name string) error {
	got, ok := integerValue(value)
	if !ok || got != want {
		return fmt.Errorf("%s must be integer %d", name, want)
	}
	return nil
}

func integerValue(value any) (int64, bool) {
	switch number := value.(type) {
	case int:
		return int64(number), true
	case int8:
		return int64(number), true
	case int16:
		return int64(number), true
	case int32:
		return int64(number), true
	case int64:
		return number, true
	default:
		return 0, false
	}
}

func positiveInt(value any, name string) (int64, error) {
	number, ok := integerValue(value)
	if !ok || number < 1 {
		return 0, fmt.Errorf("%s must be an integer of at least 1", name)
	}
	return number, nil
}

func boundedString(value any, name string, maximumBytes int, asciiOnly bool) (string, error) {
	text, ok := value.(string)
	if !ok || text == "" {
		return "", fmt.Errorf("%s must be a non-empty string", name)
	}
	if len(text) > maximumBytes {
		return "", fmt.Errorf("%s exceeds %d UTF-8 bytes", name, maximumBytes)
	}
	if asciiOnly {
		for index := 0; index < len(text); index++ {
			if text[index] >= 0x80 {
				return "", fmt.Errorf("%s must contain ASCII only", name)
			}
		}
	}
	return text, nil
}

func digestString(value any, name string) (string, error) {
	text, ok := value.(string)
	if !ok || !v2ManifestDigestPattern.MatchString(text) {
		return "", fmt.Errorf("%s must be 64 lowercase hexadecimal characters", name)
	}
	return text, nil
}

func sortedUnique(values []string) bool {
	for index, value := range values {
		if index > 0 && values[index-1] >= value {
			return false
		}
	}
	return true
}

func contains(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}

func cloneObject(source map[string]any) map[string]any {
	cloned := make(map[string]any, len(source))
	for key, value := range source {
		cloned[key] = cloneValue(value)
	}
	return cloned
}

func cloneValue(value any) any {
	switch typed := value.(type) {
	case map[string]any:
		return cloneObject(typed)
	case []any:
		cloned := make([]any, len(typed))
		for index, item := range typed {
			cloned[index] = cloneValue(item)
		}
		return cloned
	default:
		return typed
	}
}
