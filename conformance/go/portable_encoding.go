package qbccjson

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"
)

const profilePrefix = "QBC-CJSON-V1\x00"

var domainPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._/-]{0,63}$`)

// CanonicalJSONV1 returns the profile's canonical UTF-8 bytes.
// Accepted integer values are signed 64-bit integers only.
func CanonicalJSONV1(v any) ([]byte, error) {
	var out bytes.Buffer
	if err := appendValue(&out, v); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}

func appendValue(out *bytes.Buffer, v any) error {
	switch x := v.(type) {
	case nil:
		out.WriteString("null")
	case bool:
		if x {
			out.WriteString("true")
		} else {
			out.WriteString("false")
		}
	case int:
		return appendInteger(out, int64(x))
	case int8:
		return appendInteger(out, int64(x))
	case int16:
		return appendInteger(out, int64(x))
	case int32:
		return appendInteger(out, int64(x))
	case int64:
		return appendInteger(out, x)
	case string:
		return appendString(out, x)
	case []any:
		out.WriteByte('[')
		for i, item := range x {
			if i > 0 {
				out.WriteByte(',')
			}
			if err := appendValue(out, item); err != nil {
				return err
			}
		}
		out.WriteByte(']')
	case map[string]any:
		keys := make([]string, 0, len(x))
		for key := range x {
			if !utf8.ValidString(key) {
				return errors.New("object key is not valid UTF-8 / Unicode scalar text")
			}
			keys = append(keys, key)
		}
		// Go string ordering is lexicographic by UTF-8 bytes.
		sort.Strings(keys)
		out.WriteByte('{')
		for i, key := range keys {
			if i > 0 {
				out.WriteByte(',')
			}
			if err := appendString(out, key); err != nil {
				return err
			}
			out.WriteByte(':')
			if err := appendValue(out, x[key]); err != nil {
				return err
			}
		}
		out.WriteByte('}')
	default:
		return fmt.Errorf("unsupported value type %T", v)
	}
	return nil
}

func appendInteger(out *bytes.Buffer, n int64) error {
	// int64 is exactly the profile's signed 64-bit range.
	out.WriteString(strconv.FormatInt(n, 10))
	return nil
}

func appendString(out *bytes.Buffer, s string) error {
	if !utf8.ValidString(s) {
		return errors.New("string is not valid UTF-8 / Unicode scalar text")
	}
	out.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"':
			out.WriteString(`\"`)
		case '\':
			out.WriteString(`\\`)
		default:
			if r <= 0x1f {
				out.WriteString(fmt.Sprintf(`\u%04x`, r))
			} else {
				out.WriteRune(r)
			}
		}
	}
	out.WriteByte('"')
	return nil
}

// HashCanonicalV1 applies the profile's domain-separated SHA-256 construction.
func HashCanonicalV1(domain string, value any) (string, error) {
	if !domainPattern.MatchString(domain) || !isASCII(domain) {
		return "", errors.New("invalid hash domain")
	}
	encoded, err := CanonicalJSONV1(value)
	if err != nil {
		return "", err
	}
	preimage := make([]byte, 0, len(profilePrefix)+len(domain)+1+len(encoded))
	preimage = append(preimage, []byte(profilePrefix)...)
	preimage = append(preimage, domain...)
	preimage = append(preimage, 0)
	preimage = append(preimage, encoded...)
	sum := sha256.Sum256(preimage)
	return hex.EncodeToString(sum[:]), nil
}

func isASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] > 0x7f {
			return false
		}
	}
	return true
}

// ParseCanonicalJSONV1 parses canonical JSON and rejects duplicate keys and
// any input whose exact bytes do not equal the canonical re-encoding.
func ParseCanonicalJSONV1(raw []byte) (any, error) {
	if !utf8.Valid(raw) {
		return nil, errors.New("input is not valid UTF-8")
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	value, err := parseValue(dec)
	if err != nil {
		return nil, err
	}
	if _, err := dec.Token(); err != io.EOF {
		if err == nil {
			return nil, errors.New("trailing JSON content")
		}
		return nil, err
	}
	canonical, err := CanonicalJSONV1(value)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(raw, canonical) {
		return nil, errors.New("JSON input is not canonical qbc-cjson-v1")
	}
	return value, nil
}

func parseValue(dec *json.Decoder) (any, error) {
	token, err := dec.Token()
	if err != nil {
		return nil, err
	}
	switch x := token.(type) {
	case nil, bool, string:
		return x, nil
	case json.Number:
		s := string(x)
		if strings.ContainsAny(s, ".eE") || s == "-0" {
			return nil, errors.New("non-integer or negative-zero number")
		}
		n, err := strconv.ParseInt(s, 10, 64)
		if err != nil || math.MinInt64 > n {
			return nil, errors.New("integer outside signed 64-bit range")
		}
		return n, nil
	case json.Delim:
		switch x {
		case '{':
			obj := make(map[string]any)
			for dec.More() {
				keyToken, err := dec.Token()
				if err != nil {
					return nil, err
				}
				key, ok := keyToken.(string)
				if !ok {
					return nil, errors.New("object key must be a string")
				}
				if _, exists := obj[key]; exists {
					return nil, errors.New("duplicate object key")
				}
				value, err := parseValue(dec)
				if err != nil {
					return nil, err
				}
				obj[key] = value
			}
			end, err := dec.Token()
			if err != nil || end != json.Delim('}') {
				return nil, errors.New("unterminated object")
			}
			return obj, nil
		case '[':
			var arr []any
			for dec.More() {
				value, err := parseValue(dec)
				if err != nil {
					return nil, err
				}
				arr = append(arr, value)
			}
			end, err := dec.Token()
			if err != nil || end != json.Delim(']') {
				return nil, errors.New("unterminated array")
			}
			return arr, nil
		}
	}
	return nil, fmt.Errorf("unsupported JSON token %T", token)
}
