package config

import (
	"bytes"
	"encoding/json"
	"errors"
)

// boundedPrettyJSON checks an upper bound on indentation before allocating it.
// Compact encoding stays proportional to the decoded request; indentation of
// deeply nested JSON can otherwise grow quadratically.
func boundedPrettyJSON(v any) (string, error) {
	const limit = 256 << 10
	raw, err := json.Marshal(v)
	if err != nil {
		return "", err
	}
	size, depth := len(raw), 0
	quoted, escaped := false, false
	for _, c := range raw {
		if quoted {
			if escaped {
				escaped = false
			} else if c == '\\' {
				escaped = true
			} else if c == '"' {
				quoted = false
			}
			continue
		}
		switch c {
		case '"':
			quoted = true
		case '{', '[':
			depth++
			size += 1 + 2*depth
		case '}', ']':
			depth--
			size += 1 + 2*depth
		case ',':
			size += 1 + 2*depth
		case ':':
			size++
		}
		if size > limit {
			return "", errors.New("formatted JSON exceeds output limit")
		}
	}
	if size > limit {
		return "", errors.New("formatted JSON exceeds output limit")
	}
	var out bytes.Buffer
	out.Grow(size)
	if err := json.Indent(&out, raw, "", "  "); err != nil {
		return "", err
	}
	return out.String(), nil
}
