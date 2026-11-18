package config

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"path"
	"strings"
	"text/template"
	"unicode"
	"unicode/utf8"
)

//go:embed inputs.default.json
var DefaultInputsJSON []byte

// Input describes an HTTP intake without depending on a product-specific handler.
type Input struct {
	Path            string                `json:"path"`
	Source          string                `json:"source"`
	Auth            string                `json:"auth"`
	SecretEnv       string                `json:"secret_env,omitempty"`
	SignatureHeader string                `json:"signature_header,omitempty"`
	TimestampHeader string                `json:"timestamp_header,omitempty"`
	Caller          string                `json:"caller,omitempty"`
	Format          string                `json:"format"`
	Validation      string                `json:"validation,omitempty"`
	PublicSubject   string                `json:"public_subject,omitempty"`
	RequireAny      []string              `json:"require_any,omitempty"`
	Title           string                `json:"title,omitempty"`
	Body            string                `json:"body,omitempty"`
	Level           string                `json:"level,omitempty"`
	Dedup           string                `json:"dedup"`
	DedupNamespace  *string               `json:"dedup_namespace,omitempty"`
	Secret          []byte                `json:"-"`
	Templates       [3]*template.Template `json:"-"`
}

func TemplateFuncs() template.FuncMap {
	return template.FuncMap{
		"toPrettyJSON": boundedPrettyJSON,
		"text": func(v any) string {
			if v == nil {
				return ""
			}
			if s, ok := v.(string); ok {
				return s
			}
			b, _ := json.Marshal(v)
			return string(b)
		},
		"trim": strings.TrimSpace,
		"clean": func(s string) string {
			return strings.Map(func(r rune) rune {
				if unicode.IsControl(r) || r == '\u2028' || r == '\u2029' {
					return ' '
				}
				return r
			}, s)
		},
		"cut": func(n int, s string) string {
			r := []rune(s)
			if len(r) > n {
				return string(r[:n])
			}
			return s
		},
	}
}

func ParseInputs(raw []byte) ([]Input, error) {
	var inputs []Input
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if err := d.Decode(&inputs); err != nil {
		return nil, fmt.Errorf("invalid inputs JSON")
	}
	if err := d.Decode(new(any)); err != io.EOF {
		return nil, fmt.Errorf("unexpected data after inputs")
	}
	if inputs == nil {
		return nil, fmt.Errorf("inputs must be an array")
	}
	seen := map[string]bool{}
	for i := range inputs {
		p := &inputs[i]
		u, err := url.Parse(p.Path)
		if err != nil || u.Path != p.Path || !strings.HasPrefix(p.Path, "/") || p.Path == "/" || path.Clean(p.Path) != p.Path || strings.HasSuffix(p.Path, "/") || strings.ContainsAny(p.Path, "{} \t\r\n") || strings.HasPrefix(p.Path, "/admin") || p.Path == "/healthz" || p.Path == "/metrics" || seen[p.Path] {
			return nil, fmt.Errorf("input %d: invalid, reserved or duplicate path", i)
		}
		seen[p.Path] = true
		if p.DedupNamespace != nil && strings.ContainsRune(*p.DedupNamespace, 0) {
			return nil, fmt.Errorf("input %d: invalid dedup_namespace", i)
		}
		if !nameRe.MatchString(p.Source) {
			return nil, fmt.Errorf("input %d: invalid source", i)
		}
		if p.Auth != "bearer" && p.Auth != "hmac-sha256" {
			return nil, fmt.Errorf("input %d: auth must be bearer or hmac-sha256", i)
		}
		if p.Auth == "hmac-sha256" && (p.SecretEnv == "" || !headerName(p.SignatureHeader) || !headerName(p.TimestampHeader) || strings.EqualFold(p.SignatureHeader, p.TimestampHeader)) {
			return nil, fmt.Errorf("input %d: HMAC secret_env and distinct header names required", i)
		}
		if p.Format != "json" && p.Format != "text" {
			return nil, fmt.Errorf("input %d: format must be json or text", i)
		}
		if strings.IndexFunc(p.PublicSubject, unicode.IsControl) >= 0 || strings.ContainsAny(p.PublicSubject, "\u2028\u2029") || utf8.RuneCountInString(p.PublicSubject) > 200 {
			return nil, fmt.Errorf("input %d: public_subject must be one line of at most 200 characters without control characters", i)
		}
		p.PublicSubject = strings.TrimSpace(p.PublicSubject)
		if p.Validation != "" && p.Validation != "message" {
			return nil, fmt.Errorf("input %d: unsupported validation", i)
		}
		if p.Validation == "message" && (p.Format != "json" || p.Title != "" || p.Body != "" || p.Level != "" || len(p.RequireAny) > 0) {
			return nil, fmt.Errorf("input %d: message validation consumes the original JSON", i)
		}
		if len(p.RequireAny) > 0 && p.Format != "json" {
			return nil, fmt.Errorf("input %d: require_any needs JSON", i)
		}
		if p.Dedup != "idempotency-key" && p.Dedup != "body" && p.Dedup != "none" {
			return nil, fmt.Errorf("input %d: unsupported dedup", i)
		}
		for j, s := range []string{p.Title, p.Body, p.Level} {
			t, err := template.New("input").Funcs(TemplateFuncs()).Option("missingkey=zero").Parse(s)
			if err != nil {
				return nil, fmt.Errorf("input %d: invalid template %d", i, j)
			}
			p.Templates[j] = t
		}
	}
	return inputs, nil
}

func headerName(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune("!#$%&'*+-.^_`|~", r)) {
			return false
		}
	}
	return true
}

func DefaultInputs() []Input {
	inputs, err := ParseInputs(DefaultInputsJSON)
	if err != nil {
		panic(err)
	}
	return inputs
}
