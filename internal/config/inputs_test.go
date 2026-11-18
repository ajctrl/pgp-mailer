package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestInputsReplaceDefaults(t *testing.T) {
	env := base()
	file := filepath.Join(t.TempDir(), "inputs.json")
	if err := os.WriteFile(file, []byte(`[{"path":"/hooks/text","source":"text","auth":"bearer","format":"text","dedup":"none"}]`), 0600); err != nil {
		t.Fatal(err)
	}
	env["INPUTS_FILE"] = file
	delete(env, "GRAFANA_HMAC_SECRET")
	c, err := load(env)
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Inputs) != 1 || c.Inputs[0].Path != "/hooks/text" {
		t.Fatal("defaults were not replaced")
	}
	if err := os.WriteFile(file, []byte("[]"), 0600); err != nil {
		t.Fatal(err)
	}
	delete(env, "API_TOKENS")
	c, err = load(env)
	if err != nil || len(c.Inputs) != 0 {
		t.Fatalf("disable intake: %v", err)
	}
}

func TestInvalidInputs(t *testing.T) {
	valid := `[{"path":"/hooks/test","source":"test","auth":"bearer","format":"json","dedup":"body","title":"hello"}]`
	for _, raw := range []string{
		strings.Replace(valid, `"title":"hello"`, `"public_subject":"notify\r\nFrom: other"`, 1),
		strings.Replace(valid, `"title":"hello"`, `"public_subject":"`+strings.Repeat("件", 201)+`"`, 1),
		strings.Replace(valid, `"title":"hello"`, `"protected_subject_template":"{{ .Titel }}"`, 1),
		"null", valid + " {}", strings.Replace(valid, "hello", "{{", 1),
		strings.Replace(valid, "/hooks/test", "/metrics", 1),
		strings.Replace(valid, "/hooks/test", "/hooks/{id}", 1),
		strings.Replace(valid, "bearer", "none", 1),
		strings.Replace(valid, "\"title\"", "\"typo\"", 1),
		strings.Replace(valid, "/hooks/test", "/hooks/%74est", 1),
		"[" + strings.Trim(valid, "[]") + "," + strings.Trim(valid, "[]") + "]",
	} {
		if _, err := ParseInputs([]byte(raw)); err == nil {
			t.Fatalf("accepted %s", raw)
		}
	}
}

func TestProtectedSubjectFormat(t *testing.T) {
	const title = "DB接続エラー {{.Level}}"
	for _, tc := range []struct{ format, want string }{
		{"", "[error] " + title},
		{"監視通知", "監視通知"},
		{"{{ .Level | upper }}: {{ .Title }}", "ERROR: " + title},
		{"{{ .Level | lower }}: {{ .Title }}", "error: " + title},
		{"{{.Level|upper}}/{{.Level}}{{.Title}}", "ERROR/error" + title},
	} {
		raw, err := json.Marshal([]Input{{Path: "/notify", Source: "api", Auth: "bearer", Format: "json", Validation: "message", Dedup: "none", ProtectedSubjectTemplate: tc.format}})
		if err != nil {
			t.Fatal(err)
		}
		inputs, err := ParseInputs(raw)
		if err != nil {
			t.Fatal(err)
		}
		var subject strings.Builder
		if err := inputs[0].WriteProtectedSubject(&subject, "error", title); err != nil || subject.String() != tc.want {
			t.Errorf("format %q: subject = %q, want %q, err = %v", tc.format, subject.String(), tc.want, err)
		}
	}
}

func TestRejectUnsupportedProtectedSubject(t *testing.T) {
	for _, format := range []string{
		"   ", "line\nbreak", "a\tb", "a\u2028b", "a\u2029b", "{{\n.Title}}",
		"{{.Title", "stray }}", "{{}}", "{{.Missing}}", "{{.Title | upper}}", "{{.Title | lower}}",
		"{{range len .Title}}{{println $.Title}}{{end}}", "{{with or .Title nil}}{{.Level}}{{end}}",
		"{{if .Level}}{{.Title}}{{end}}", "{{define \"part\"}}x{{end}}", "{{template \"part\"}}",
		"{{$v := .Title}}", "{{printf \"%s\" .Title}}", "{{.Level | upper | upper}}",
		"{{/* comment */}}notice", "{{- .Title -}}", "{{.Ti tle}}",
	} {
		if _, err := parseSubjectTemplate(format); err == nil {
			t.Errorf("accepted protected subject format %q", format)
		}
	}
}
