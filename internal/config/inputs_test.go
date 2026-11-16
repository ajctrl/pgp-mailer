package config

import (
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
