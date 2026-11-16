package config

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestPrettyJSONBudget(t *testing.T) {
	for _, raw := range []string{
		`{"text":"brackets [ ] { }, : and escaped \"quotes\"","nested":[{},[],{"n":123}]}`,
		`[true,null,"日本語",["x"]]`,
	} {
		var v any
		if err := json.Unmarshal([]byte(raw), &v); err != nil {
			t.Fatal(err)
		}
		got, err := boundedPrettyJSON(v)
		if err != nil {
			t.Fatal(err)
		}
		want, _ := json.MarshalIndent(v, "", "  ")
		if got != string(want) {
			t.Fatalf("got %q want %q", got, want)
		}
	}
	var nested any
	raw := strings.Repeat("[", 2000) + "0" + strings.Repeat("]", 2000)
	if err := json.Unmarshal([]byte(raw), &nested); err != nil {
		t.Fatal(err)
	}
	if _, err := boundedPrettyJSON(nested); err == nil {
		t.Fatal("deep expansion accepted")
	}
	if _, err := boundedPrettyJSON(strings.Repeat("x", 256<<10)); err == nil {
		t.Fatal("oversize string accepted")
	}
}
