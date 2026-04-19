package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestToCamel(t *testing.T) {
	cases := map[string]string{
		"API_HOST":  "apiHost",
		"IAM_HOST":  "iamHost",
		"RPC_HOST":  "rpcHost",
		"ID_HOST":   "idHost",
		"CHAIN_ID":  "chainId",
		"ENV":       "env",
		"FEATURE_X": "featureX",
	}
	for in, want := range cases {
		if got := toCamel(in); got != want {
			t.Errorf("toCamel(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestParseValue(t *testing.T) {
	if parseValue("true") != true {
		t.Error("true should parse to bool true")
	}
	if parseValue("false") != false {
		t.Error("false should parse to bool false")
	}
	if parseValue("8675310") != int64(8675310) {
		t.Errorf("8675310 should parse to int64, got %T", parseValue("8675310"))
	}
	if parseValue("https://api.test.satschel.com") != "https://api.test.satschel.com" {
		t.Error("URL should stay string")
	}
	if parseValue("v1.2.3") != "v1.2.3" {
		t.Error("version string should stay string")
	}
}

func TestWriteRuntimeConfigSingleApp(t *testing.T) {
	dir := t.TempDir()
	placeholder := filepath.Join(dir, "config.json")
	if err := os.WriteFile(placeholder, []byte(`{"v":1,"env":"__TEMPLATE__"}`), 0o644); err != nil {
		t.Fatal(err)
	}

	t.Setenv("SPA_API_HOST", "https://api.test.satschel.com")
	t.Setenv("SPA_IAM_HOST", "https://iam.test.satschel.com")
	t.Setenv("SPA_CHAIN_ID", "8675310")
	t.Setenv("SPA_ENV", "test")

	if err := writeRuntimeConfig(dir, false); err != nil {
		t.Fatal(err)
	}

	raw, err := os.ReadFile(placeholder)
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]any
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("invalid JSON: %v\n%s", err, raw)
	}

	if got["apiHost"] != "https://api.test.satschel.com" {
		t.Errorf("apiHost = %v", got["apiHost"])
	}
	if got["iamHost"] != "https://iam.test.satschel.com" {
		t.Errorf("iamHost = %v", got["iamHost"])
	}
	if got["chainId"].(float64) != 8675310 {
		t.Errorf("chainId = %v", got["chainId"])
	}
	if got["env"] != "test" {
		t.Errorf("env = %v", got["env"])
	}
	if got["v"].(float64) != 1 {
		t.Errorf("v should be 1, got %v", got["v"])
	}
}

func TestWriteRuntimeConfigMultiApp(t *testing.T) {
	root := t.TempDir()
	for _, name := range []string{"superadmin", "ats", "bd", "ta"} {
		d := filepath.Join(root, name)
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(d, "config.json"), []byte(`{"v":1}`), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	t.Setenv("SPA_API_HOST", "https://api.test.satschel.com")
	t.Setenv("SPA_ENV", "test")

	if err := writeRuntimeConfig(root, true); err != nil {
		t.Fatal(err)
	}

	for _, name := range []string{"superadmin", "ats", "bd", "ta"} {
		raw, err := os.ReadFile(filepath.Join(root, name, "config.json"))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		var got map[string]any
		if err := json.Unmarshal(raw, &got); err != nil {
			t.Fatalf("%s: invalid JSON: %v", name, err)
		}
		if got["apiHost"] != "https://api.test.satschel.com" {
			t.Errorf("%s: apiHost = %v", name, got["apiHost"])
		}
	}
}

func TestWriteRuntimeConfigNoEnv(t *testing.T) {
	dir := t.TempDir()
	placeholder := filepath.Join(dir, "config.json")
	original := []byte(`{"v":1,"env":"__TEMPLATE__"}`)
	if err := os.WriteFile(placeholder, original, 0o644); err != nil {
		t.Fatal(err)
	}

	// Wipe any inherited SPA_* vars.
	for _, e := range os.Environ() {
		k, _, ok := splitCut(e, "=")
		if ok && len(k) > 4 && k[:4] == "SPA_" {
			t.Setenv(k, "")
		}
	}

	if err := writeRuntimeConfig(dir, false); err != nil {
		t.Fatal(err)
	}

	raw, err := os.ReadFile(placeholder)
	if err != nil {
		t.Fatal(err)
	}
	if string(raw) != string(original) {
		t.Errorf("placeholder should be untouched when no SPA_* vars set\ngot: %s\nwant: %s", raw, original)
	}
}

func splitCut(s, sep string) (string, string, bool) {
	for i := 0; i+len(sep) <= len(s); i++ {
		if s[i:i+len(sep)] == sep {
			return s[:i], s[i+len(sep):], true
		}
	}
	return s, "", false
}
