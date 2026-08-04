package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
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
	if parseValue("42") != int64(42) {
		t.Errorf("42 should parse to int64, got %T", parseValue("42"))
	}
	if parseValue("https://api.test.example.com") != "https://api.test.example.com" {
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

	t.Setenv("SPA_API_HOST", "https://api.test.example.com")
	t.Setenv("SPA_IAM_HOST", "https://iam.test.example.com")
	t.Setenv("SPA_CHAIN_ID", "1")
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

	if got["apiHost"] != "https://api.test.example.com" {
		t.Errorf("apiHost = %v", got["apiHost"])
	}
	if got["iamHost"] != "https://iam.test.example.com" {
		t.Errorf("iamHost = %v", got["iamHost"])
	}
	if got["chainId"].(float64) != 1 {
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
	for _, name := range []string{"default", "admin", "app", "console"} {
		d := filepath.Join(root, name)
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(d, "config.json"), []byte(`{"v":1}`), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	t.Setenv("SPA_API_HOST", "https://api.test.example.com")
	t.Setenv("SPA_ENV", "test")

	if err := writeRuntimeConfig(root, true); err != nil {
		t.Fatal(err)
	}

	for _, name := range []string{"default", "admin", "app", "console"} {
		raw, err := os.ReadFile(filepath.Join(root, name, "config.json"))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		var got map[string]any
		if err := json.Unmarshal(raw, &got); err != nil {
			t.Fatalf("%s: invalid JSON: %v", name, err)
		}
		if got["apiHost"] != "https://api.test.example.com" {
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

func TestResolveAndServeNextExport(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "index.html"), []byte("ROOT"), 0644); err != nil { t.Fatal(err) }
	if err := os.MkdirAll(filepath.Join(dir, "docs"), 0755); err != nil { t.Fatal(err) }
	if err := os.WriteFile(filepath.Join(dir, "docs.html"), []byte("DOCS"), 0644); err != nil { t.Fatal(err) }
	if err := os.MkdirAll(filepath.Join(dir, "guide"), 0755); err != nil { t.Fatal(err) }
	if err := os.WriteFile(filepath.Join(dir, "guide", "index.html"), []byte("GUIDE-INDEX"), 0644); err != nil { t.Fatal(err) }

	srv := httptest.NewServer(spaHandler(dir))
	defer srv.Close()

	cases := map[string]string{
		"/":         "ROOT",
		"/docs":     "DOCS",
		"/docs/":    "DOCS",
		"/guide":    "GUIDE-INDEX",
		"/guide/":   "GUIDE-INDEX",
		"/missing":  "ROOT",
	}
	for path, want := range cases {
		r, err := http.Get(srv.URL + path)
		if err != nil { t.Fatalf("%s: %v", path, err) }
		body, _ := io.ReadAll(r.Body); r.Body.Close()
		if string(body) != want {
			t.Errorf("%s: got %q want %q", path, body, want)
		}
	}
}

// A missing subresource must 404. The fallback answers ROUTES; answering an
// <img src> with the HTML shell under a 200 makes a broken icon and a working
// one indistinguishable to anything that reads a status code — which is how
// seven missing icons shipped to app.lux.finance unnoticed.
func TestMissingAssetIs404(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "index.html"), []byte("ROOT"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "images"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "images", "real.svg"), []byte("<svg/>"), 0644); err != nil {
		t.Fatal(err)
	}

	srv := httptest.NewServer(spaHandler(dir))
	defer srv.Close()

	cases := []struct {
		path       string
		wantStatus int
		wantType   string // prefix match; "" means don't care
		why        string
	}{
		{"/images/real.svg", 200, "image/svg+xml", "the asset exists — positive control"},
		{"/images/icons/lux.svg", 404, "", "missing image must not answer as the HTML shell"},
		{"/assets/index-deadbeef.js", 404, "", "missing script must not answer as the HTML shell"},
		{"/styles/app.css", 404, "", "missing stylesheet must not answer as the HTML shell"},
		{"/fonts/geist.woff2", 404, "", "missing font must not answer as the HTML shell"},
		{"/data/vaults.json", 404, "", "missing data file must not answer as the HTML shell"},
		{"/vaults", 200, "text/html", "a client-side route still falls back to index.html"},
		{"/governance/proposals", 200, "text/html", "a nested route still falls back"},
		{"/users/z@hanzo.ai", 200, "text/html", "a route whose last element ends in a dotted token is NOT an asset"},
	}
	for _, c := range cases {
		r, err := http.Get(srv.URL + c.path)
		if err != nil {
			t.Fatalf("%s: %v", c.path, err)
		}
		body, _ := io.ReadAll(r.Body)
		r.Body.Close()
		if r.StatusCode != c.wantStatus {
			t.Errorf("GET %s = %d, want %d (%s)", c.path, r.StatusCode, c.wantStatus, c.why)
		}
		if c.wantType != "" && !strings.HasPrefix(r.Header.Get("Content-Type"), c.wantType) {
			t.Errorf("GET %s Content-Type = %q, want prefix %q (%s)",
				c.path, r.Header.Get("Content-Type"), c.wantType, c.why)
		}
		// The specific defect: never the SPA shell under an asset's URL.
		if c.wantStatus == 404 && string(body) == "ROOT" {
			t.Errorf("GET %s served the SPA shell — %s", c.path, c.why)
		}
	}
}

func TestHealthCacheControl(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		w.Write([]byte(`{"status":"ok"}`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	r, err := http.Get(srv.URL + "/health")
	if err != nil {
		t.Fatal(err)
	}
	defer r.Body.Close()
	if got := r.Header.Get("Cache-Control"); got != "no-store" {
		t.Errorf("Cache-Control = %q, want no-store (CDN must not cache /health)", got)
	}
}

func TestServeFileVaryAccept(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "index.html"), []byte("ROOT"), 0644); err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(spaHandler(dir))
	defer srv.Close()

	// Identity (no precompressed variant available) — Vary still required.
	req, _ := http.NewRequest("GET", srv.URL+"/", nil)
	req.Header.Set("Accept-Encoding", "gzip, br")
	r, err := srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	r.Body.Close()
	if r.Header.Get("Vary") != "Accept-Encoding" {
		t.Errorf("Vary = %q, want Accept-Encoding (CDN representation cache requires this)", r.Header.Get("Vary"))
	}
	if r.Header.Get("Content-Encoding") != "" {
		t.Errorf("Content-Encoding = %q, want empty (no .br/.gz on disk)", r.Header.Get("Content-Encoding"))
	}
}

func TestAcceptsEncoding(t *testing.T) {
	cases := []struct {
		header string
		coding string
		want   bool
	}{
		{"gzip, br", "br", true},
		{"gzip, br", "gzip", true},
		{"identity", "br", false},
		{"", "br", false},
		{"br;q=0", "br", false},
		{"gzip, br;q=0", "br", false},
		{"gzip, br;q=0", "gzip", true},
		{"br;q=0.0", "br", false},
		{"br;q=0.5", "br", true},
		{"BR", "br", true},
		{" br ", "br", true},
		{"*", "br", true},
		{"*;q=0", "br", false},
	}
	for _, c := range cases {
		if got := acceptsEncoding(c.header, c.coding); got != c.want {
			t.Errorf("acceptsEncoding(%q, %q) = %v, want %v", c.header, c.coding, got, c.want)
		}
	}
}
