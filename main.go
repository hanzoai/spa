// Package main is hanzoai/spa — zero-config SPA server.
//
// Single app mode (default):
//
//	FROM ghcr.io/hanzoai/spa
//	COPY dist /public
//
// Multi-app mode (MULTI_APP=true):
//
//	FROM ghcr.io/hanzoai/spa
//	COPY --from=build /app/apps/default/dist  /public/default
//	COPY --from=build /app/apps/admin/dist    /public/admin
//	ENV MULTI_APP=true
//
// In multi-app mode, the hostname prefix selects the app:
//   admin.example.com → /public/admin/
//   app.example.com   → /public/app/
//   Default           → /public/default/
//
// Runtime config:
//   SPA_API_HOST=https://api.test.example.com
//   SPA_IAM_HOST=https://iam.test.example.com
//   SPA_CHAIN_ID=1
//   SPA_ENV=test
// ...at startup is templated into /public/config.json (or
// /public/<app>/config.json per app in multi-app mode). SPA reads
// /config.json at boot. No SPA_* vars = the placeholder file shipped in
// the image is left alone, and the SPA falls back to its own defaults.
//
// Features:
//   - SPA mode: index.html served for all routes (client-side routing)
//   - Aggressive caching: hashed assets get 1 year, index.html gets no-cache
//   - Security headers: HSTS, X-Content-Type-Options, X-Frame-Options, Referrer-Policy
//   - Gzip/Brotli: pre-compressed .gz/.br files served automatically
//   - Health check: GET /health → 200
//   - Runtime config: /config.json templated from SPA_* env vars at startup
//   - Port: 3000 (override with PORT env var)
//   - Root: /public (override with ROOT env var)
//   - Scratch-based: ~5MB total image size
package main

import (
	"encoding/json"
	"io"
	"log"
	"mime"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

func main() {
	port := os.Getenv("PORT")
	if port == "" {
		port = "3000"
	}
	root := os.Getenv("ROOT")
	if root == "" {
		root = "/public"
	}
	multiApp := os.Getenv("MULTI_APP") == "true"
	defaultApp := os.Getenv("DEFAULT_APP")
	if defaultApp == "" {
		defaultApp = "default"
	}

	if err := writeRuntimeConfig(root, multiApp); err != nil {
		log.Fatalf("spa: runtime config: %v", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		w.Write([]byte(`{"status":"ok"}`))
	})

	// 301 redirect routes. REDIRECTS=/from1=/to1,/from2=/to2 installs an
	// exact-match handler for each pair that returns 301 → target.
	// Useful when consolidating multi-page sites into a single landing
	// and you want old URLs to redirect rather than 404 / fall through
	// to index.html.
	if redirects := os.Getenv("REDIRECTS"); redirects != "" {
		for _, pair := range strings.Split(redirects, ",") {
			pair = strings.TrimSpace(pair)
			from, to, ok := strings.Cut(pair, "=")
			if !ok || from == "" || to == "" {
				log.Printf("spa: ignoring malformed REDIRECTS pair %q", pair)
				continue
			}
			fromPath, toPath := from, to
			mux.HandleFunc(fromPath, func(w http.ResponseWriter, r *http.Request) {
				http.Redirect(w, r, toPath, http.StatusMovedPermanently)
			})
			log.Printf("spa: redirect %s → %s (301)", from, to)
		}
	}

	// Reverse-proxy routes. Each PROXY_<PREFIX>=<upstream-url> env var
	// installs a prefix handler that forwards matching requests to the
	// upstream. Example:
	//   PROXY_V1=http://api.tenant:8080    → /v1/* → api.tenant:8080
	//   PROXY_API=https://api.example.com    → /api/* → api.example.com
	// The exchange SPA needs this so relative `/v1/*` fetches don't fall
	// through the SPA 404 handler and come back as `index.html`.
	for _, e := range os.Environ() {
		k, v, ok := strings.Cut(e, "=")
		if !ok || !strings.HasPrefix(k, "PROXY_") || v == "" {
			continue
		}
		prefix := "/" + strings.ToLower(strings.TrimPrefix(k, "PROXY_")) + "/"
		upstream, err := url.Parse(v)
		if err != nil {
			log.Fatalf("spa: PROXY_%s parse: %v", strings.TrimPrefix(k, "PROXY_"), err)
		}
		mux.Handle(prefix, httputil.NewSingleHostReverseProxy(upstream))
		log.Printf("spa: proxy %s → %s", prefix, upstream)
	}

	if multiApp {
		log.Printf("spa: multi-app mode, root=%s, default=%s, port=%s", root, defaultApp, port)
		mux.Handle("/", multiAppHandler(root, defaultApp))
	} else {
		log.Printf("spa: serving %s on :%s", root, port)
		mux.Handle("/", spaHandler(root))
	}

	// Optional native auth gate. When SPA_PROTECT is unset, loadProtect returns
	// nil and wrap is a no-op — the mux is served byte-for-byte as before.
	handler := loadProtect().wrap(mux)
	log.Fatal(http.ListenAndServe(":"+port, handler))
}

// writeRuntimeConfig templates /public/config.json (or each app's config.json
// in multi-app mode) from SPA_* env vars. SPA_API_HOST → apiHost,
// SPA_CHAIN_ID → chainId (int if all digits), SPA_FEATURE_X → featureX. No
// SPA_* vars set = the placeholder file shipped in the image is left alone.
func writeRuntimeConfig(root string, multiApp bool) error {
	vars := map[string]any{}
	for _, e := range os.Environ() {
		k, v, ok := strings.Cut(e, "=")
		if !ok || !strings.HasPrefix(k, "SPA_") || v == "" {
			continue
		}
		// config.json is served to browsers, so never template a secret into
		// it. Server-side secrets already drop the SPA_ prefix (PROTECT_*), but
		// this is defense-in-depth: any SPA_* key that looks like a secret is
		// excluded. NOT *TOKEN — SPA_COMMERCE_TOKEN is an intentionally
		// browser-safe Published token that must appear in config.json.
		if isSensitiveKey(k) {
			log.Printf("spa: refusing to template %s into browser config.json (looks secret)", k)
			continue
		}
		vars[toCamel(strings.TrimPrefix(k, "SPA_"))] = parseValue(v)
	}
	if len(vars) == 0 {
		log.Print("spa: no SPA_* env vars set — leaving existing /config.json in place")
		return nil
	}
	vars["v"] = 1

	targets := []string{root}
	if multiApp {
		entries, err := os.ReadDir(root)
		if err != nil {
			return err
		}
		targets = targets[:0]
		for _, e := range entries {
			if e.IsDir() {
				targets = append(targets, filepath.Join(root, e.Name()))
			}
		}
	}

	body := marshalSorted(vars)
	for _, dir := range targets {
		dst := filepath.Join(dir, "config.json")
		tmp := dst + ".tmp"
		if err := os.WriteFile(tmp, body, 0o644); err != nil {
			return err
		}
		if err := os.Rename(tmp, dst); err != nil {
			return err
		}
		log.Printf("spa: wrote runtime %s", dst)
	}
	return nil
}

// marshalSorted produces deterministic JSON output — keys sorted, no HTML
// escaping. Two builds with the same env produce byte-identical config.json.
func marshalSorted(m map[string]any) []byte {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := make([]byte, 0, 256)
	out = append(out, '{')
	for i, k := range keys {
		if i > 0 {
			out = append(out, ',')
		}
		kb, _ := json.Marshal(k)
		vb, _ := json.Marshal(m[k])
		out = append(out, kb...)
		out = append(out, ':')
		out = append(out, vb...)
	}
	out = append(out, '}', '\n')
	return out
}

// isSensitiveKey reports whether an env var name looks like a secret that must
// never be templated into the browser-served config.json. SECRET/PASSWORD/
// PRIVATE only — deliberately NOT TOKEN, because SPA_COMMERCE_TOKEN is a
// browser-safe Published token the SPA needs at runtime.
func isSensitiveKey(k string) bool {
	u := strings.ToUpper(k)
	return strings.Contains(u, "SECRET") ||
		strings.Contains(u, "PASSWORD") ||
		strings.Contains(u, "PRIVATE")
}

// toCamel turns SPA_API_HOST → apiHost, SPA_CHAIN_ID → chainId.
func toCamel(s string) string {
	parts := strings.Split(strings.ToLower(s), "_")
	for i, p := range parts {
		if i == 0 || p == "" {
			continue
		}
		parts[i] = strings.ToUpper(p[:1]) + p[1:]
	}
	return strings.Join(parts, "")
}

// parseValue coerces env-var strings: "true"/"false" → bool, all-digits →
// int64, else → string. Needed so chainId serializes as a JSON number.
func parseValue(v string) any {
	switch strings.ToLower(v) {
	case "true":
		return true
	case "false":
		return false
	}
	allDigits := len(v) > 0
	for _, c := range v {
		if c < '0' || c > '9' {
			allDigits = false
			break
		}
	}
	if allDigits {
		var n int64
		for _, c := range v {
			n = n*10 + int64(c-'0')
		}
		return n
	}
	return v
}

// resolveApp picks the app subdirectory from the hostname prefix.
// The first label of the hostname maps to a directory under root;
// if that directory exists, the prefix wins, otherwise defaultApp is used.
func resolveApp(host, defaultApp string) string {
	return resolveAppWithRoot(host, defaultApp, "")
}

func resolveAppWithRoot(host, defaultApp, root string) string {
	// Strip port
	if idx := strings.IndexByte(host, ':'); idx >= 0 {
		host = host[:idx]
	}
	// First label of hostname
	prefix := host
	if idx := strings.IndexByte(host, '.'); idx >= 0 {
		prefix = host[:idx]
	}
	if prefix == "" || prefix == host {
		return defaultApp
	}
	// Only accept simple identifiers so a hostile Host header can't escape root.
	for _, c := range prefix {
		if !((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '_') {
			return defaultApp
		}
	}
	if root != "" {
		if stat, err := os.Stat(filepath.Join(root, prefix)); err == nil && stat.IsDir() {
			return prefix
		}
		return defaultApp
	}
	return prefix
}

func multiAppHandler(root, defaultApp string) http.Handler {
	allowFraming := os.Getenv("ALLOW_FRAMING") == "true"
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		app := resolveAppWithRoot(r.Host, defaultApp, root)
		appRoot := filepath.Join(root, app)
		setSecurityHeaders(w, allowFraming)
		resolveAndServe(w, r, appRoot)
	})
}

func spaHandler(root string) http.Handler {
	allowFraming := os.Getenv("ALLOW_FRAMING") == "true"
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		setSecurityHeaders(w, allowFraming)
		resolveAndServe(w, r, root)
	})
}

// resolveAndServe handles both Vite-style SPAs (one index.html) and Next.js
// static exports (per-route .html or per-route /index.html). Resolution order:
//   1. <root>/<path>        — exact file (e.g. /favicon.ico)
//   2. <root>/<path>.html   — Next.js export with trailingSlash:false (/foo → /foo.html)
//   3. <root>/<path>/index.html  — Next.js export with trailingSlash:true OR a directory hit
//   4. <root>/index.html    — SPA fallback for client-side routing
func resolveAndServe(w http.ResponseWriter, r *http.Request, root string) {
	clean := filepath.Clean(r.URL.Path)
	path := filepath.Join(root, clean)

	if fi, err := os.Stat(path); err == nil && !fi.IsDir() {
		serveFile(w, r, path, false)
		return
	}
	if fi, err := os.Stat(path + ".html"); err == nil && !fi.IsDir() {
		serveFile(w, r, path+".html", false)
		return
	}
	idx := filepath.Join(path, "index.html")
	if fi, err := os.Stat(idx); err == nil && !fi.IsDir() {
		serveFile(w, r, idx, false)
		return
	}
	// A request that names a file — it has an extension (/app.js, /img/x.png)
	// or targets a known asset root — but reached the fallback simply doesn't
	// exist: 404 it rather than masquerading the SPA index.html shell as the
	// asset. Only extensionless client routes (/shop, /guide) fall through to
	// index.html for client-side routing.
	if filepath.Ext(clean) != "" || strings.HasPrefix(clean, "/img/") || strings.HasPrefix(clean, "/fonts/") {
		// This miss is transient by construction: during a rolling deploy the
		// old replica is asked for the new build's hashed assets. An edge cache
		// that stores the 404 (Cloudflare's default TTL rules do) stretches
		// that seconds-long window into hours of blank pages, so the refusal
		// must be uncacheable.
		w.Header().Set("Cache-Control", "no-store")
		http.NotFound(w, r)
		return
	}
	serveFile(w, r, filepath.Join(root, "index.html"), true)
}

// permissionsPolicyHeader and cspFrameAncestorsHeader are evaluated once
// at startup. SPAs that need camera/mic (biometric KYC) or inline-script
// CSP (dev HMR, analytics) set the env vars; defaults stay locked-down.
var (
	permissionsPolicyHeader = envOr("SPA_PERMISSIONS_POLICY",
		"camera=(), microphone=(), geolocation=()")
	cspFrameAncestorsHeader = envOr("SPA_CSP",
		"frame-ancestors 'none'")
)

func envOr(k, fallback string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return fallback
}

func setSecurityHeaders(w http.ResponseWriter, allowFraming bool) {
	w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	if !allowFraming {
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Content-Security-Policy", cspFrameAncestorsHeader)
	}
	w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
	w.Header().Set("Permissions-Policy", permissionsPolicyHeader)
}

func serveFile(w http.ResponseWriter, r *http.Request, path string, isFallback bool) {
	f, err := os.Open(path)
	if err != nil {
		http.Error(w, "not found", 404)
		return
	}
	defer f.Close()

	fi, err := f.Stat()
	if err != nil {
		http.Error(w, "error", 500)
		return
	}

	ext := filepath.Ext(path)
	ct := mime.TypeByExtension(ext)
	if ct != "" {
		w.Header().Set("Content-Type", ct)
	}

	name := filepath.Base(path)
	// config.json must never be cached — it's templated at startup and the
	// SPA fetches it on boot.
	if name == "config.json" {
		w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
	} else if isFallback || name == "index.html" {
		w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
	} else if isHashedAsset(name) {
		w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
	} else {
		w.Header().Set("Cache-Control", "public, max-age=86400")
	}

	// Vary: Accept-Encoding is required regardless of which branch fires —
	// the response varies by the request's Accept-Encoding even when we
	// fall through to the identity body (CDN representation cache must
	// not serve the identity bytes to a client that asked for br/gzip).
	w.Header().Set("Vary", "Accept-Encoding")

	accept := r.Header.Get("Accept-Encoding")
	if acceptsEncoding(accept, "br") {
		if br, err := os.Open(path + ".br"); err == nil {
			defer br.Close()
			w.Header().Set("Content-Encoding", "br")
			io.Copy(w, br)
			return
		}
	}
	if acceptsEncoding(accept, "gzip") {
		if gz, err := os.Open(path + ".gz"); err == nil {
			defer gz.Close()
			w.Header().Set("Content-Encoding", "gzip")
			io.Copy(w, gz)
			return
		}
	}

	http.ServeContent(w, r, fi.Name(), fi.ModTime(), f)
}

// acceptsEncoding reports whether the Accept-Encoding header allows the given
// coding. A token is allowed unless the client explicitly disables it with
// `;q=0`. Whitespace and case are ignored. Falls back to a substring check
// for the most common single-token forms (br, gzip).
func acceptsEncoding(header, coding string) bool {
	for _, part := range strings.Split(header, ",") {
		token := strings.TrimSpace(part)
		if token == "" {
			continue
		}
		name := token
		q := "1"
		if i := strings.IndexByte(token, ';'); i >= 0 {
			name = strings.TrimSpace(token[:i])
			rest := strings.TrimSpace(token[i+1:])
			if eq := strings.IndexByte(rest, '='); eq > 0 && strings.EqualFold(strings.TrimSpace(rest[:eq]), "q") {
				q = strings.TrimSpace(rest[eq+1:])
			}
		}
		if !strings.EqualFold(name, coding) && name != "*" {
			continue
		}
		// q=0 is "not acceptable" per RFC 9110 §12.5.3.
		if q == "0" || strings.HasPrefix(q, "0.") && strings.TrimLeft(q[2:], "0") == "" {
			return false
		}
		return true
	}
	return false
}

func isHashedAsset(name string) bool {
	ext := filepath.Ext(name)
	base := strings.TrimSuffix(name, ext)
	if idx := strings.LastIndex(base, "-"); idx > 0 {
		hash := base[idx+1:]
		if len(hash) >= 6 {
			for _, c := range hash {
				if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')) {
					return false
				}
			}
			return true
		}
	}
	return false
}
