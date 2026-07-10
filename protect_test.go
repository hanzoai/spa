package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

const realMarker = "REAL-CONTENT-MARKER"

// realHandler stands in for the production mux — its body is the sentinel that
// must NEVER appear in a gated (unauthenticated) response.
func realHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, realMarker+":"+r.URL.Path)
	})
}

// testProtect is an enabled gate with fixed endpoints and a fixed cookie key —
// no network/discovery needed for cookie/gate assertions.
func testProtect() *protect {
	return &protect{
		enabled:           true,
		iamHost:           "https://iam.example",
		clientID:          "karma-style",
		clientSecret:      "shh",
		allow:             map[string]bool{"z@hanzo.ai": true, "a@hanzo.ai": true},
		cookieSecret:      []byte("test-cookie-secret-0123456789abcd"),
		client:            &http.Client{Timeout: 5 * time.Second},
		authorizeEndpoint: "https://iam.example/v1/iam/oauth/authorize",
		tokenEndpoint:     "https://iam.example/v1/iam/oauth/token",
		userinfoEndpoint:  "https://iam.example/v1/iam/oauth/userinfo",
	}
}

func noRedirect(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }

func getBody(t *testing.T, url string) (int, string) {
	t.Helper()
	r, err := http.Get(url)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	defer r.Body.Close()
	b, _ := io.ReadAll(r.Body)
	return r.StatusCode, string(b)
}

// --- disabled = byte-for-byte no-op -----------------------------------------

func TestProtectDisabledReturnsNil(t *testing.T) {
	t.Setenv("SPA_PROTECT", "")
	if p := loadProtect(); p != nil {
		t.Fatalf("loadProtect() = %v, want nil when SPA_PROTECT unset", p)
	}
	t.Setenv("SPA_PROTECT", "off")
	if p := loadProtect(); p != nil {
		t.Fatalf("loadProtect() = %v, want nil when SPA_PROTECT=off", p)
	}
}

func TestProtectDisabledWrapIsNoop(t *testing.T) {
	// nil (disabled) gate must serve real content unchanged for every path,
	// including an asset that WOULD be gated when protection is on.
	h := (*protect)(nil).wrap(realHandler())
	srv := httptest.NewServer(h)
	defer srv.Close()

	code, body := getBody(t, srv.URL+"/app.js")
	if code != 200 {
		t.Errorf("status = %d, want 200", code)
	}
	if !strings.Contains(body, realMarker) {
		t.Errorf("disabled wrap must serve real content, got %q", body)
	}
	if strings.Contains(body, "spa-protect-gate") {
		t.Errorf("disabled wrap must not serve the gate")
	}
}

// --- enabled + anonymous = gate everywhere, no content leak ------------------

func TestProtectAnonymousGate(t *testing.T) {
	p := testProtect()
	srv := httptest.NewServer(p.wrap(realHandler()))
	defer srv.Close()

	for _, path := range []string{"/", "/index.html", "/app.js", "/products.json", "/img/x.png", "/fonts/f.woff2"} {
		code, body := getBody(t, srv.URL+path)
		if strings.Contains(body, realMarker) {
			t.Errorf("%s: LEAKED real content: %q", path, body)
		}
		if !strings.Contains(body, "spa-protect-gate") {
			t.Errorf("%s: gate marker absent (status %d): %q", path, code, body)
		}
		if !strings.Contains(body, "/auth/login") {
			t.Errorf("%s: gate missing sign-in link", path)
		}
	}

	// /health is never gated.
	code, body := getBody(t, srv.URL+"/health")
	if code != 200 {
		t.Errorf("/health status = %d, want 200", code)
	}
	if !strings.Contains(body, realMarker) {
		t.Errorf("/health must pass through to the real handler, got %q", body)
	}
}

// --- /auth/login = 302 to authorize with PKCE + state -----------------------

func TestProtectLoginRedirect(t *testing.T) {
	p := testProtect()
	srv := httptest.NewServer(p.wrap(realHandler()))
	defer srv.Close()

	client := &http.Client{CheckRedirect: noRedirect}
	resp, err := client.Get(srv.URL + "/auth/login")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("status = %d, want 302", resp.StatusCode)
	}
	loc := resp.Header.Get("Location")
	if !strings.HasPrefix(loc, p.authorizeEndpoint) {
		t.Fatalf("Location = %q, want prefix %q", loc, p.authorizeEndpoint)
	}
	u, err := url.Parse(loc)
	if err != nil {
		t.Fatal(err)
	}
	q := u.Query()
	if q.Get("code_challenge") == "" {
		t.Error("missing code_challenge")
	}
	if q.Get("code_challenge_method") != "S256" {
		t.Errorf("code_challenge_method = %q, want S256", q.Get("code_challenge_method"))
	}
	if q.Get("state") == "" {
		t.Error("missing state")
	}
	if q.Get("client_id") != "karma-style" {
		t.Errorf("client_id = %q", q.Get("client_id"))
	}
	if q.Get("response_type") != "code" {
		t.Errorf("response_type = %q", q.Get("response_type"))
	}
	if q.Get("scope") != "openid profile email" {
		t.Errorf("scope = %q", q.Get("scope"))
	}
	if q.Get("redirect_uri") == "" {
		t.Error("missing redirect_uri")
	}
	var gotAuthCookie bool
	for _, c := range resp.Cookies() {
		if c.Name == authCookie {
			gotAuthCookie = true
			if !c.HttpOnly {
				t.Error("auth cookie must be HttpOnly")
			}
		}
	}
	if !gotAuthCookie {
		t.Error("login must set the signed PKCE transaction cookie")
	}
}

// --- session cookie: forged / expired / wrong-user all fail closed ----------

func TestProtectSessionCookies(t *testing.T) {
	p := testProtect()
	srv := httptest.NewServer(p.wrap(realHandler()))
	defer srv.Close()

	future := strconv.FormatInt(time.Now().Add(time.Hour).Unix(), 10)
	past := strconv.FormatInt(time.Now().Add(-time.Hour).Unix(), 10)

	// A gate that signs with a DIFFERENT key — its cookie is a forgery here.
	forger := &protect{cookieSecret: []byte("a-totally-different-key-value!!")}

	cases := []struct {
		name     string
		value    string
		wantReal bool
	}{
		{"valid allowed email", p.sign([]byte("z@hanzo.ai|" + future)), true},
		{"valid allowed uppercase", p.sign([]byte("Z@Hanzo.AI|" + future)), true},
		{"expired", p.sign([]byte("z@hanzo.ai|" + past)), false},
		{"non-allowed email", p.sign([]byte("evil@example.com|" + future)), false},
		{"forged signature", forger.sign([]byte("z@hanzo.ai|" + future)), false},
		{"garbage", "not-a-valid-cookie", false},
		{"tampered payload", "ZXZpbEBleGFtcGxlLmNvbXwxMA.deadbeef", false},
	}
	for _, c := range cases {
		req, _ := http.NewRequest("GET", srv.URL+"/products.json", nil)
		req.AddCookie(&http.Cookie{Name: sessionCookie, Value: c.value})
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		gotReal := strings.Contains(string(body), realMarker)
		if gotReal != c.wantReal {
			t.Errorf("%s: real-content=%v, want %v (status %d)", c.name, gotReal, c.wantReal, resp.StatusCode)
		}
		if !c.wantReal && !strings.Contains(string(body), "spa-protect-gate") {
			t.Errorf("%s: expected gate, got %q", c.name, body)
		}
	}
}

// TestProtectAuthedNoStore proves that authed passthrough responses carry
// Cache-Control: no-store, so a shared CDN (Cloudflare) can never cache a
// protected asset and later serve it to an anonymous visitor.
func TestProtectAuthedNoStore(t *testing.T) {
	p := testProtect()
	// A handler that sets a cacheable header, mimicking the static file server.
	cacheable := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "public, max-age=86400")
		io.WriteString(w, realMarker)
	})
	srv := httptest.NewServer(p.wrap(cacheable))
	defer srv.Close()

	future := strconv.FormatInt(time.Now().Add(time.Hour).Unix(), 10)
	req, _ := http.NewRequest("GET", srv.URL+"/app.js", nil)
	req.AddCookie(&http.Cookie{Name: sessionCookie, Value: p.sign([]byte("z@hanzo.ai|" + future))})
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), realMarker) {
		t.Fatalf("authed request must serve real content, got %q", body)
	}
	if cc := resp.Header.Get("Cache-Control"); cc != "no-store" {
		t.Errorf("authed response Cache-Control = %q, want no-store (CDN must not cache protected content)", cc)
	}
}

// TestProtectDeniedGate proves the unauthorized state names the rejected account
// and offers sign-out (not a dead end): its primary action is /auth/logout, NOT
// /auth/login (which would just re-authorize the same rejected SSO account).
func TestProtectDeniedGate(t *testing.T) {
	p := testProtect()
	h := p.gateHTML(gateView{deniedEmail: "evil@example.com"})
	if !strings.Contains(h, "evil@example.com") {
		t.Error("denied gate must name the rejected account")
	}
	if !strings.Contains(h, `href="/auth/logout"`) {
		t.Error("denied gate must offer sign-out (/auth/logout)")
	}
	if strings.Contains(h, `href="/auth/login"`) {
		t.Error("denied gate primary action must be sign-out, not sign-in")
	}
	if !strings.Contains(h, "spa-protect-gate") {
		t.Error("denied page must still be the gate shell")
	}
}

// TestProtectLogoutClearsAndEndSession proves /auth/logout clears BOTH cookies and
// bounces the browser through the IdP end-session endpoint (so the SSO session
// drops and the next sign-in isn't silently re-authorized as the rejected account).
func TestProtectLogoutClearsAndEndSession(t *testing.T) {
	p := testProtect()
	p.endSessionEndpoint = "https://iam.example/v1/iam/oauth/logout"
	srv := httptest.NewServer(p.wrap(realHandler()))
	defer srv.Close()

	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	req, _ := http.NewRequest("GET", srv.URL+"/auth/logout", nil)
	req.AddCookie(&http.Cookie{Name: sessionCookie, Value: "x"})
	req.AddCookie(&http.Cookie{Name: authCookie, Value: "y"})
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("logout should 302, got %d", resp.StatusCode)
	}
	if loc := resp.Header.Get("Location"); !strings.HasPrefix(loc, p.endSessionEndpoint) {
		t.Errorf("logout must redirect to the IdP end-session endpoint, got %q", loc)
	}
	var clearedSession, clearedAuth bool
	for _, c := range resp.Cookies() {
		if c.Name == sessionCookie && (c.MaxAge < 0 || c.Value == "") {
			clearedSession = true
		}
		if c.Name == authCookie && (c.MaxAge < 0 || c.Value == "") {
			clearedAuth = true
		}
	}
	if !clearedSession || !clearedAuth {
		t.Errorf("logout must clear both cookies (session=%v auth=%v)", clearedSession, clearedAuth)
	}
}

// TestProtectAuthedInjectsSignOut proves an authorized HTML document gets the
// floating sign-out link injected before </body>, still contains the real content,
// and stays no-store.
func TestProtectAuthedInjectsSignOut(t *testing.T) {
	p := testProtect()
	htmlHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		io.WriteString(w, "<html><body><h1>"+realMarker+"</h1></body></html>")
	})
	srv := httptest.NewServer(p.wrap(htmlHandler))
	defer srv.Close()

	future := strconv.FormatInt(time.Now().Add(time.Hour).Unix(), 10)
	req, _ := http.NewRequest("GET", srv.URL+"/", nil)
	req.AddCookie(&http.Cookie{Name: sessionCookie, Value: p.sign([]byte("z@hanzo.ai|" + future))})
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	s := string(body)
	if !strings.Contains(s, realMarker) {
		t.Fatal("authed html must still contain the real content")
	}
	if !strings.Contains(s, `href="/auth/logout"`) {
		t.Error("authed html must have the injected sign-out link")
	}
	if strings.Index(s, "/auth/logout") > strings.LastIndex(s, "</body>") {
		t.Error("sign-out link must be injected BEFORE </body>")
	}
	if cc := resp.Header.Get("Cache-Control"); cc != "no-store" {
		t.Errorf("authed response Cache-Control = %q, want no-store", cc)
	}
}

// --- end-to-end: login -> IAM -> callback -> session -> real content --------

// fakeIAM serves discovery + token + userinfo, returning the given email.
func fakeIAM(t *testing.T, email string) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	var srv *httptest.Server
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"issuer":                 srv.URL,
			"authorization_endpoint": srv.URL + "/authorize",
			"token_endpoint":         srv.URL + "/token",
			"userinfo_endpoint":      srv.URL + "/userinfo",
			"jwks_uri":               srv.URL + "/jwks",
		})
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		if r.Form.Get("grant_type") != "authorization_code" || r.Form.Get("code") == "" ||
			r.Form.Get("code_verifier") == "" || r.Form.Get("client_id") == "" || r.Form.Get("client_secret") == "" {
			w.WriteHeader(400)
			io.WriteString(w, `{"error":"invalid_request"}`)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"access_token": "AT-" + r.Form.Get("code"), "token_type": "Bearer"})
	})
	mux.HandleFunc("/userinfo", func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") {
			w.WriteHeader(401)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"sub": "u1", "email": email})
	})
	srv = httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func runFlow(t *testing.T, iamEmail string) (int, string, bool) {
	t.Helper()
	iam := fakeIAM(t, iamEmail)
	t.Setenv("SPA_PROTECT", "iam")
	t.Setenv("SPA_IAM_HOST", iam.URL)
	t.Setenv("SPA_PROTECT_CLIENT_ID", "karma-style")
	t.Setenv("PROTECT_CLIENT_SECRET", "shh")
	t.Setenv("SPA_PROTECT_ALLOW", "z@hanzo.ai,a@hanzo.ai")
	t.Setenv("PROTECT_COOKIE_SECRET", "test-cookie-secret-0123456789abcd")
	t.Setenv("SPA_PROTECT_REDIRECT", "https://karma.style/auth/callback")

	p := loadProtect()
	if p == nil {
		t.Fatal("loadProtect() returned nil with SPA_PROTECT=iam")
	}
	// discovery must have picked up the fake endpoints
	if p.tokenEndpoint != iam.URL+"/token" {
		t.Fatalf("discovery failed: tokenEndpoint = %q", p.tokenEndpoint)
	}
	srv := httptest.NewServer(p.wrap(realHandler()))
	defer srv.Close()

	client := &http.Client{CheckRedirect: noRedirect}

	// 1. login → capture auth cookie + state
	loginResp, err := client.Get(srv.URL + "/auth/login")
	if err != nil {
		t.Fatal(err)
	}
	loginResp.Body.Close()
	loc, _ := url.Parse(loginResp.Header.Get("Location"))
	state := loc.Query().Get("state")
	var authC *http.Cookie
	for _, c := range loginResp.Cookies() {
		if c.Name == authCookie {
			authC = c
		}
	}
	if authC == nil {
		t.Fatal("no auth cookie from /auth/login")
	}

	// 2. callback with code + matching state + auth cookie
	cbReq, _ := http.NewRequest("GET", srv.URL+"/auth/callback?code=abc123&state="+url.QueryEscape(state), nil)
	cbReq.AddCookie(authC)
	cbResp, err := client.Do(cbReq)
	if err != nil {
		t.Fatal(err)
	}
	cbBody, _ := io.ReadAll(cbResp.Body)
	cbResp.Body.Close()

	var sessC *http.Cookie
	for _, c := range cbResp.Cookies() {
		if c.Name == sessionCookie && c.Value != "" {
			sessC = c
		}
	}
	if sessC == nil {
		// denied path — no session issued; return the callback response
		return cbResp.StatusCode, string(cbBody), false
	}

	// 3. request real content with the session cookie
	contentReq, _ := http.NewRequest("GET", srv.URL+"/products.json", nil)
	contentReq.AddCookie(sessC)
	contentResp, err := client.Do(contentReq)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(contentResp.Body)
	contentResp.Body.Close()
	return contentResp.StatusCode, string(body), true
}

func TestProtectFullFlowAllowed(t *testing.T) {
	code, body, gotSession := runFlow(t, "z@hanzo.ai")
	if !gotSession {
		t.Fatalf("allowed user got no session; callback body: %s", body)
	}
	if code != 200 || !strings.Contains(body, realMarker) {
		t.Fatalf("allowed user should see real content, got status %d body %q", code, body)
	}
}

func TestProtectFullFlowDenied(t *testing.T) {
	code, body, gotSession := runFlow(t, "intruder@evil.com")
	if gotSession {
		t.Fatal("non-allow-listed user must NOT get a session")
	}
	if code != http.StatusForbidden {
		t.Errorf("denied callback status = %d, want 403", code)
	}
	if !strings.Contains(body, "spa-protect-gate") {
		t.Errorf("denied user should see the gate, got %q", body)
	}
	if strings.Contains(body, realMarker) {
		t.Error("denied user must not see real content")
	}
}

// --- missing-asset hardening (independent of protect mode) -------------------

func TestMissingAssetIsNotShell(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "index.html"), []byte("SHELL"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "img"), 0755); err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(spaHandler(dir))
	defer srv.Close()

	// Missing asset paths must 404, not serve the SPA shell.
	for _, path := range []string{"/img/missing.png", "/fonts/none.woff2", "/app.js", "/style.css"} {
		code, body := getBody(t, srv.URL+path)
		if code != 404 {
			t.Errorf("%s: status = %d, want 404", path, code)
		}
		if strings.Contains(body, "SHELL") {
			t.Errorf("%s: served the SPA shell instead of 404: %q", path, body)
		}
	}

	// A real client route (no extension) still falls through to index.html.
	code, body := getBody(t, srv.URL+"/shop")
	if code != 200 {
		t.Errorf("/shop: status = %d, want 200", code)
	}
	if body != "SHELL" {
		t.Errorf("/shop: body = %q, want SHELL (client route → index.html)", body)
	}
}

// --- config.json must never leak a secret ------------------------------------

// config.json is served to browsers. The protect secrets are non-SPA_ so they
// are never templated, and any SPA_* key that looks like a secret is dropped.
// Browser-safe SPA_* vars (including SPA_COMMERCE_TOKEN) must still appear.
func TestRuntimeConfigExcludesSecrets(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "config.json"), []byte(`{"v":1}`), 0644); err != nil {
		t.Fatal(err)
	}

	// Secrets — must NOT appear in config.json.
	t.Setenv("PROTECT_CLIENT_SECRET", "OIDC-CLIENT-SECRET-VALUE") // non-SPA_
	t.Setenv("PROTECT_COOKIE_SECRET", "COOKIE-HMAC-KEY-VALUE")    // non-SPA_
	t.Setenv("SPA_PROTECT_CLIENT_SECRET", "LEGACY-SPA-SECRET")    // SPA_ + SECRET → filtered
	t.Setenv("SPA_DB_PASSWORD", "DB-PASSWORD-VALUE")              // SPA_ + PASSWORD → filtered
	t.Setenv("SPA_TLS_PRIVATE_KEY", "PRIVATE-KEY-VALUE")          // SPA_ + PRIVATE → filtered
	// Browser-safe — MUST appear.
	t.Setenv("SPA_API_HOST", "https://api.example.com")
	t.Setenv("SPA_COMMERCE_TOKEN", "PUBLISHED-COMMERCE-TOKEN") // TOKEN is intentionally allowed

	if err := writeRuntimeConfig(dir, false); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(dir, "config.json"))
	if err != nil {
		t.Fatal(err)
	}
	got := string(raw)

	for _, leak := range []string{
		"OIDC-CLIENT-SECRET-VALUE", "COOKIE-HMAC-KEY-VALUE",
		"LEGACY-SPA-SECRET", "DB-PASSWORD-VALUE", "PRIVATE-KEY-VALUE",
	} {
		if strings.Contains(got, leak) {
			t.Errorf("config.json LEAKED a secret value %q:\n%s", leak, got)
		}
	}
	// And parse it to be sure no camelCased secret keys slipped in.
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("config.json invalid: %v\n%s", err, got)
	}
	for _, k := range []string{"protectClientSecret", "dbPassword", "tlsPrivateKey"} {
		if _, ok := m[k]; ok {
			t.Errorf("config.json contains sensitive key %q", k)
		}
	}
	// Browser-safe vars survive.
	if m["apiHost"] != "https://api.example.com" {
		t.Errorf("apiHost missing/wrong: %v", m["apiHost"])
	}
	if m["commerceToken"] != "PUBLISHED-COMMERCE-TOKEN" {
		t.Errorf("SPA_COMMERCE_TOKEN must survive (browser-safe Published token): %v", m["commerceToken"])
	}
}
