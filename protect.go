package main

// Protect mode — native OIDC auth gate for hanzoai/spa.
//
// When SPA_PROTECT=iam is set, ANY static site served by this image is locked
// behind Hanzo IAM (hanzo.id) OIDC. Anonymous visitors see ONLY a minimal
// white sign-in gate — never a real asset byte, never real markup. Only
// allow-listed admin emails get through, after Authorization-Code + PKCE
// sign-in. Fail-closed everywhere.
//
// Design: one middleware wraps the ENTIRE mux (see (*protect).wrap). The mux
// itself is untouched, so with SPA_PROTECT unset the wrap is a no-op and
// behavior is byte-for-byte identical. This keeps the protect concern in one
// place (this file) — orthogonal to static serving.
//
// Config (env). The SPA_ prefix means "browser-safe": writeRuntimeConfig
// templates every SPA_* var into /public/config.json, which is SERVED to
// visitors. So the two secrets deliberately DROP the SPA_ prefix — the Go
// server reads them via os.Getenv directly and they never reach config.json.
// (writeRuntimeConfig also drops any SPA_* key containing SECRET/PASSWORD/
// PRIVATE as belt-and-suspenders.)
//   SPA_PROTECT=iam                     enable (empty/unset = disabled)          [browser-safe]
//   SPA_PROTECT_ALLOW=a@x,b@x           comma emails, case-insensitive; empty = gate everyone
//   SPA_IAM_HOST=https://hanzo.id       OIDC issuer (reuses existing SPA_IAM_HOST) [browser-safe]
//   SPA_PROTECT_CLIENT_ID               confidential OIDC client id (public)
//   SPA_PROTECT_REDIRECT                optional; default https://<Host>/auth/callback
//   SPA_PROTECT_BRAND                   optional wordmark on the gate (brand-neutral if unset)
//   PROTECT_CLIENT_SECRET               *** SECRET *** OIDC client secret (env only, k8s Secret; NON-SPA_)
//   PROTECT_COOKIE_SECRET               *** SECRET *** HMAC key for session cookie; random if unset (NON-SPA_)

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

const (
	sessionCookie = "spa_session" // signed {email|exp} — proves an authorized session
	authCookie    = "spa_auth"    // signed {verifier|state} — short-lived PKCE transaction
	sessionTTL    = 8 * time.Hour
	authTTL       = 10 * time.Minute
)

type protect struct {
	enabled      bool
	iamHost      string
	clientID     string
	clientSecret string
	redirect     string // SPA_PROTECT_REDIRECT override; "" = derive per-request
	brand        string
	// internalHost (SPA_IAM_INTERNAL) is an in-cluster IAM base URL used for the
	// SERVER-SIDE calls (discovery, token, userinfo) so they bypass the public
	// CDN/WAF in front of the IdP — no edge rate-limit/IP-ban, no edge TLS. The
	// browser-facing authorize endpoint always stays on the public SPA_IAM_HOST.
	internalHost string
	allow        map[string]bool // lowercased allowed emails; empty = nobody passes
	cookieSecret []byte
	client       *http.Client

	authorizeEndpoint string
	tokenEndpoint     string
	userinfoEndpoint  string
	jwksURI           string
}

// loadProtect reads env and, when SPA_PROTECT=iam, returns a configured gate.
// Returns nil when disabled so the caller keeps the mux untouched. Never fails
// open: misconfiguration (missing creds, empty allow-list) still gates everyone.
func loadProtect() *protect {
	if !strings.EqualFold(strings.TrimSpace(os.Getenv("SPA_PROTECT")), "iam") {
		return nil
	}
	p := &protect{
		enabled:  true,
		iamHost:  strings.TrimRight(envOr("SPA_IAM_HOST", "https://hanzo.id"), "/"),
		clientID: os.Getenv("SPA_PROTECT_CLIENT_ID"),
		// Secrets are intentionally NON-SPA_ so writeRuntimeConfig never
		// templates them into the browser-served /public/config.json.
		clientSecret: os.Getenv("PROTECT_CLIENT_SECRET"),
		redirect:     strings.TrimSpace(os.Getenv("SPA_PROTECT_REDIRECT")),
		brand:        strings.TrimSpace(os.Getenv("SPA_PROTECT_BRAND")),
		internalHost: strings.TrimRight(strings.TrimSpace(os.Getenv("SPA_IAM_INTERNAL")), "/"),
		allow:        parseAllow(os.Getenv("SPA_PROTECT_ALLOW")),
		client:       &http.Client{Timeout: 10 * time.Second},
	}
	if s := os.Getenv("PROTECT_COOKIE_SECRET"); s != "" {
		p.cookieSecret = []byte(s)
	} else {
		b := make([]byte, 32)
		if _, err := rand.Read(b); err != nil {
			log.Fatalf("spa: protect: crypto/rand unavailable: %v", err)
		}
		p.cookieSecret = b
		log.Print("spa: protect: PROTECT_COOKIE_SECRET unset — generated an ephemeral key; sessions will NOT survive a restart. Set it (from a k8s Secret) in production.")
	}

	p.discover()

	if p.clientID == "" || p.clientSecret == "" {
		log.Print("spa: protect: SPA_PROTECT_CLIENT_ID/PROTECT_CLIENT_SECRET missing — sign-in cannot complete (fail-closed: everyone stays gated).")
	}
	if len(p.allow) == 0 {
		log.Print("spa: protect: SPA_PROTECT_ALLOW is empty — fail-closed: no user can pass the gate.")
	}
	return p
}

// parseAllow builds a case-insensitive set from a comma list.
func parseAllow(s string) map[string]bool {
	m := map[string]bool{}
	for _, part := range strings.Split(s, ",") {
		e := strings.ToLower(strings.TrimSpace(part))
		if e != "" {
			m[e] = true
		}
	}
	return m
}

// discover reads ${iamHost}/.well-known/openid-configuration and caches the
// endpoints. On any failure it falls back to the Hanzo IAM gateway convention
// (/v1/iam/oauth/*) — verified live against hanzo.id and shared by lux.id /
// zoo.id. (Raw upstream Casdoor paths like /login/oauth/authorize are NOT
// reachable through the gateway, so they would be a broken fallback.)
func (p *protect) discover() {
	// srv = host for SERVER-SIDE calls (token/userinfo/discovery): internal when
	// set, else the public host. authorize is ALWAYS public (the browser hits it).
	srv := p.iamHost
	if p.internalHost != "" {
		srv = p.internalHost
	}
	p.authorizeEndpoint = p.iamHost + "/v1/iam/oauth/authorize"
	p.tokenEndpoint = srv + "/v1/iam/oauth/token"
	p.userinfoEndpoint = srv + "/v1/iam/oauth/userinfo"
	p.jwksURI = srv + "/v1/iam/.well-known/jwks"

	// Discover from the server-side host so a public-edge ban can't break startup.
	// Casdoor returns its PUBLIC origin URLs in the doc, so authorize stays public;
	// we pin token/userinfo back onto srv (internal) below.
	resp, err := p.client.Get(srv + "/.well-known/openid-configuration")
	if err != nil {
		log.Printf("spa: protect: OIDC discovery failed (%v) — using gateway defaults", err)
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		log.Printf("spa: protect: OIDC discovery HTTP %d — using gateway defaults", resp.StatusCode)
		return
	}
	var d struct {
		AuthorizationEndpoint string `json:"authorization_endpoint"`
		TokenEndpoint         string `json:"token_endpoint"`
		UserinfoEndpoint      string `json:"userinfo_endpoint"`
		JwksURI               string `json:"jwks_uri"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&d); err != nil {
		log.Printf("spa: protect: OIDC discovery decode failed (%v) — using gateway defaults", err)
		return
	}
	// authorize stays PUBLIC (browser-facing). token/userinfo/jwks are pinned to
	// srv (internal when SPA_IAM_INTERNAL is set) by swapping the discovered URL's
	// host — so server-side calls never traverse the public edge.
	if d.AuthorizationEndpoint != "" {
		p.authorizeEndpoint = d.AuthorizationEndpoint
	}
	if d.TokenEndpoint != "" {
		p.tokenEndpoint = onHost(d.TokenEndpoint, srv)
	}
	if d.UserinfoEndpoint != "" {
		p.userinfoEndpoint = onHost(d.UserinfoEndpoint, srv)
	}
	if d.JwksURI != "" {
		p.jwksURI = onHost(d.JwksURI, srv)
	}
	log.Printf("spa: protect: OIDC endpoints — authorize=%s token=%s userinfo=%s", p.authorizeEndpoint, p.tokenEndpoint, p.userinfoEndpoint)
}

// onHost returns rawURL with its scheme+host replaced by base's (path/query
// preserved). Used to pin discovered token/userinfo endpoints onto the internal
// IAM host. Returns rawURL unchanged if base or rawURL is unparseable.
func onHost(rawURL, base string) string {
	if base == "" {
		return rawURL
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		return rawURL
	}
	b, err := url.Parse(base)
	if err != nil || b.Host == "" {
		return rawURL
	}
	u.Scheme = b.Scheme
	u.Host = b.Host
	return u.String()
}

// wrap installs the gate in front of next. Nil/disabled → next unchanged, so
// SPA_PROTECT unset is a byte-for-byte no-op.
func (p *protect) wrap(next http.Handler) http.Handler {
	if p == nil || !p.enabled {
		return next
	}
	log.Printf("spa: PROTECT MODE ON — issuer=%s allow=%d emails (fail-closed)", p.iamHost, len(p.allow))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/health": // liveness/readiness probes are NEVER gated
			next.ServeHTTP(w, r)
			return
		case "/auth/login":
			p.handleLogin(w, r)
			return
		case "/auth/callback":
			p.handleCallback(w, r)
			return
		case "/auth/logout":
			p.handleLogout(w, r)
			return
		}
		if email, ok := p.session(r); ok && p.allowed(email) {
			// Authorized — serve the real content, but force Cache-Control:
			// no-store so a SHARED cache (Cloudflare) never stores a protected
			// asset and later hands it to an anonymous visitor. Without this, an
			// authed admin's asset fetch (the static handler sets max-age=86400
			// for css/js/img) would populate the CDN edge and leak content past
			// the gate. The site is admin-only + low-traffic while protected, so
			// dropping edge caching costs nothing; public launch (SPA_PROTECT
			// unset) restores normal caching.
			next.ServeHTTP(&noStoreWriter{ResponseWriter: w}, r)
			return
		}
		// Anything else, any method, any extension → gate only. No real byte leaks.
		p.serveGate(w, http.StatusOK, "")
	})
}

func (p *protect) allowed(email string) bool {
	return p.allow[strings.ToLower(strings.TrimSpace(email))]
}

// noStoreWriter forces Cache-Control: no-store on the wrapped response. It wraps
// the authed passthrough so a shared CDN never caches protected content and then
// serves it to an anonymous visitor. The override is applied at WriteHeader time
// (after the static handler set its own Cache-Control), so no-store always wins.
type noStoreWriter struct {
	http.ResponseWriter
	wrote bool
}

func (w *noStoreWriter) WriteHeader(code int) {
	w.Header().Set("Cache-Control", "no-store")
	w.wrote = true
	w.ResponseWriter.WriteHeader(code)
}

func (w *noStoreWriter) Write(b []byte) (int, error) {
	if !w.wrote {
		w.WriteHeader(http.StatusOK)
	}
	return w.ResponseWriter.Write(b)
}

// handleLogin starts the Authorization-Code + PKCE flow: mint verifier/state,
// stash them in a signed short-lived cookie, redirect to the IAM authorize URL.
func (p *protect) handleLogin(w http.ResponseWriter, r *http.Request) {
	verifier := randToken(32)
	sum := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(sum[:])
	state := randToken(24)

	p.setCookie(w, authCookie, p.sign([]byte(verifier+"|"+state)), int(authTTL.Seconds()))

	q := url.Values{}
	q.Set("client_id", p.clientID)
	q.Set("redirect_uri", p.redirectURI(r))
	q.Set("response_type", "code")
	q.Set("scope", "openid profile email")
	q.Set("state", state)
	q.Set("code_challenge", challenge)
	q.Set("code_challenge_method", "S256")

	w.Header().Set("Cache-Control", "no-store")
	http.Redirect(w, r, p.authorizeEndpoint+"?"+q.Encode(), http.StatusFound)
}

// handleCallback verifies state, exchanges the code (PKCE), reads the email from
// userinfo, checks the allow-list, and on success mints the session cookie.
func (p *protect) handleCallback(w http.ResponseWriter, r *http.Request) {
	c, err := r.Cookie(authCookie)
	if err != nil {
		p.serveGate(w, http.StatusForbidden, "Sign-in expired. Please try again.")
		return
	}
	p.clearCookie(w, authCookie) // single-use PKCE transaction
	payload, ok := p.unsign(c.Value)
	if !ok {
		p.serveGate(w, http.StatusForbidden, "Sign-in could not be verified. Please try again.")
		return
	}
	verifier, wantState, ok := strings.Cut(string(payload), "|")
	if !ok {
		p.serveGate(w, http.StatusForbidden, "Sign-in could not be verified. Please try again.")
		return
	}
	gotState := r.URL.Query().Get("state")
	if gotState == "" || subtle.ConstantTimeCompare([]byte(gotState), []byte(wantState)) != 1 {
		p.serveGate(w, http.StatusForbidden, "Sign-in state mismatch. Please try again.")
		return
	}
	code := r.URL.Query().Get("code")
	if code == "" {
		p.serveGate(w, http.StatusForbidden, "Sign-in failed. Please try again.")
		return
	}

	email, err := p.exchange(r.Context(), code, verifier, p.redirectURI(r))
	if err != nil {
		log.Printf("spa: protect: token/userinfo exchange failed: %v", err)
		p.serveGate(w, http.StatusForbidden, "Sign-in failed. Please try again.")
		return
	}
	if !p.allowed(email) {
		log.Printf("spa: protect: denied non-allow-listed email %q", email)
		p.serveGate(w, http.StatusForbidden, "That account is not authorized.")
		return
	}

	exp := time.Now().Add(sessionTTL).Unix()
	p.setCookie(w, sessionCookie, p.sign([]byte(email+"|"+strconv.FormatInt(exp, 10))), int(sessionTTL.Seconds()))
	w.Header().Set("Cache-Control", "no-store")
	http.Redirect(w, r, "/", http.StatusFound)
}

func (p *protect) handleLogout(w http.ResponseWriter, r *http.Request) {
	p.clearCookie(w, sessionCookie)
	w.Header().Set("Cache-Control", "no-store")
	http.Redirect(w, r, "/", http.StatusFound)
}

// exchange trades the authorization code for tokens (client_secret_post +
// PKCE verifier), then reads the email from the userinfo endpoint.
//
// Why userinfo, not local id_token verification: hanzo.id advertises MLDSA65
// (post-quantum ML-DSA) among its id_token signing algs, which the Go standard
// library cannot verify — and JWKS/JWT verification adds alg-confusion and
// key-rotation surface. The access token fetches identity directly from the
// IdP's userinfo endpoint over a server-to-server TLS channel that already
// authenticates the issuer, making the response the authoritative identity with
// minimal crypto surface. This is the robust choice.
func (p *protect) exchange(ctx context.Context, code, verifier, redirect string) (string, error) {
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("redirect_uri", redirect)
	form.Set("client_id", p.clientID)
	form.Set("client_secret", p.clientSecret) // client_secret_post (advertised by hanzo.id)
	form.Set("code_verifier", verifier)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.tokenEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := p.client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("token endpoint HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	var tok struct {
		AccessToken string `json:"access_token"`
		IDToken     string `json:"id_token"`
		TokenType   string `json:"token_type"`
		Error       string `json:"error"`
	}
	if err := json.Unmarshal(body, &tok); err != nil {
		return "", fmt.Errorf("token response decode: %w", err)
	}
	if tok.Error != "" {
		return "", fmt.Errorf("token endpoint error: %s", tok.Error)
	}
	if tok.AccessToken == "" {
		return "", fmt.Errorf("token endpoint returned no access_token")
	}
	// Prefer userinfo (authoritative). Fall back to the id_token's email claim
	// when the IdP's userinfo omits it (e.g. Casdoor scope-filters email out of
	// /userinfo even though the token was minted with the email scope). The
	// id_token rode the SAME TLS-authenticated token-endpoint response, so its
	// claims are as trustworthy as userinfo for the email; we decode (not
	// signature-verify) the payload — verification is unnecessary and would drag
	// in the IdP's ML-DSA id_token signing alg the Go stdlib can't check.
	email, err := p.userinfo(ctx, tok.AccessToken)
	if (err != nil || email == "") && tok.IDToken != "" {
		if e := emailFromJWT(tok.IDToken); e != "" {
			return e, nil
		}
	}
	return email, err
}

// emailFromJWT decodes (without verifying) the payload of a compact JWS and
// returns its "email" claim, or "" if absent/malformed. Trust comes from the
// caller having fetched the token over an authenticated TLS channel to the IdP.
func emailFromJWT(jwt string) string {
	parts := strings.Split(jwt, ".")
	if len(parts) < 2 {
		return ""
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return ""
	}
	var claims struct {
		Email string `json:"email"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return ""
	}
	return strings.TrimSpace(claims.Email)
}

func (p *protect) userinfo(ctx context.Context, accessToken string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.userinfoEndpoint, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Accept", "application/json")

	resp, err := p.client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("userinfo HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	var u struct {
		Email string `json:"email"`
	}
	if err := json.Unmarshal(body, &u); err != nil {
		return "", fmt.Errorf("userinfo decode: %w", err)
	}
	if strings.TrimSpace(u.Email) == "" {
		return "", fmt.Errorf("userinfo returned no email")
	}
	return u.Email, nil
}

// session returns the authorized email from a valid, unexpired session cookie.
func (p *protect) session(r *http.Request) (string, bool) {
	c, err := r.Cookie(sessionCookie)
	if err != nil {
		return "", false
	}
	payload, ok := p.unsign(c.Value)
	if !ok {
		return "", false
	}
	email, expStr, ok := strings.Cut(string(payload), "|")
	if !ok {
		return "", false
	}
	exp, err := strconv.ParseInt(expStr, 10, 64)
	if err != nil || time.Now().Unix() > exp {
		return "", false
	}
	return strings.ToLower(email), true
}

// redirectURI is the OIDC callback: the SPA_PROTECT_REDIRECT override, else
// https://<Host>/auth/callback. https is forced — the public callback is always
// served over TLS by the ingress even though the pod speaks plain HTTP.
func (p *protect) redirectURI(r *http.Request) string {
	if p.redirect != "" {
		return p.redirect
	}
	return "https://" + r.Host + "/auth/callback"
}

// sign returns base64url(payload)"."base64url(HMAC-SHA256(payload)).
func (p *protect) sign(payload []byte) string {
	mac := hmac.New(sha256.New, p.cookieSecret)
	mac.Write(payload)
	return base64.RawURLEncoding.EncodeToString(payload) + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

// unsign verifies the HMAC (constant-time) and returns the payload.
func (p *protect) unsign(token string) ([]byte, bool) {
	dot := strings.LastIndexByte(token, '.')
	if dot <= 0 {
		return nil, false
	}
	payload, err := base64.RawURLEncoding.DecodeString(token[:dot])
	if err != nil {
		return nil, false
	}
	sig, err := base64.RawURLEncoding.DecodeString(token[dot+1:])
	if err != nil {
		return nil, false
	}
	mac := hmac.New(sha256.New, p.cookieSecret)
	mac.Write(payload)
	if !hmac.Equal(sig, mac.Sum(nil)) {
		return nil, false
	}
	return payload, true
}

func (p *protect) setCookie(w http.ResponseWriter, name, value string, maxAge int) {
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    value,
		Path:     "/",
		MaxAge:   maxAge,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode, // Lax: cookie rides the top-level GET back from IAM
	})
}

func (p *protect) clearCookie(w http.ResponseWriter, name string) {
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})
}

// randToken returns n bytes of crypto-random data as base64url. Empty on the
// (essentially impossible) rand failure, which fails the flow closed.
func randToken(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return ""
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

// serveGate writes the self-contained white sign-in page. It reuses the shared
// security headers (frame-ancestors 'none', nosniff, HSTS) and is never cached,
// so a CDN can't hand one user's gate/content to another.
func (p *protect) serveGate(w http.ResponseWriter, status int, note string) {
	setSecurityHeaders(w, false)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	io.WriteString(w, p.gateHTML(note))
}

// gateHTML is fully self-contained: inline CSS, no external refs, no real
// markup or asset bytes from the protected site. The id="spa-protect-gate"
// hook is a stable marker for tests and ops.
func (p *protect) gateHTML(note string) string {
	brand := "Protected"
	if p.brand != "" {
		brand = p.brand
	}
	noteHTML := ""
	if note != "" {
		noteHTML = `<p class="note">` + html.EscapeString(note) + `</p>`
	}
	return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex, nofollow">
<title>Sign in</title>
<style>
:root{color-scheme:light}
*{box-sizing:border-box}
html,body{height:100%;margin:0}
body{display:flex;align-items:center;justify-content:center;background:#fff;
font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;
color:#111;-webkit-font-smoothing:antialiased}
main{width:100%;max-width:340px;padding:32px;text-align:center}
.mark{font-size:22px;font-weight:600;letter-spacing:-.01em;margin:0 0 4px}
.sub{font-size:14px;color:#666;margin:0 0 28px}
a.btn{display:inline-block;width:100%;padding:12px 16px;border-radius:10px;
background:#111;color:#fff;text-decoration:none;font-size:15px;font-weight:500;
transition:opacity .15s ease}
a.btn:hover{opacity:.85}
.note{margin:20px 0 0;font-size:13px;color:#b00020}
.lock{width:40px;height:40px;margin:0 auto 20px;display:block;opacity:.9}
</style>
</head>
<body>
<main id="spa-protect-gate" role="main">
<svg class="lock" viewBox="0 0 24 24" fill="none" stroke="#111" stroke-width="1.6" aria-hidden="true">
<rect x="4" y="10" width="16" height="11" rx="2"></rect>
<path d="M8 10V7a4 4 0 0 1 8 0v3"></path>
</svg>
<h1 class="mark">` + html.EscapeString(brand) + `</h1>
<p class="sub">Please sign in to continue.</p>
<a class="btn" href="/auth/login" rel="nofollow">Sign in</a>
` + noteHTML + `
</main>
</body>
</html>
`
}
