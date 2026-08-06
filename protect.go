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
	"bytes"
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
	idTokenCookie = "spa_id"      // the IdP's raw id_token — kept ONLY as id_token_hint for RP-initiated logout
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

	authorizeEndpoint  string
	tokenEndpoint      string
	userinfoEndpoint   string
	jwksURI            string
	endSessionEndpoint string // RP-initiated logout (browser-facing, public)
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
	// end-session is BROWSER-facing (the user's browser is redirected to it to
	// drop the IdP SSO session), so it always stays on the PUBLIC host.
	p.endSessionEndpoint = p.iamHost + "/v1/iam/oauth/logout"

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
		EndSessionEndpoint    string `json:"end_session_endpoint"`
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
	if d.EndSessionEndpoint != "" {
		p.endSessionEndpoint = d.EndSessionEndpoint // browser-facing → keep public host
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
			//
			// injectWriter also drops an unobtrusive floating "Sign out" link into
			// authorized HTML documents so any user can switch accounts without the
			// site needing to know about protect mode (reusable, site-agnostic).
			iw := &injectWriter{ResponseWriter: w, snippet: signOutSnippet}
			next.ServeHTTP(iw, r)
			iw.finalize()
			return
		}
		// Anything else, any method, any extension → gate only. No real byte leaks.
		p.serveGate(w, http.StatusOK, "")
	})
}

func (p *protect) allowed(email string) bool {
	return p.allow[strings.ToLower(strings.TrimSpace(email))]
}

// signOutSnippet is the unobtrusive floating "Sign out" affordance injected into
// authorized HTML so any signed-in user can switch accounts — no site cooperation
// needed (reusable, site-agnostic). Self-contained inline styles, fixed bottom-right.
var signOutSnippet = []byte(`<a href="/auth/logout" rel="nofollow" aria-label="Sign out" ` +
	`style="position:fixed;bottom:14px;right:14px;z-index:2147483000;` +
	`font:500 12px/1 -apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif;` +
	`color:#111;background:rgba(255,255,255,.92);border:1px solid rgba(0,0,0,.14);` +
	`border-radius:8px;padding:8px 12px;text-decoration:none;box-shadow:0 1px 3px rgba(0,0,0,.12);opacity:.85">` +
	`Sign out</a>`)

// injectWriter forces Cache-Control: no-store on every authorized response (so a
// shared CDN never caches protected content and later serves it to an anonymous
// visitor) AND, for 200 text/html documents, injects `snippet` before </body> so a
// signed-in user always has a sign-out affordance. Non-HTML / non-200 responses
// stream through untouched (no buffering).
type injectWriter struct {
	http.ResponseWriter
	snippet []byte
	started bool
	isHTML  bool
	status  int
	buf     []byte
}

func (w *injectWriter) WriteHeader(code int) {
	if w.started {
		return
	}
	w.started = true
	w.Header().Set("Cache-Control", "no-store")
	if code == http.StatusOK && strings.HasPrefix(w.Header().Get("Content-Type"), "text/html") {
		w.isHTML = true
		w.status = code
		w.Header().Del("Content-Length") // recomputed after injection
		return                           // defer the real WriteHeader to finalize()
	}
	w.ResponseWriter.WriteHeader(code)
}

func (w *injectWriter) Write(b []byte) (int, error) {
	if !w.started {
		w.WriteHeader(http.StatusOK)
	}
	if w.isHTML {
		w.buf = append(w.buf, b...)
		return len(b), nil
	}
	return w.ResponseWriter.Write(b)
}

// finalize must run after the wrapped handler returns: for a buffered HTML document
// it injects the snippet and flushes; a no-op for anything streamed through.
func (w *injectWriter) finalize() {
	if !w.isHTML {
		return
	}
	out := injectBefore(w.buf, []byte("</body>"), w.snippet)
	w.Header().Set("Content-Length", strconv.Itoa(len(out)))
	w.ResponseWriter.WriteHeader(w.status)
	w.ResponseWriter.Write(out)
}

// injectBefore inserts snip before the LAST case-insensitive occurrence of marker
// in body (appends if marker is absent).
func injectBefore(body, marker, snip []byte) []byte {
	i := bytes.LastIndex(bytes.ToLower(body), bytes.ToLower(marker))
	if i < 0 {
		return append(body, snip...)
	}
	out := make([]byte, 0, len(body)+len(snip))
	out = append(out, body[:i]...)
	out = append(out, snip...)
	out = append(out, body[i:]...)
	return out
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

	email, idToken, err := p.exchange(r.Context(), code, verifier, p.redirectURI(r))
	if err != nil {
		log.Printf("spa: protect: token/userinfo exchange failed: %v", err)
		p.serveGate(w, http.StatusForbidden, "Sign-in failed. Please try again.")
		return
	}
	// Retain the IdP id_token as id_token_hint for RP-initiated logout — set for
	// BOTH allowed AND denied users, so the denied gate's "sign out & try another
	// account" can actually drop the IdP SSO session. httpOnly/Secure; it is opaque
	// to us and NEVER trusted for authorization (identity is the userinfo email).
	if idToken != "" {
		p.setCookie(w, idTokenCookie, idToken, int(sessionTTL.Seconds()))
	}
	if !p.allowed(email) {
		log.Printf("spa: protect: denied non-allow-listed email %q", email)
		p.serveDenied(w, email)
		return
	}

	exp := time.Now().Add(sessionTTL).Unix()
	p.setCookie(w, sessionCookie, p.sign([]byte(email+"|"+strconv.FormatInt(exp, 10))), int(sessionTTL.Seconds()))
	w.Header().Set("Cache-Control", "no-store")
	http.Redirect(w, r, "/", http.StatusFound)
}

func (p *protect) handleLogout(w http.ResponseWriter, r *http.Request) {
	// Read the stored id_token BEFORE clearing — it's the id_token_hint below.
	idToken := ""
	if c, err := r.Cookie(idTokenCookie); err == nil {
		idToken = c.Value
	}
	// Clear ALL of our cookies (session + in-flight PKCE + the id_token hint).
	p.clearCookie(w, sessionCookie)
	p.clearCookie(w, authCookie)
	p.clearCookie(w, idTokenCookie)
	w.Header().Set("Cache-Control", "no-store")

	gate := "https://" + r.Host + "/"
	// RP-initiated logout: bounce through the IdP end-session endpoint so the IdP's
	// OWN SSO session drops too — otherwise the next sign-in is silently re-authorized
	// as the same (possibly rejected) account, an infinite dead-end. hanzo.id REQUIRES
	// id_token_hint and returns raw JSON ({"msg":"Missing parameter: id_token_hint"})
	// without it, so we take the IdP round-trip ONLY when we hold the hint;
	// post_logout_redirect_uri brings the browser back to our white gate.
	if idToken != "" && p.endSessionEndpoint != "" {
		q := url.Values{}
		q.Set("id_token_hint", idToken)
		q.Set("post_logout_redirect_uri", gate)
		if p.clientID != "" {
			q.Set("client_id", p.clientID)
		}
		http.Redirect(w, r, p.endSessionEndpoint+"?"+q.Encode(), http.StatusFound)
		return
	}
	// No id_token (expired, or too large to have stored) → NEVER strand the user on
	// the IdP's raw-JSON error. Our cookies are already cleared, so just go home to
	// the gate; signing in there re-authenticates cleanly.
	http.Redirect(w, r, gate, http.StatusFound)
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
func (p *protect) exchange(ctx context.Context, code, verifier, redirect string) (string, string, error) {
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("redirect_uri", redirect)
	form.Set("client_id", p.clientID)
	form.Set("client_secret", p.clientSecret) // client_secret_post (advertised by hanzo.id)
	form.Set("code_verifier", verifier)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.tokenEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return "", "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := p.client.Do(req)
	if err != nil {
		return "", "", err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		return "", "", fmt.Errorf("token endpoint HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	var tok struct {
		AccessToken string `json:"access_token"`
		IDToken     string `json:"id_token"`
		TokenType   string `json:"token_type"`
		Error       string `json:"error"`
	}
	if err := json.Unmarshal(body, &tok); err != nil {
		return "", "", fmt.Errorf("token response decode: %w", err)
	}
	if tok.Error != "" {
		return "", "", fmt.Errorf("token endpoint error: %s", tok.Error)
	}
	if tok.AccessToken == "" {
		return "", "", fmt.Errorf("token endpoint returned no access_token")
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
			return e, tok.IDToken, nil
		}
	}
	return email, tok.IDToken, err
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

// gateView selects which gate to render. deniedEmail non-empty → the "not
// authorized" variant (shows the rejected account + a working sign-out), so the
// unauthorized state is never a dead end.
type gateView struct {
	note        string
	deniedEmail string
}

// serveGate writes the self-contained white sign-in page. It reuses the shared
// security headers (frame-ancestors 'none', nosniff, HSTS) and is never cached,
// so a CDN can't hand one user's gate/content to another.
func (p *protect) serveGate(w http.ResponseWriter, status int, note string) {
	p.renderGate(w, status, gateView{note: note})
}

// serveDenied renders the "signed in as X — not on the allow list" gate whose
// primary action signs the user OUT (local cookies + IdP session) and returns to
// the gate, so a rejected account can switch to an allowed one.
func (p *protect) serveDenied(w http.ResponseWriter, email string) {
	p.renderGate(w, http.StatusForbidden, gateView{deniedEmail: email})
}

func (p *protect) renderGate(w http.ResponseWriter, status int, v gateView) {
	setSecurityHeaders(w, false)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	io.WriteString(w, p.gateHTML(v))
}

// gateHTML is fully self-contained: inline CSS, no external refs, no real
// markup or asset bytes from the protected site. The id="spa-protect-gate"
// hook is a stable marker for tests and ops.
func (p *protect) gateHTML(v gateView) string {
	brand := "Protected"
	if p.brand != "" {
		brand = p.brand
	}
	title := "Sign in"
	sub := "Please sign in to continue."
	action := `<a class="btn" href="/auth/login" rel="nofollow">Sign in</a>`
	if v.deniedEmail != "" {
		title = "Not authorized"
		sub = `Signed in as <b>` + html.EscapeString(v.deniedEmail) + `</b> — that account isn't on the allow&#8209;list.`
		action = `<a class="btn" href="/auth/logout" rel="nofollow">Sign out &amp; try another account</a>`
	}
	noteHTML := ""
	if v.note != "" {
		noteHTML = `<p class="note">` + html.EscapeString(v.note) + `</p>`
	}
	return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex, nofollow">
<title>` + html.EscapeString(title) + `</title>
<style>
:root{color-scheme:light}
*{box-sizing:border-box}
html,body{height:100%;margin:0}
body{display:flex;align-items:center;justify-content:center;background:#fff;
font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;
color:#111;-webkit-font-smoothing:antialiased}
main{width:100%;max-width:340px;padding:32px;text-align:center}
.mark{font-size:22px;font-weight:600;letter-spacing:-.01em;margin:0 0 4px}
.sub{font-size:14px;color:#666;margin:0 0 28px;line-height:1.45}
.sub b{color:#111;font-weight:600}
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
<p class="sub">` + sub + `</p>
` + action + `
` + noteHTML + `
</main>
</body>
</html>
`
}
