package main

// Analytics mode — lightweight native page & SPA journey tracking for hanzoai/spa.
//
// Cooperates seamlessly with hanzo/ingress (pkg/middlewares/analytics) without
// double-counting:
//   - When hanzo/ingress analytics is active in front of hanzo/spa, ingress sets
//     `X-Hanzo-Analytics-Ingress: 1` on navigation requests and records the
//     initial pageload at the edge. hanzo/spa sees that header, skips emitting a
//     duplicate server-side initial pageview, and handles subsequent SPA client
//     route-change beacons (`POST /_/beacon` or `POST /__spa/beacon`).
//   - When hanzo/spa runs standalone without ingress analytics, hanzo/spa records
//     the initial HTML navigation pageview itself AND forwards subsequent SPA
//     route-change beacons under the same `_hz_sid` session cookie.
//   - When `SPA_ANALYTICS_INJECT=true`, hanzo/spa injects a compact, CSP-friendly
//     route-observer snippet before `</body>` on 200 HTML documents that hooks
//     `history.pushState`, `history.replaceState`, and `popstate` to beacon
//     client-side route transitions to `/_/beacon`.
//
// Secrets stay out of `/public/config.json`: `ANALYTICS_API_KEY` deliberately
// drops the `SPA_` prefix so `writeRuntimeConfig` never exposes it to browsers.

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	spaIngressTrackedHeader = "X-Hanzo-Analytics-Ingress"
	spaTrackedHeader        = "X-Hanzo-Analytics-Tracked"
	spaBeaconPath           = "/_/beacon"
	spaAltBeaconPath        = "/__spa/beacon"
	spaMaxBeaconBytes       = 32 << 10 // 32 KiB
	spaSessionCookie        = "_hz_sid"
	spaAnonCookie           = "_hz_aid"
	spaSessionMaxAge        = 1800     // 30m sliding session window
	spaAnonMaxAge           = 31536000 // 1y anonymous visitor id
)

var (
	spaClickParams = []string{
		"gclid", "gbraid", "wbraid", "fbclid", "twclid", "li_fat_id", "ttclid",
	}
	spaClickCookies = []string{
		"_fbp", "_fbc", "_ttp", "li_fat_id",
	}
)

// spaAnalyticsConfig configures native SPA analytics forwarding.
type spaAnalyticsConfig struct {
	Endpoint      string
	HostHeader    string
	APIKey        string
	Environment   string
	InjectScript  bool
	BatchSize     int
	BufferSize    int
	FlushInterval time.Duration
	Transport     http.RoundTripper
}

func spaAnalyticsConfigFromEnv() spaAnalyticsConfig {
	endpoint := strings.TrimSpace(os.Getenv("ANALYTICS_ENDPOINT"))
	if endpoint == "" {
		endpoint = strings.TrimSpace(os.Getenv("SPA_ANALYTICS_ENDPOINT"))
	}
	env := strings.TrimSpace(os.Getenv("ANALYTICS_ENV"))
	if env == "" {
		env = strings.TrimSpace(os.Getenv("SPA_ENV"))
	}
	cfg := spaAnalyticsConfig{
		Endpoint:     endpoint,
		HostHeader:   strings.TrimSpace(os.Getenv("ANALYTICS_HOST")),
		APIKey:       strings.TrimSpace(os.Getenv("ANALYTICS_API_KEY")),
		Environment:  env,
		InjectScript: strings.EqualFold(strings.TrimSpace(os.Getenv("SPA_ANALYTICS_INJECT")), "true"),
	}
	if v := strings.TrimSpace(os.Getenv("ANALYTICS_BATCH_SIZE")); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			cfg.BatchSize = n
		}
	}
	if v := strings.TrimSpace(os.Getenv("ANALYTICS_FLUSH_INTERVAL")); v != "" {
		if d, err := time.ParseDuration(v); err == nil && d > 0 {
			cfg.FlushInterval = d
		}
	}
	return cfg
}

type spaUTM struct {
	Source   string `json:"source,omitempty"`
	Medium   string `json:"medium,omitempty"`
	Campaign string `json:"campaign,omitempty"`
	Term     string `json:"term,omitempty"`
	Content  string `json:"content,omitempty"`
}

// spaCaptureEvent matches cloud/apps/event.CaptureEvent wire shape for POST /v1/event.
type spaCaptureEvent struct {
	MessageID   string         `json:"messageId,omitempty"`
	Type        string         `json:"type"`
	Event       string         `json:"event"`
	Timestamp   string         `json:"timestamp"`
	DistinctID  string         `json:"distinctId,omitempty"`
	AnonymousID string         `json:"anonymousId,omitempty"`
	SessionID   string         `json:"sessionId,omitempty"`
	Product     string         `json:"product"`
	URL         string         `json:"url"`
	Path        string         `json:"path"`
	Referrer    string         `json:"referrer,omitempty"`
	UTM         spaUTM         `json:"utm,omitempty"`
	Site        string         `json:"site"`
	Environment string         `json:"environment,omitempty"`
	Service     string         `json:"service"`
	Properties  map[string]any `json:"properties,omitempty"`
	Library     string         `json:"library"`
	LibraryVer  string         `json:"libraryVersion"`
}

type spaCaptureBatch struct {
	Batch []spaCaptureEvent `json:"batch"`
}

// spaBeaconPayload is the lightweight JSON body accepted by POST /_/beacon.
type spaBeaconPayload struct {
	Event       string         `json:"event"`
	Type        string         `json:"type"`
	Hostname    string         `json:"hostname"`
	Path        string         `json:"path"`
	URL         string         `json:"url"`
	Referrer    string         `json:"referrer"`
	SessionID   string         `json:"sessionId"`
	AnonymousID string         `json:"anonymousId"`
	DistinctID  string         `json:"distinctId"`
	EventID     string         `json:"eventId"`
	Initial     bool           `json:"initial"`
	UTM         spaUTM         `json:"utm"`
	Properties  map[string]any `json:"properties"`
}

type spaAnalytics struct {
	cfg     spaAnalyticsConfig
	client  *http.Client
	ch      chan spaCaptureEvent
	wg      sync.WaitGroup
	once    sync.Once
	closed  atomic.Bool
	sent    atomic.Uint64
	dropped atomic.Uint64
	failed  atomic.Uint64
}

func loadAnalytics() *spaAnalytics {
	return newSPAAnalytics(spaAnalyticsConfigFromEnv())
}

func newSPAAnalytics(cfg spaAnalyticsConfig) *spaAnalytics {
	if strings.TrimSpace(cfg.Endpoint) == "" {
		return nil
	}
	if cfg.BatchSize <= 0 {
		cfg.BatchSize = 100
	}
	if cfg.BatchSize > 500 {
		cfg.BatchSize = 500
	}
	if cfg.BufferSize <= 0 {
		cfg.BufferSize = 2048
	}
	if cfg.FlushInterval <= 0 {
		cfg.FlushInterval = 2 * time.Second
	}
	tr := cfg.Transport
	if tr == nil {
		tr = &http.Transport{
			MaxIdleConns:        32,
			MaxIdleConnsPerHost: 16,
			IdleConnTimeout:     60 * time.Second,
		}
	}
	a := &spaAnalytics{
		cfg: cfg,
		client: &http.Client{
			Timeout:   5 * time.Second,
			Transport: tr,
		},
		ch: make(chan spaCaptureEvent, cfg.BufferSize),
	}
	a.wg.Add(1)
	go a.loop()
	return a
}

// spaRouteSnippet hooks client-side History API transitions and beacons them to /_/beacon.
// Initial pageload is already captured by ingress (or by spaAnalytics on HTML delivery),
// so the client snippet fires strictly on SPA route transitions — zero double-counting.
var spaRouteSnippet = []byte(`<script data-hz-spa-beacon>(function(){` +
	`if(window.__hzSpaBeacon)return;window.__hzSpaBeacon=1;` +
	`var last=location.pathname+location.search;` +
	`function send(prev){` +
	`var cur=location.pathname+location.search;if(cur===last)return;last=cur;` +
	`var q=new URLSearchParams(location.search);` +
	`var body=JSON.stringify({type:"pageview",event:"$pageview",hostname:location.hostname,path:location.pathname,url:location.href,referrer:prev||document.referrer||"",utm:{source:q.get("utm_source")||"",medium:q.get("utm_medium")||"",campaign:q.get("utm_campaign")||"",term:q.get("utm_term")||"",content:q.get("utm_content")||""}});` +
	`if(navigator.sendBeacon){try{navigator.sendBeacon("/_/beacon",new Blob([body],{type:"application/json"}));return}catch(e){}}` +
	`try{fetch("/_/beacon",{method:"POST",headers:{"Content-Type":"application/json"},body:body,keepalive:true,credentials:"same-origin"}).catch(function(){})}catch(e){}` +
	`}` +
	`var ps=history.pushState,rs=history.replaceState;` +
	`history.pushState=function(){var prev=location.href;ps.apply(this,arguments);send(prev)};` +
	`history.replaceState=function(){var prev=location.href;rs.apply(this,arguments);send(prev)};` +
	`addEventListener("popstate",function(){send("")});` +
	`})()</script>`)

func (a *spaAnalytics) wrap(next http.Handler) http.Handler {
	if a == nil {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == spaBeaconPath || r.URL.Path == spaAltBeaconPath {
			a.handleBeacon(w, r)
			return
		}
		if r.URL.Path == "/health" || strings.HasPrefix(r.URL.Path, "/auth/") {
			next.ServeHTTP(w, r)
			return
		}

		isNavCandidate := (r.Method == http.MethodGet || r.Method == http.MethodHead) &&
			!assetExtensions[strings.ToLower(extOfPath(r.URL.Path))] ||
			strings.HasSuffix(strings.ToLower(r.URL.Path), ".html")

		ingressTracked := r.Header.Get(spaIngressTrackedHeader) == "1"

		// Ensure session cookie exists on HTML navigations so subsequent SPA route
		// transitions share the same sessionId.
		sid, mintedSid := a.ensureSession(w, r)
		_, _ = sid, mintedSid

		if a.cfg.InjectScript && isNavCandidate && r.Method == http.MethodGet {
			// Inject route-change observer into uncompressed HTML responses; if
			// precompressed (.br/.gz), spaHTMLRecorder sees Content-Encoding != ""
			// and streams untouched.
			if ingressTracked {
				w.Header().Set(spaTrackedHeader, "ingress")
			} else {
				w.Header().Set(spaTrackedHeader, "spa")
			}
			rec := &spaHTMLRecorder{ResponseWriter: w, snippet: spaRouteSnippet}
			next.ServeHTTP(rec, r)
			rec.finalize()
			if rec.status == http.StatusOK && rec.isHTML && !ingressTracked {
				a.enqueue(a.buildServerNavEvent(r, sid))
			}
			return
		}

		rec := &spaStatusRecorder{ResponseWriter: w, status: http.StatusOK}
		if ingressTracked {
			w.Header().Set(spaTrackedHeader, "ingress")
		} else if isNavCandidate {
			w.Header().Set(spaTrackedHeader, "spa")
		}
		next.ServeHTTP(rec, r)

		if !ingressTracked && isNavCandidate && rec.status == http.StatusOK &&
			strings.Contains(strings.ToLower(rec.Header().Get("Content-Type")), "text/html") {
			a.enqueue(a.buildServerNavEvent(r, sid))
		}
	})
}

func (a *spaAnalytics) handleBeacon(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	raw, err := io.ReadAll(io.LimitReader(r.Body, spaMaxBeaconBytes))
	if err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	var b spaBeaconPayload
	if len(bytes.TrimSpace(raw)) > 0 {
		if err := json.Unmarshal(raw, &b); err != nil {
			http.Error(w, "invalid json", http.StatusBadRequest)
			return
		}
	}

	// Cooperate with hanzo/ingress: if the client explicitly flagged an initial
	// pageload beacon AND ingress already tracked the navigation request, skip
	// emitting a duplicate pageview.
	if b.Initial && r.Header.Get(spaIngressTrackedHeader) == "1" {
		w.Header().Set(spaTrackedHeader, "ingress")
		w.WriteHeader(http.StatusNoContent)
		return
	}

	sid := strings.TrimSpace(b.SessionID)
	if sid == "" {
		sid, _ = a.ensureSession(w, r)
	}

	ev := a.buildBeaconEvent(r, b, sid)
	a.enqueue(ev)
	w.Header().Set(spaTrackedHeader, "spa-beacon")
	w.WriteHeader(http.StatusNoContent)
}

func (a *spaAnalytics) buildServerNavEvent(r *http.Request, sessionID string) spaCaptureEvent {
	host := spaNormalizeHost(r, "")
	normPath := spaNormalizePath(r.URL.Path)
	scheme := "https"
	if r.TLS == nil && !strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https") {
		scheme = "http"
	}
	fullURL := scheme + "://" + host + normPath
	if rq := spaSanitizeQuery(r.URL.RawQuery); rq != "" {
		fullURL += "?" + rq
	}

	ua := r.UserAgent()
	clientIP := spaExtractClientIP(r)
	device := spaClassifyDevice(ua)
	distinctID, anonID := spaExtractIdentity(r, clientIP, ua, host, "", "")

	q := r.URL.Query()
	utm := spaUTM{
		Source:   strings.TrimSpace(q.Get("utm_source")),
		Medium:   strings.TrimSpace(q.Get("utm_medium")),
		Campaign: strings.TrimSpace(q.Get("utm_campaign")),
		Term:     strings.TrimSpace(q.Get("utm_term")),
		Content:  strings.TrimSpace(q.Get("utm_content")),
	}

	props := map[string]any{
		"hostname":      host,
		"device":        device,
		"is_navigation": true,
		"source":        "spa_nav",
	}
	if ua != "" {
		props["user_agent"] = ua
	}
	spaCopyClickSignals(props, q, r)

	return spaCaptureEvent{
		Type:        "pageview",
		Event:       "$pageview",
		Timestamp:   time.Now().UTC().Format(time.RFC3339Nano),
		DistinctID:  distinctID,
		AnonymousID: anonID,
		SessionID:   sessionID,
		Product:     "spa",
		URL:         fullURL,
		Path:        normPath,
		Referrer:    strings.TrimSpace(r.Referer()),
		UTM:         utm,
		Site:        host,
		Environment: a.cfg.Environment,
		Service:     "spa",
		Properties:  props,
		Library:     "hanzo-spa",
		LibraryVer:  "1.0.0",
	}
}

func (a *spaAnalytics) buildBeaconEvent(r *http.Request, b spaBeaconPayload, sessionID string) spaCaptureEvent {
	host := spaNormalizeHost(r, b.Hostname)

	rawPath := strings.TrimSpace(b.Path)
	var parsedURL *url.URL
	if strings.TrimSpace(b.URL) != "" {
		if u, err := url.Parse(strings.TrimSpace(b.URL)); err == nil {
			parsedURL = u
			if rawPath == "" {
				rawPath = u.Path
			}
			if host == "" && u.Host != "" {
				host = spaCleanHost(u.Host)
			}
		}
	}
	normPath := spaNormalizePath(rawPath)

	scheme := "https"
	if parsedURL != nil && (parsedURL.Scheme == "http" || parsedURL.Scheme == "https") {
		scheme = parsedURL.Scheme
	} else if r.TLS == nil && !strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https") {
		scheme = "http"
	}

	var rawQuery string
	if parsedURL != nil {
		rawQuery = spaSanitizeQuery(parsedURL.RawQuery)
	}
	fullURL := scheme + "://" + host + normPath
	if rawQuery != "" {
		fullURL += "?" + rawQuery
	}

	var q url.Values
	if parsedURL != nil {
		q = parsedURL.Query()
	} else {
		q = r.URL.Query()
	}

	utm := spaUTM{
		Source:   firstNonEmpty(b.UTM.Source, q.Get("utm_source")),
		Medium:   firstNonEmpty(b.UTM.Medium, q.Get("utm_medium")),
		Campaign: firstNonEmpty(b.UTM.Campaign, q.Get("utm_campaign")),
		Term:     firstNonEmpty(b.UTM.Term, q.Get("utm_term")),
		Content:  firstNonEmpty(b.UTM.Content, q.Get("utm_content")),
	}

	ua := r.UserAgent()
	clientIP := spaExtractClientIP(r)
	device := spaClassifyDevice(ua)
	distinctID, anonID := spaExtractIdentity(r, clientIP, ua, host, b.DistinctID, b.AnonymousID)

	evType := strings.ToLower(strings.TrimSpace(b.Type))
	if evType == "" {
		evType = "pageview"
	}
	evName := strings.TrimSpace(b.Event)
	if evName == "" {
		if evType == "pageview" {
			evName = "$pageview"
		} else {
			evName = "spa_event"
		}
	}

	props := make(map[string]any, len(b.Properties)+6)
	for k, v := range b.Properties {
		props[k] = v
	}
	props["hostname"] = host
	props["device"] = device
	props["is_spa_transition"] = !b.Initial
	if ua != "" {
		props["user_agent"] = ua
	}
	if eid := strings.TrimSpace(b.EventID); eid != "" {
		props["event_id"] = eid
	}
	spaCopyClickSignals(props, q, r)

	ref := firstNonEmpty(b.Referrer, r.Referer())

	return spaCaptureEvent{
		MessageID:   strings.TrimSpace(b.EventID),
		Type:        evType,
		Event:       evName,
		Timestamp:   time.Now().UTC().Format(time.RFC3339Nano),
		DistinctID:  distinctID,
		AnonymousID: anonID,
		SessionID:   sessionID,
		Product:     "spa",
		URL:         fullURL,
		Path:        normPath,
		Referrer:    ref,
		UTM:         utm,
		Site:        host,
		Environment: a.cfg.Environment,
		Service:     "spa",
		Properties:  props,
		Library:     "hanzo-spa",
		LibraryVer:  "1.0.0",
	}
}

func spaCopyClickSignals(props map[string]any, q url.Values, r *http.Request) {
	for _, k := range spaClickParams {
		if _, ok := props[k]; !ok {
			if v := strings.TrimSpace(q.Get(k)); v != "" {
				props[k] = v
			}
		}
	}
	for _, ck := range spaClickCookies {
		if _, ok := props[ck]; !ok {
			if c, err := r.Cookie(ck); err == nil && strings.TrimSpace(c.Value) != "" {
				props[ck] = strings.TrimSpace(c.Value)
			}
		}
	}
}

func (a *spaAnalytics) ensureSession(w http.ResponseWriter, r *http.Request) (string, bool) {
	if sid := strings.TrimSpace(r.Header.Get("X-Hanzo-Session-Id")); sid != "" {
		return sid, false
	}
	for _, name := range []string{spaSessionCookie, "hz_sid"} {
		if c, err := r.Cookie(name); err == nil && strings.TrimSpace(c.Value) != "" {
			return strings.TrimSpace(c.Value), false
		}
	}
	b := make([]byte, 12)
	_, _ = rand.Read(b)
	sid := "s_" + hex.EncodeToString(b)
	http.SetCookie(w, &http.Cookie{
		Name:     spaSessionCookie,
		Value:    sid,
		Path:     "/",
		MaxAge:   spaSessionMaxAge,
		HttpOnly: false, // readable by @hanzo/event / tag.js when present on same origin
		Secure:   r.TLS != nil || strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https"),
		SameSite: http.SameSiteLaxMode,
	})
	return sid, true
}

func (a *spaAnalytics) enqueue(ev spaCaptureEvent) {
	if a.closed.Load() {
		a.dropped.Add(1)
		return
	}
	select {
	case a.ch <- ev:
	default:
		a.dropped.Add(1)
	}
}

func (a *spaAnalytics) Close() error {
	if a == nil {
		return nil
	}
	a.once.Do(func() {
		a.closed.Store(true)
		close(a.ch)
		a.wg.Wait()
	})
	return nil
}

func (a *spaAnalytics) Stats() (sent, dropped, failed uint64) {
	if a == nil {
		return 0, 0, 0
	}
	return a.sent.Load(), a.dropped.Load(), a.failed.Load()
}

func (a *spaAnalytics) loop() {
	defer a.wg.Done()
	ticker := time.NewTicker(a.cfg.FlushInterval)
	defer ticker.Stop()

	batch := make([]spaCaptureEvent, 0, a.cfg.BatchSize)
	flush := func() {
		if len(batch) == 0 {
			return
		}
		a.sendBatch(batch)
		batch = batch[:0]
	}

	for {
		select {
		case ev, ok := <-a.ch:
			if !ok {
				flush()
				return
			}
			batch = append(batch, ev)
			if len(batch) >= a.cfg.BatchSize {
				flush()
			}
		case <-ticker.C:
			flush()
		}
	}
}

func (a *spaAnalytics) sendBatch(events []spaCaptureEvent) {
	payload, err := json.Marshal(spaCaptureBatch{Batch: events})
	if err != nil {
		a.failed.Add(uint64(len(events)))
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, a.cfg.Endpoint, bytes.NewReader(payload))
	if err != nil {
		a.failed.Add(uint64(len(events)))
		return
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "hanzo-spa-analytics/1.0")
	req.Header.Set("X-Hanzo-Protocol", "zap-proto-s2s")
	if a.cfg.HostHeader != "" {
		req.Host = a.cfg.HostHeader
	}
	if a.cfg.APIKey != "" {
		req.Header.Set("Authorization", "Bearer "+a.cfg.APIKey)
	}

	resp, err := a.client.Do(req)
	if err != nil {
		a.failed.Add(uint64(len(events)))
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		a.sent.Add(uint64(len(events)))
		return
	}
	a.failed.Add(uint64(len(events)))
}

func spaNormalizeHost(r *http.Request, fallback string) string {
	if xfh := strings.TrimSpace(r.Header.Get("X-Forwarded-Host")); xfh != "" {
		if idx := strings.IndexByte(xfh, ','); idx >= 0 {
			xfh = xfh[:idx]
		}
		if h := spaCleanHost(xfh); h != "" {
			return h
		}
	}
	if h := spaCleanHost(fallback); h != "" {
		return h
	}
	return spaCleanHost(r.Host)
}

func spaCleanHost(host string) string {
	host = strings.TrimSpace(host)
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	return strings.ToLower(strings.Trim(host, "[]"))
}

func spaNormalizePath(p string) string {
	p = strings.TrimSpace(p)
	if idx := strings.IndexAny(p, "?#"); idx >= 0 {
		p = p[:idx]
	}
	if p == "" {
		return "/"
	}
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	for strings.Contains(p, "//") {
		p = strings.ReplaceAll(p, "//", "/")
	}
	if len(p) > 1 {
		p = strings.TrimRight(p, "/")
	}
	return p
}

func spaExtractClientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		if idx := strings.IndexByte(xff, ','); idx >= 0 {
			return strings.TrimSpace(xff[:idx])
		}
		return strings.TrimSpace(xff)
	}
	if xri := strings.TrimSpace(r.Header.Get("X-Real-Ip")); xri != "" {
		return xri
	}
	if h, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return h
	}
	return r.RemoteAddr
}

func spaExtractIdentity(r *http.Request, clientIP, ua, host, explicitDistinct, explicitAnon string) (distinctID, anonID string) {
	distinctID = firstNonEmpty(explicitDistinct, r.Header.Get("X-Hanzo-User-Id"))
	anonID = strings.TrimSpace(explicitAnon)
	if anonID == "" {
		for _, name := range []string{spaAnonCookie, "hz_vid"} {
			if c, err := r.Cookie(name); err == nil && strings.TrimSpace(c.Value) != "" {
				anonID = strings.TrimSpace(c.Value)
				break
			}
		}
	}
	if anonID == "" {
		sum := sha256.Sum256([]byte(host + "|" + clientIP + "|" + ua))
		anonID = "spa_" + hex.EncodeToString(sum[:12])
	}
	if distinctID == "" {
		distinctID = anonID
	}
	return distinctID, anonID
}

func spaClassifyDevice(ua string) string {
	lua := strings.ToLower(strings.TrimSpace(ua))
	switch {
	case lua == "":
		return "unknown"
	case strings.Contains(lua, "bot") || strings.Contains(lua, "crawler") || strings.Contains(lua, "spider") || strings.Contains(lua, "curl/") || strings.Contains(lua, "headless"):
		return "bot"
	case strings.Contains(lua, "ipad") || strings.Contains(lua, "tablet") || (strings.Contains(lua, "android") && !strings.Contains(lua, "mobile")):
		return "tablet"
	case strings.Contains(lua, "mobile") || strings.Contains(lua, "iphone") || strings.Contains(lua, "android"):
		return "mobile"
	default:
		return "desktop"
	}
}

func spaSanitizeQuery(raw string) string {
	if raw == "" {
		return ""
	}
	parts := strings.Split(raw, "&")
	kept := make([]string, 0, len(parts))
	for _, part := range parts {
		k, _, _ := strings.Cut(part, "=")
		lk := strings.ToLower(k)
		if strings.Contains(lk, "token") || strings.Contains(lk, "secret") || strings.Contains(lk, "key") || strings.Contains(lk, "password") || lk == "code" || lk == "auth" {
			continue
		}
		if part != "" {
			kept = append(kept, part)
		}
	}
	return strings.Join(kept, "&")
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if t := strings.TrimSpace(v); t != "" {
			return t
		}
	}
	return ""
}

func extOfPath(p string) string {
	if i := strings.LastIndexByte(p, '.'); i >= 0 && i > strings.LastIndexByte(p, '/') {
		return p[i:]
	}
	return ""
}

type spaStatusRecorder struct {
	http.ResponseWriter
	status      int
	wroteHeader bool
}

func (r *spaStatusRecorder) WriteHeader(code int) {
	if !r.wroteHeader {
		r.status = code
		r.wroteHeader = true
	}
	r.ResponseWriter.WriteHeader(code)
}

func (r *spaStatusRecorder) Write(b []byte) (int, error) {
	if !r.wroteHeader {
		r.wroteHeader = true
	}
	return r.ResponseWriter.Write(b)
}

type spaHTMLRecorder struct {
	http.ResponseWriter
	snippet []byte
	started bool
	isHTML  bool
	status  int
	buf     []byte
}

func (w *spaHTMLRecorder) WriteHeader(code int) {
	if w.started {
		return
	}
	w.started = true
	ct := strings.ToLower(w.Header().Get("Content-Type"))
	enc := strings.TrimSpace(w.Header().Get("Content-Encoding"))
	if code == http.StatusOK && strings.HasPrefix(ct, "text/html") && enc == "" {
		w.isHTML = true
		w.status = code
		w.Header().Del("Content-Length")
		return
	}
	w.ResponseWriter.WriteHeader(code)
}

func (w *spaHTMLRecorder) Write(b []byte) (int, error) {
	if !w.started {
		w.WriteHeader(http.StatusOK)
	}
	if w.isHTML {
		w.buf = append(w.buf, b...)
		return len(b), nil
	}
	return w.ResponseWriter.Write(b)
}

func (w *spaHTMLRecorder) finalize() {
	if !w.isHTML {
		return
	}
	out := injectBefore(w.buf, []byte("</body>"), w.snippet)
	w.Header().Set("Content-Length", strconv.Itoa(len(out)))
	w.ResponseWriter.WriteHeader(w.status)
	_, _ = w.ResponseWriter.Write(out)
}
