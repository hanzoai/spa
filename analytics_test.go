package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestSPAAnalyticsDisabledIsNoop(t *testing.T) {
	t.Setenv("ANALYTICS_ENDPOINT", "")
	t.Setenv("SPA_ANALYTICS_ENDPOINT", "")
	if a := loadAnalytics(); a != nil {
		t.Fatalf("expected nil spaAnalytics when endpoint unset, got %+v", a)
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "index.html"), []byte("<html><body>hello</body></html>"), 0o644); err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(loadAnalytics().wrap(spaHandler(dir)))
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/pricing")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(body) != "<html><body>hello</body></html>" {
		t.Fatalf("expected byte-identical HTML when analytics disabled, got %q", body)
	}
}

func TestSPAAnalyticsCooperationWithIngressNoDoubleCount(t *testing.T) {
	var (
		mu       sync.Mutex
		received []spaCaptureEvent
		authHdr  string
	)
	sink := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var batch spaCaptureBatch
		if err := json.NewDecoder(r.Body).Decode(&batch); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		mu.Lock()
		authHdr = r.Header.Get("Authorization")
		received = append(received, batch.Batch...)
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer sink.Close()

	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "index.html"), []byte("<!doctype html><html><body>app</body></html>"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "app-abc12345.js"), []byte("console.log(1)"), 0o644); err != nil {
		t.Fatal(err)
	}

	a := newSPAAnalytics(spaAnalyticsConfig{
		Endpoint:      sink.URL,
		APIKey:        "sk-spa-s2s",
		Environment:   "production",
		InjectScript:  true,
		FlushInterval: 20 * time.Millisecond,
	})
	srv := httptest.NewServer(a.wrap(spaHandler(dir)))
	defer srv.Close()

	// 1. Initial HTML load arriving THROUGH hanzo/ingress (X-Hanzo-Analytics-Ingress: 1).
	// Must NOT emit a duplicate initial pageview from hanzo/spa, must set _hz_sid cookie,
	// and must inject the route-transition beacon script before </body>.
	req1, _ := http.NewRequest(http.MethodGet, srv.URL+"/dashboard?utm_source=google&gclid=gc_99", nil)
	req1.Host = "insights.hanzo.ai:443"
	req1.Header.Set("X-Forwarded-Proto", "https")
	req1.Header.Set("X-Forwarded-Host", "insights.hanzo.ai:443")
	req1.Header.Set(spaIngressTrackedHeader, "1")
	req1.Header.Set("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)")
	resp1, err := srv.Client().Do(req1)
	if err != nil {
		t.Fatal(err)
	}
	htmlBody, _ := io.ReadAll(resp1.Body)
	resp1.Body.Close()

	if resp1.Header.Get(spaTrackedHeader) != "ingress" {
		t.Fatalf("expected %s=ingress, got %q", spaTrackedHeader, resp1.Header.Get(spaTrackedHeader))
	}
	if !strings.Contains(string(htmlBody), "data-hz-spa-beacon") {
		t.Fatalf("expected injected SPA route beacon script in HTML, got %q", htmlBody)
	}
	var sidCookie *http.Cookie
	for _, c := range resp1.Cookies() {
		if c.Name == spaSessionCookie {
			sidCookie = c
		}
	}
	if sidCookie == nil || sidCookie.Value == "" {
		t.Fatal("expected _hz_sid cookie to be minted on navigation")
	}

	// 2. Client-side initial beacon when X-Hanzo-Analytics-Ingress=1 must ALSO be suppressed (204, no event).
	initBeacon, _ := json.Marshal(spaBeaconPayload{
		Initial:  true,
		Hostname: "insights.hanzo.ai",
		Path:     "/dashboard",
	})
	reqInit, _ := http.NewRequest(http.MethodPost, srv.URL+"/_/beacon", bytes.NewReader(initBeacon))
	reqInit.Header.Set("Content-Type", "application/json")
	reqInit.Header.Set(spaIngressTrackedHeader, "1")
	respInit, err := srv.Client().Do(reqInit)
	if err != nil {
		t.Fatal(err)
	}
	respInit.Body.Close()
	if respInit.StatusCode != http.StatusNoContent {
		t.Fatalf("expected 204 for suppressed initial beacon, got %d", respInit.StatusCode)
	}

	// 3. SPA client route transition (pushState -> POST /_/beacon) — MUST be captured with
	// normalized hostname, normalized path, referrer, utm_*, device, sessionId, and click IDs.
	routeBeacon, _ := json.Marshal(spaBeaconPayload{
		Type:     "pageview",
		Event:    "$pageview",
		Hostname: "INSIGHTS.HANZO.AI:443",
		Path:     "//funnels//conversion/?secret=dropme",
		URL:      "https://insights.hanzo.ai/funnels/conversion/?utm_source=linkedin&utm_medium=cpc&utm_campaign=oct&li_fat_id=li_abc&token=secret",
		Referrer: "https://insights.hanzo.ai/dashboard",
		EventID:  "ev_route_1",
	})
	reqRoute, _ := http.NewRequest(http.MethodPost, srv.URL+"/_/beacon", bytes.NewReader(routeBeacon))
	reqRoute.Header.Set("Content-Type", "application/json")
	reqRoute.Header.Set("User-Agent", "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) Mobile")
	reqRoute.AddCookie(sidCookie)
	reqRoute.AddCookie(&http.Cookie{Name: "_fbp", Value: "fb.1.1700000000.999"})
	respRoute, err := srv.Client().Do(reqRoute)
	if err != nil {
		t.Fatal(err)
	}
	respRoute.Body.Close()
	if respRoute.StatusCode != http.StatusNoContent {
		t.Fatalf("expected 204 from /_/beacon, got %d", respRoute.StatusCode)
	}

	// 4. Static asset fetch must never emit a pageview.
	respAsset, err := http.Get(srv.URL + "/app-abc12345.js")
	if err != nil {
		t.Fatal(err)
	}
	respAsset.Body.Close()

	// 5. Standalone HTML navigation (WITHOUT X-Hanzo-Analytics-Ingress) MUST emit 1 server pageview.
	reqStandalone, _ := http.NewRequest(http.MethodGet, srv.URL+"/standalone/?utm_source=x&twclid=tw_77", nil)
	reqStandalone.Host = "analytics.hanzo.ai"
	reqStandalone.Header.Set("Referer", "https://x.com/hanzoai")
	reqStandalone.Header.Set("User-Agent", "Mozilla/5.0 (iPad; CPU OS 17_0 like Mac OS X)")
	reqStandalone.AddCookie(sidCookie)
	respStandalone, err := srv.Client().Do(reqStandalone)
	if err != nil {
		t.Fatal(err)
	}
	respStandalone.Body.Close()

	if err := a.Close(); err != nil {
		t.Fatal(err)
	}

	mu.Lock()
	defer mu.Unlock()

	if authHdr != "Bearer sk-spa-s2s" {
		t.Fatalf("expected Authorization Bearer sk-spa-s2s, got %q", authHdr)
	}
	if len(received) != 2 {
		t.Fatalf("expected exactly 2 events (1 SPA route beacon + 1 standalone nav, 0 duplicates), got %d: %+v", len(received), received)
	}

	ev1 := received[0]
	if ev1.Site != "insights.hanzo.ai" || ev1.Properties["hostname"] != "insights.hanzo.ai" {
		t.Errorf("expected hostname insights.hanzo.ai, got site=%q prop=%v", ev1.Site, ev1.Properties["hostname"])
	}
	if ev1.Path != "/funnels/conversion" {
		t.Errorf("expected normalized path /funnels/conversion, got %q", ev1.Path)
	}
	if ev1.Referrer != "https://insights.hanzo.ai/dashboard" {
		t.Errorf("unexpected referrer %q", ev1.Referrer)
	}
	if ev1.UTM.Source != "linkedin" || ev1.UTM.Medium != "cpc" || ev1.UTM.Campaign != "oct" {
		t.Errorf("unexpected UTM %+v", ev1.UTM)
	}
	if ev1.Properties["device"] != "mobile" {
		t.Errorf("expected device=mobile, got %v", ev1.Properties["device"])
	}
	if ev1.SessionID != sidCookie.Value {
		t.Errorf("expected sessionId=%q, got %q", sidCookie.Value, ev1.SessionID)
	}
	if ev1.Properties["li_fat_id"] != "li_abc" || ev1.Properties["_fbp"] != "fb.1.1700000000.999" {
		t.Errorf("expected click IDs preserved on SPA beacon, got %+v", ev1.Properties)
	}
	if strings.Contains(ev1.URL, "token=") {
		t.Errorf("expected sensitive query parameter stripped from URL, got %q", ev1.URL)
	}

	ev2 := received[1]
	if ev2.Site != "analytics.hanzo.ai" || ev2.Path != "/standalone" {
		t.Errorf("unexpected standalone nav site/path: %q %q", ev2.Site, ev2.Path)
	}
	if ev2.Properties["device"] != "tablet" || ev2.Properties["twclid"] != "tw_77" {
		t.Errorf("unexpected standalone nav props: %+v", ev2.Properties)
	}
	if ev2.SessionID != sidCookie.Value {
		t.Errorf("expected shared sessionId=%q, got %q", sidCookie.Value, ev2.SessionID)
	}
}
