package node

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"besoeasy/sikka/internal/config"
)

func TestSecurityHeadersAPI(t *testing.T) {
	t.Parallel()

	n := mustNewNode(t, config.Config{APIPort: 64552, DataDir: t.TempDir(), SyncIntervalSeconds: 15})
	req := httptest.NewRequest(http.MethodGet, "/v1/status", nil)
	rec := httptest.NewRecorder()
	n.routes().ServeHTTP(rec, req)

	if rec.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Fatalf("missing X-Content-Type-Options header")
	}
	if rec.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("Cache-Control = %q, want no-store", rec.Header().Get("Cache-Control"))
	}
	if csp := rec.Header().Get("Content-Security-Policy"); !strings.Contains(csp, "default-src 'none'") {
		t.Fatalf("unexpected API CSP: %q", csp)
	}
}

func TestSecurityHeadersStatic(t *testing.T) {
	t.Parallel()

	n := mustNewNode(t, config.Config{APIPort: 64552, DataDir: t.TempDir(), SyncIntervalSeconds: 15})
	if n.publicDir == "" {
		t.Skip("public assets not available in test runtime")
	}

	req := httptest.NewRequest(http.MethodGet, "/public/sikka.svg", nil)
	rec := httptest.NewRecorder()
	n.routes().ServeHTTP(rec, req)

	csp := rec.Header().Get("Content-Security-Policy")
	if !strings.Contains(csp, "unsafe-inline") || !strings.Contains(csp, "unsafe-eval") || !strings.Contains(csp, "wasm-unsafe-eval") {
		t.Fatalf("unexpected static CSP: %q", csp)
	}
}

