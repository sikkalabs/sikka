package node

import (
	"log/slog"
	"net/http"
	"strings"
	"time"
)

type statusRecorder struct {
	http.ResponseWriter
	status  int
	written int64
}

func (r *statusRecorder) WriteHeader(code int) {
	r.status = code
	r.ResponseWriter.WriteHeader(code)
}

func (r *statusRecorder) Write(b []byte) (int, error) {
	n, err := r.ResponseWriter.Write(b)
	r.written += int64(n)
	return n, err
}

func securityProfile(path string) string {
	if path == "/healthz" || strings.HasPrefix(path, "/v1/") {
		return "api"
	}
	return "static"
}

func (n *Node) withSecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")

		switch securityProfile(r.URL.Path) {
		case "api":
			w.Header().Set("Cache-Control", "no-store")
			w.Header().Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
		default:
			w.Header().Set("Content-Security-Policy",
				"default-src 'self'; "+
					"script-src 'self' 'unsafe-inline' 'unsafe-eval' 'wasm-unsafe-eval'; "+
					"style-src 'self' 'unsafe-inline'; "+
					"connect-src 'self'; "+
					"img-src 'self' data:; "+
					"frame-ancestors 'none'")
		}

		next.ServeHTTP(w, r)
	})
}

func (n *Node) withAccessLog(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodOptions {
			next.ServeHTTP(w, r)
			return
		}

		start := time.Now()
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(rec, r)

		attrs := []any{
			"method", r.Method,
			"path", r.URL.Path,
			"status", rec.status,
			"bytes", rec.written,
			"duration_ms", time.Since(start).Milliseconds(),
			"remote", r.RemoteAddr,
		}
		if rec.status >= http.StatusInternalServerError {
			n.log.Error("http", attrs...)
		} else if rec.status >= http.StatusBadRequest {
			n.log.Info("http", attrs...)
		} else {
			n.log.Debug("http", attrs...)
		}
	})
}

func initNodeLogger() *slog.Logger {
	return slog.With("component", "node")
}
