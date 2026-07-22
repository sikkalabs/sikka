package node

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
)

func (n *Node) writeJSON(w http.ResponseWriter, status int, payload any) {
	if w.Header().Get("Content-Type") == "" {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
	}
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(payload); err != nil {
		n.log.Error("encode response", "err", err)
	}
}

func (n *Node) withCORS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")

		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}

		next.ServeHTTP(w, r)
	})
}

func (n *Node) staticHandler(publicDir string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if len(r.URL.Path) > 0 && r.URL.Path[len(r.URL.Path)-1] == '/' {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Cache-Control", "public, max-age=3600, immutable")
		http.FileServer(http.Dir(publicDir)).ServeHTTP(w, r)
	})
}

func locatePublicDir() (string, bool) {
	candidates := []string{
		"public2",
		filepath.Join("..", "public2"),
		filepath.Join("..", "..", "public2"),
		filepath.Join("/home", "sikka", "public2"),
		"public",
		filepath.Join("..", "public"),
		filepath.Join("..", "..", "public"),
		filepath.Join("/home", "sikka", "public"),
	}

	for _, candidate := range candidates {
		info, err := os.Stat(candidate)
		if err == nil && info.IsDir() {
			return candidate, true
		}
	}

	return "", false
}
