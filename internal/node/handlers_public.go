package node

import (
	"net/http"
	"path/filepath"
)

func (n *Node) handleRoot(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}

	n.servePublicFile(w, r, "index.html")
}

func (n *Node) handleTxPage(w http.ResponseWriter, r *http.Request) {
	n.servePublicFile(w, r, filepath.Join("tx", "index.html"))
}

func (n *Node) handleWalletAddressPage(w http.ResponseWriter, r *http.Request) {
	n.servePublicFile(w, r, filepath.Join("wallet", "index.html"))
}

func (n *Node) servePublicFile(w http.ResponseWriter, r *http.Request, name string) {
	if n.publicDir == "" {
		n.writeErrorResponse(w, http.StatusServiceUnavailable, "unavailable", "public assets are not available in this runtime")
		return
	}
	http.ServeFile(w, r, filepath.Join(n.publicDir, name))
}
