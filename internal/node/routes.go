package node

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"
)

func (n *Node) runHTTP() error {
	if err := n.http.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return fmt.Errorf("serve api: %w", err)
	}

	return nil
}

func (n *Node) shutdownHTTP() error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := n.http.Shutdown(ctx); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return fmt.Errorf("shutdown api: %w", err)
	}

	return nil
}

func (n *Node) routes() http.Handler {
	mux := http.NewServeMux()
	if dir, ok := locatePublicDir(); ok {
		n.publicDir = dir
		n.publicHandler = n.staticHandler(dir)
	}
	if n.publicHandler == nil {
		n.publicHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			n.writeErrorResponse(w, http.StatusServiceUnavailable, "unavailable", "public assets are not available in this runtime")
		})
	}
	mux.HandleFunc("/", n.handleRoot)
	mux.HandleFunc("/healthz", n.handleHealth)
	mux.HandleFunc("/metrics", n.handleMetrics)
	mux.HandleFunc("/v1/status", n.handleStatus)
	mux.HandleFunc("/v1/tx/{txid}/weight", n.handleTxWeight)
	mux.HandleFunc("/v1/sync/status", n.handleSyncStatus)
	mux.HandleFunc("POST /v1/sync/tail", n.handleSyncTail)
	mux.HandleFunc("GET /v1/sync/tail", n.handleSyncTail)
	mux.HandleFunc("POST /v1/sync", n.handleSync)
	mux.HandleFunc("/v1/discovery/nodes", n.handleDiscoveryNodes)
	mux.HandleFunc("POST /v1/discovery/announce", n.handleDiscoveryAnnounce)
	mux.HandleFunc("GET /v1/tx/{txid}", n.handleTxLookup)
	mux.HandleFunc("POST /v1/txs", n.handleTxsBulkLookup)
	mux.HandleFunc("/v1/address/{address}", n.handleAddress)
	mux.HandleFunc("POST /v1/tx/pow-quote", n.handleTxPowQuote)
	mux.HandleFunc("POST /v1/tx/submit", n.handleTxSubmit)
	mux.Handle("/index.html", n.publicHandler)
	mux.Handle("/paperwallet.html", n.publicHandler)
	mux.Handle("/wallet.html", n.publicHandler)
	mux.HandleFunc("/tx/", n.handleTxPage)
	mux.HandleFunc("/wallet/", n.handleWalletAddressPage)
	mux.Handle("/public/", http.StripPrefix("/public/", n.publicHandler))

	handler := n.withSecurityHeaders(mux)
	handler = n.withCORS(handler)
	handler = n.withAccessLog(handler)
	return handler
}
