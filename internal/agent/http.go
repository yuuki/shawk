package agent

import (
	"crypto/subtle"
	"encoding/json"
	"net/http"
	"time"

	"github.com/yuuki/shawk/internal/api"
)

func (a *Agent) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		a.mu.Lock()
		err, last := a.lastErr, a.lastTick
		a.mu.Unlock()
		if err != nil {
			http.Error(w, err.Error(), http.StatusServiceUnavailable)
			return
		}
		writeJSON(w, map[string]any{"status": "ok", "last_collect": last})
	})
	mux.HandleFunc("GET /api/v1/info", func(w http.ResponseWriter, r *http.Request) {
		info, err := a.info(r.Context())
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, info)
	})
	mux.HandleFunc("GET /api/v1/edges", func(w http.ResponseWriter, r *http.Request) {
		q, err := api.ParseEdgeQuery(r.URL.Query())
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		edges, err := a.ledger.Edges(r.Context(), q)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, api.EdgesResponse{Edges: edges})
	})
	mux.HandleFunc("GET /api/v1/listeners", func(w http.ResponseWriter, r *http.Request) {
		var since time.Time
		if s := r.URL.Query().Get("since"); s != "" {
			var err error
			if since, err = time.Parse(time.RFC3339, s); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
		}
		ls, err := a.ledger.Listeners(r.Context(), since)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, api.ListenersResponse{Listeners: ls})
	})
	mux.HandleFunc("GET /api/v1/programs", func(w http.ResponseWriter, r *http.Request) {
		stats, err := a.programStats()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, stats)
	})
	if a.cfg.Token == "" {
		return mux
	}
	want := []byte("Bearer " + a.cfg.Token)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/healthz" && subtle.ConstantTimeCompare([]byte(r.Header.Get("Authorization")), want) != 1 {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		mux.ServeHTTP(w, r)
	})
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}
