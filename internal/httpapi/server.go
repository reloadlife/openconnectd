// Package httpapi serves openconnectd's REST API over loopback. Routing is
// stdlib net/http (Go 1.22 method+path patterns) — no router dep for an API
// this small. Every route except /healthz requires the bearer token.
package httpapi

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/reloadlife/openconnectd/internal/config"
	"github.com/reloadlife/openconnectd/internal/ocserv"
	"github.com/reloadlife/openconnectd/pkg/api"
)

// Build info, injected at link time (-ldflags -X).
var (
	Version = "dev"
	Commit  = ""
)

type Server struct {
	cfg config.Config
	mgr *ocserv.Manager
	log *slog.Logger
}

func New(cfg config.Config, mgr *ocserv.Manager, log *slog.Logger) *Server {
	return &Server{cfg: cfg, mgr: mgr, log: log}
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", s.health)
	mux.HandleFunc("GET /v1/version", s.auth(s.version))

	mux.HandleFunc("GET /v1/instances", s.auth(s.listInstances))
	mux.HandleFunc("POST /v1/instances", s.auth(s.createInstance))
	mux.HandleFunc("GET /v1/instances/{name}", s.auth(s.getInstance))
	mux.HandleFunc("PATCH /v1/instances/{name}", s.auth(s.patchInstance))
	mux.HandleFunc("DELETE /v1/instances/{name}", s.auth(s.deleteInstance))

	mux.HandleFunc("GET /v1/instances/{name}/clients", s.auth(s.listClients))
	mux.HandleFunc("POST /v1/instances/{name}/clients", s.auth(s.createClient))
	mux.HandleFunc("PATCH /v1/instances/{name}/clients/{cn}", s.auth(s.patchClient))
	mux.HandleFunc("DELETE /v1/instances/{name}/clients/{cn}", s.auth(s.deleteClient))
	mux.HandleFunc("GET /v1/instances/{name}/clients/{cn}/client-config", s.auth(s.clientConfig))

	mux.HandleFunc("GET /v1/sessions", s.auth(s.listSessions))

	mux.HandleFunc("GET /v1/bans", s.auth(s.listBans))
	mux.HandleFunc("DELETE /v1/bans/{ip}", s.auth(s.unban))
	mux.HandleFunc("DELETE /v1/instances/{name}/sessions/{cn}", s.auth(s.disconnect))
	return logging(s.log, mux)
}

func (s *Server) health(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok"))
}

func (s *Server) version(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()
	path, ver := ocserv.Resolve(ctx, s.cfg.OcservBin)
	writeJSON(w, http.StatusOK, api.VersionInfo{
		Version: Version, Commit: Commit, OcservPath: path, OcservVer: ver,
	})
}

// --- instances ---

func (s *Server) listInstances(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.mgr.ListInstances())
}

func (s *Server) createInstance(w http.ResponseWriter, r *http.Request) {
	var req api.InstanceCreateRequest
	if !decode(w, r, &req) {
		return
	}
	in, err := s.mgr.CreateInstance(r.Context(), req)
	if err != nil {
		writeErr(w, statusFor(err), "create_instance", err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, in)
}

func (s *Server) getInstance(w http.ResponseWriter, r *http.Request) {
	in, ok := s.mgr.GetInstance(r.PathValue("name"))
	if !ok {
		writeErr(w, http.StatusNotFound, "not_found", "instance not found")
		return
	}
	writeJSON(w, http.StatusOK, in)
}

func (s *Server) patchInstance(w http.ResponseWriter, r *http.Request) {
	var body map[string]any
	if !decode(w, r, &body) {
		return
	}
	in, err := s.mgr.PatchInstance(r.PathValue("name"), body)
	if err != nil {
		writeErr(w, statusFor(err), "patch_instance", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, in)
}

func (s *Server) deleteInstance(w http.ResponseWriter, r *http.Request) {
	if err := s.mgr.DeleteInstance(r.PathValue("name")); err != nil {
		writeErr(w, statusFor(err), "delete_instance", err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// --- clients ---

func (s *Server) listClients(w http.ResponseWriter, r *http.Request) {
	list, err := s.mgr.ListClients(r.PathValue("name"))
	if err != nil {
		writeErr(w, statusFor(err), "list_clients", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, list)
}

func (s *Server) createClient(w http.ResponseWriter, r *http.Request) {
	var req api.ClientCreateRequest
	if !decode(w, r, &req) {
		return
	}
	c, err := s.mgr.CreateClient(r.Context(), r.PathValue("name"), req)
	if err != nil {
		writeErr(w, statusFor(err), "create_client", err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, c)
}

func (s *Server) patchClient(w http.ResponseWriter, r *http.Request) {
	var body map[string]any
	if !decode(w, r, &body) {
		return
	}
	c, err := s.mgr.PatchClient(r.Context(), r.PathValue("name"), r.PathValue("cn"), body)
	if err != nil {
		writeErr(w, statusFor(err), "patch_client", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, c)
}

func (s *Server) deleteClient(w http.ResponseWriter, r *http.Request) {
	if err := s.mgr.DeleteClient(r.PathValue("name"), r.PathValue("cn")); err != nil {
		writeErr(w, statusFor(err), "delete_client", err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) clientConfig(w http.ResponseWriter, r *http.Request) {
	cfg, err := s.mgr.ClientConfig(r.PathValue("name"), r.PathValue("cn"))
	if err != nil {
		writeErr(w, statusFor(err), "client_config", err.Error())
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(cfg))
}

// --- sessions ---

func (s *Server) listSessions(w http.ResponseWriter, r *http.Request) {
	sessions, err := s.mgr.Sessions(r.Context(), r.URL.Query().Get("instance"))
	if err != nil {
		writeErr(w, statusFor(err), "sessions", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, sessions)
}

// --- bans ---

func (s *Server) listBans(w http.ResponseWriter, r *http.Request) {
	bans, err := s.mgr.Bans(r.Context())
	if err != nil {
		writeErr(w, statusFor(err), "bans", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, bans)
}

func (s *Server) unban(w http.ResponseWriter, r *http.Request) {
	if err := s.mgr.Unban(r.Context(), r.PathValue("ip")); err != nil {
		writeErr(w, statusFor(err), "unban", err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) disconnect(w http.ResponseWriter, r *http.Request) {
	if err := s.mgr.Disconnect(r.Context(), r.PathValue("name"), r.PathValue("cn")); err != nil {
		writeErr(w, statusFor(err), "disconnect", err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// --- middleware + helpers ---

func (s *Server) auth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if s.cfg.Token == "" { // no token configured ⇒ open (dev only)
			next(w, r)
			return
		}
		const p = "Bearer "
		h := r.Header.Get("Authorization")
		if len(h) <= len(p) || subtle.ConstantTimeCompare([]byte(h[len(p):]), []byte(s.cfg.Token)) != 1 {
			writeErr(w, http.StatusUnauthorized, "unauthorized", "bad or missing token")
			return
		}
		next(w, r)
	}
}

func decode(w http.ResponseWriter, r *http.Request, v any) bool {
	if err := json.NewDecoder(r.Body).Decode(v); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", "invalid JSON: "+err.Error())
		return false
	}
	return true
}

// statusFor maps manager errors to HTTP status by their text — the manager
// returns plain errors, so this keeps status mapping in one place.
func statusFor(err error) int {
	if err == nil {
		return http.StatusOK
	}
	msg := err.Error()
	switch {
	case strings.Contains(msg, "not found"):
		return http.StatusNotFound
	case strings.Contains(msg, "already exists"):
		return http.StatusConflict
	case strings.Contains(msg, "required"), strings.Contains(msg, "invalid"):
		return http.StatusBadRequest
	case errors.Is(err, context.Canceled):
		return http.StatusRequestTimeout
	default:
		return http.StatusInternalServerError
	}
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, status int, code, msg string) {
	var eb api.ErrorBody
	eb.Error.Code = code
	eb.Error.Message = msg
	writeJSON(w, status, eb)
}

func logging(log *slog.Logger, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		sw := &statusWriter{ResponseWriter: w, status: 200}
		next.ServeHTTP(sw, r)
		log.Info("http", "method", r.Method, "path", r.URL.Path, "status", sw.status, "dur", time.Since(start).String())
	})
}

type statusWriter struct {
	http.ResponseWriter
	status int
}

func (w *statusWriter) WriteHeader(c int) {
	w.status = c
	w.ResponseWriter.WriteHeader(c)
}
