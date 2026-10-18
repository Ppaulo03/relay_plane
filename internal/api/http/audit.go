package http

import (
	"context"
	"log/slog"
	nethttp "net/http"
	"strconv"
	"strings"
	"time"

	"github.com/relayplane/relayplane/internal/core/errs"
	"github.com/relayplane/relayplane/internal/core/ids"
	"github.com/relayplane/relayplane/internal/ports"
)

// auditedTenantRoutes are the tenant requests that change who can act or what is kept: credentials, where events go and with
// which secret, erasure, and the deletion of an instance. Admin requests are always audited.
var auditedTenantRoutes = map[string]bool{
	"POST /api/v1/api-keys":                         true,
	"DELETE /api/v1/api-keys/{id}":                  true,
	"POST /api/v1/subscriptions":                    true,
	"DELETE /api/v1/subscriptions/{id}":             true,
	"POST /api/v1/subscriptions/{id}/rotate-secret": true,
	"DELETE /api/v1/contacts/{number}/data":         true,
	"DELETE /api/v1/instances/{id}":                 true,
	"POST /api/v1/instances/{id}/logout":            true,
	"POST /api/v1/instances/{id}/migrate":           true,
	"POST /api/v1/subscriptions/{id}/pause":         true,
	"POST /api/v1/subscriptions/{id}/resume":        true,
	"PUT /api/v1/instances/{id}/rate-policy":        true,
}

func audited(p Principal, r *nethttp.Request) bool {
	return p.Role == RoleAdmin || auditedTenantRoutes[r.Pattern]
}

// audit records the request after it was answered. A failure to store it is logged and counted, never turned into an error
// for a request that already happened.
func (s *Server) audit(r *nethttp.Request, p Principal, status int, requestID string) {
	e := ports.AuditEntry{ID: ids.New("aud"), At: time.Now().UTC(), Actor: string(p.Role), TenantID: p.TenantID, KeyID: p.KeyID,
		Route: r.Pattern, Target: r.PathValue("id"), Status: status, RequestID: requestID}
	if p.Role == RoleAdmin {
		e.KeyID = ""
		if p.PreviousAdminKey {
			e.Actor = "admin-previous"
		}
		// an admin acting on a tenant: file the entry under that tenant too
		if strings.HasPrefix(r.Pattern, "POST /api/v1/tenants/{id}") || strings.HasPrefix(r.Pattern, "PUT /api/v1/tenants/{id}") {
			e.TenantID = e.Target
		}
	}
	ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), 5*time.Second)
	defer cancel()
	if err := s.App.Deps.Repos.Audit.Append(ctx, e); err != nil {
		if s.Metrics != nil {
			s.Metrics.AuditWriteFailures.Inc()
		}
		s.Log.LogAttrs(ctx, slog.LevelError, "audit entry not stored", slog.String("route", e.Route), slog.String("actor", e.Actor),
			slog.String("tenant_id", e.TenantID), slog.Int("status", e.Status), slog.String("error", err.Error()))
		return
	}
	if p.PreviousAdminKey {
		s.Log.LogAttrs(ctx, slog.LevelWarn, "request authenticated with ADMIN_API_KEY_PREVIOUS: move this client to the new admin key",
			slog.String("route", e.Route), slog.String("request_id", e.RequestID))
	}
}

func (s *Server) adminAuthFailed(r *nethttp.Request) {
	if s.Metrics != nil {
		s.Metrics.AdminAuthFailures.Inc()
	}
	s.Log.LogAttrs(r.Context(), slog.LevelWarn, "admin route refused: missing or wrong credential", slog.String("route", r.Pattern),
		slog.String("remote", r.RemoteAddr))
}

type auditPage struct {
	Entries    []auditView `json:"entries"`
	NextBefore string      `json:"next_before,omitempty"`
}

type auditView struct {
	ID        string    `json:"id"`
	At        time.Time `json:"at"`
	Actor     string    `json:"actor"`
	TenantID  string    `json:"tenant_id,omitempty"`
	KeyID     string    `json:"key_id,omitempty"`
	Route     string    `json:"route"`
	Target    string    `json:"target,omitempty"`
	Status    int       `json:"status"`
	RequestID string    `json:"request_id,omitempty"`
}

// listAudit: GET /api/v1/audit?tenant_id=&before=<RFC 3339>&limit= (admin), newest first.
func (s *Server) listAudit(w nethttp.ResponseWriter, r *nethttp.Request, _ Principal) {
	q := r.URL.Query()
	f := ports.AuditFilter{TenantID: q.Get("tenant_id"), Limit: 100}
	if v := q.Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > 500 {
			writeError(w, r, s.Log, errs.Wrap(errs.ErrInvalidArgument, "limit must be between 1 and 500"))
			return
		}
		f.Limit = n
	}
	if v := q.Get("before"); v != "" {
		t, err := time.Parse(time.RFC3339Nano, v)
		if err != nil {
			writeError(w, r, s.Log, errs.Wrap(errs.ErrInvalidArgument, "before must be an RFC 3339 timestamp"))
			return
		}
		f.Before = t
	}
	entries, err := s.App.Deps.Repos.Audit.List(r.Context(), f)
	if err != nil {
		writeError(w, r, s.Log, err)
		return
	}
	page := auditPage{Entries: make([]auditView, 0, len(entries))}
	for _, e := range entries {
		page.Entries = append(page.Entries, auditView(e))
	}
	if len(entries) == f.Limit {
		page.NextBefore = entries[len(entries)-1].At.Format(time.RFC3339Nano)
	}
	writeJSON(w, 200, page)
}
