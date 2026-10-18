package ports

import (
	"context"
	"time"
)

// AuditEntry records one privileged action: every request authenticated by the admin key and the security-relevant requests of a
// tenant (API keys, subscriptions and their secrets, contact erasure, instance deletion). It never holds a request body, a
// secret or a phone number: Route is the route pattern and Target the resource id taken from the path.
type AuditEntry struct {
	ID        string
	At        time.Time
	Actor     string // "admin", "admin-previous" (the key being rotated out) or "tenant"
	TenantID  string // the tenant that acted, or the tenant an admin acted upon when the path names one
	KeyID     string // the tenant API key that authenticated the request (empty for admins)
	Route     string // e.g. "POST /api/v1/tenants/{id}/api-keys"
	Target    string // the {id} of the path, when it has one
	Status    int    // HTTP status of the answer
	RequestID string
}

// AuditFilter selects entries, newest first.
type AuditFilter struct {
	TenantID string    // only this tenant's entries (empty: all)
	Before   time.Time // only entries strictly older (zero: from the newest)
	Limit    int
}

// AuditRepository is the append-only audit log.
type AuditRepository interface {
	Append(ctx context.Context, e AuditEntry) error
	// List returns entries newest first (ties broken by id, descending).
	List(ctx context.Context, f AuditFilter) ([]AuditEntry, error)
	// PurgeBefore deletes the entries older than cutoff and reports how many (the retention of the audit log).
	PurgeBefore(ctx context.Context, cutoff time.Time) (int64, error)
}
