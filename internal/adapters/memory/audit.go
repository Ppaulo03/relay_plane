package memory

import (
	"context"
	"sort"
	"time"

	"github.com/relayplane/relayplane/internal/ports"
)

type auditRepo struct{ s *Store }

func (r auditRepo) Append(_ context.Context, e ports.AuditEntry) error {
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	r.s.audit = append(r.s.audit, e)
	return nil
}

func (r auditRepo) List(_ context.Context, f ports.AuditFilter) ([]ports.AuditEntry, error) {
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	var out []ports.AuditEntry
	for _, e := range r.s.audit {
		if (f.TenantID == "" || e.TenantID == f.TenantID) && (f.Before.IsZero() || e.At.Before(f.Before)) {
			out = append(out, e)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if !out[i].At.Equal(out[j].At) {
			return out[i].At.After(out[j].At)
		}
		return out[i].ID > out[j].ID
	})
	if f.Limit > 0 && len(out) > f.Limit {
		out = out[:f.Limit]
	}
	return out, nil
}

func (r auditRepo) PurgeBefore(_ context.Context, cutoff time.Time) (int64, error) {
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	kept, n := r.s.audit[:0], int64(0)
	for _, e := range r.s.audit {
		if e.At.Before(cutoff) {
			n++
			continue
		}
		kept = append(kept, e)
	}
	r.s.audit = kept
	return n, nil
}
