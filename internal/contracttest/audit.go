package contracttest

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/relayplane/relayplane/internal/ports"
)

// The audit log: append-only, newest first, filterable by tenant, pageable by time, purged by age.
func auditContract(t *testing.T, f RepoFactory) {
	fx, ctx := newFixture(t, f), context.Background()
	repo := fx.r.Audit
	base := time.Now().UTC().Truncate(time.Millisecond)
	for i := 0; i < 5; i++ {
		tenant := "t1"
		if i%2 == 1 {
			tenant = "t2"
		}
		e := ports.AuditEntry{ID: fmt.Sprintf("aud_%d", i), At: base.Add(time.Duration(i) * time.Second), Actor: "admin", TenantID: tenant,
			Route: "POST /api/v1/tenants/{id}/api-keys", Target: tenant, Status: 201, RequestID: fmt.Sprintf("req_%d", i)}
		if err := repo.Append(ctx, e); err != nil {
			t.Fatal(err)
		}
	}
	all, err := repo.List(ctx, ports.AuditFilter{Limit: 10})
	if err != nil || len(all) != 5 || all[0].ID != "aud_4" || all[4].ID != "aud_0" {
		t.Fatalf("newest first: %+v %v", all, err)
	}
	if got := all[0]; got.Actor != "admin" || got.Route != "POST /api/v1/tenants/{id}/api-keys" || got.Status != 201 || got.RequestID != "req_4" || !got.At.Equal(base.Add(4*time.Second)) {
		t.Errorf("fields round-trip: %+v", got)
	}
	t1, _ := repo.List(ctx, ports.AuditFilter{TenantID: "t1", Limit: 10})
	if len(t1) != 3 {
		t.Errorf("filter by tenant: %d entries", len(t1))
	}
	page, _ := repo.List(ctx, ports.AuditFilter{Before: all[1].At, Limit: 2})
	if len(page) != 2 || page[0].ID != "aud_2" || page[1].ID != "aud_1" {
		t.Errorf("page before %v: %+v", all[1].At, page)
	}
	n, err := repo.PurgeBefore(ctx, base.Add(2*time.Second))
	if err != nil || n != 2 {
		t.Errorf("purge: %d %v", n, err)
	}
	if left, _ := repo.List(ctx, ports.AuditFilter{Limit: 10}); len(left) != 3 || left[2].ID != "aud_2" {
		t.Errorf("after purge: %+v", left)
	}
}
