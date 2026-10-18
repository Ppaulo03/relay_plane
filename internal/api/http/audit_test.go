package http_test

import (
	"context"
	"io"
	"log/slog"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"
	apihttp "github.com/relayplane/relayplane/internal/api/http"
	"github.com/relayplane/relayplane/internal/ports"
	"github.com/relayplane/relayplane/internal/systemtest"
)

func auditHarness(t *testing.T, auth apihttp.KeyAuthenticator) (*harness, *systemtest.Env) {
	t.Helper()
	e := systemtest.NewEnv(t)
	_, k1, _ := e.App.Tenants.Create(context.Background(), "t-one")
	auth.Tenants = e.App.Tenants
	api := &apihttp.Server{App: e.App, Metrics: e.Metrics, Log: slog.New(slog.NewTextHandler(io.Discard, nil)), MaxUpload: 1 << 20, Auth: auth}
	srv := httptest.NewServer(api.Handler())
	t.Cleanup(srv.Close)
	return &harness{t: t, env: e, srv: srv, key1: k1, admin: auth.AdminKey}, e
}

func auditEntries(t *testing.T, e *systemtest.Env) []ports.AuditEntry {
	t.Helper()
	got, err := e.App.Deps.Repos.Audit.List(context.Background(), ports.AuditFilter{Limit: 100})
	if err != nil {
		t.Fatal(err)
	}
	return got
}

// Rotating the admin key: the previous key keeps working next to the new one, and every use of it is visible in the audit log.
func TestAdminKeyRotationAcceptsBothKeysAndAuditsThePreviousOne(t *testing.T) {
	h, e := auditHarness(t, apihttp.KeyAuthenticator{AdminKey: "admin-key-new", PreviousAdminKey: "admin-key-old"})
	for _, k := range []string{"admin-key-new", "admin-key-old"} {
		if c, _, _ := h.call("GET", "/api/v1/nodes", k, ""); c != 200 {
			t.Fatalf("%s must be accepted during the rotation: %d", k, c)
		}
	}
	if c, _, _ := h.call("GET", "/api/v1/nodes", "admin-key-older", ""); c != 401 {
		t.Errorf("any other key is refused: %d", c)
	}
	got := auditEntries(t, e)
	if len(got) != 2 || got[0].Actor != "admin-previous" || got[1].Actor != "admin" || got[0].Route != "GET /api/v1/nodes" || got[0].Status != 200 {
		t.Fatalf("audit of the rotation: %+v", got)
	}
	if got[0].RequestID == "" {
		t.Error("the entry carries the request id (to find the request in the logs)")
	}
	// once the rotation is over (no previous key configured) the old key is just a wrong key
	h2, _ := auditHarness(t, apihttp.KeyAuthenticator{AdminKey: "admin-key-new"})
	if c, _, _ := h2.call("GET", "/api/v1/nodes", "admin-key-old", ""); c != 401 {
		t.Errorf("after the rotation the old key is refused: %d", c)
	}
}

// A previous key alone (no current admin key) must not open the admin API.
func TestPreviousAdminKeyAloneIsNotAnAdminKey(t *testing.T) {
	h, _ := auditHarness(t, apihttp.KeyAuthenticator{PreviousAdminKey: "admin-key-old"})
	if c, _, _ := h.call("GET", "/api/v1/nodes", "admin-key-old", ""); c != 401 {
		t.Errorf("previous key without a current one: %d", c)
	}
}

func TestAuditRecordsPrivilegedActionsOnly(t *testing.T) {
	h, e := auditHarness(t, apihttp.KeyAuthenticator{AdminKey: "admin-key"})
	c, body, _ := h.call("POST", "/api/v1/tenants", h.admin, `{"name":"acme"}`)
	if c != 201 {
		t.Fatalf("create tenant: %d %v", c, body)
	}
	tid := body["tenant_id"]
	if tid == nil {
		tid = body["id"]
	}
	if c, _, _ := h.call("POST", "/api/v1/tenants/"+tid.(string)+"/api-keys", h.admin, `{"name":"recovery"}`); c != 201 {
		t.Fatalf("admin issues a key: %d", c)
	}
	// tenant: a credential change is audited, everyday traffic is not
	if c, _, _ := h.call("POST", "/api/v1/api-keys", h.key1, `{"name":"second"}`); c != 201 {
		t.Fatalf("tenant key: %d", c)
	}
	h.call("GET", "/api/v1/instances", h.key1, "")
	h.call("GET", "/api/v1/limits", h.key1, "")
	// erasure is audited WITHOUT the number
	if c, _, _ := h.call("DELETE", "/api/v1/contacts/5562999999999/data", h.key1, ""); c/100 != 2 {
		t.Fatalf("erase: %d", c)
	}
	got := auditEntries(t, e)
	routes := []string{}
	for _, a := range got {
		routes = append(routes, a.Route)
		if strings.Contains(a.Target+a.Route+a.RequestID, "5562999999999") {
			t.Errorf("the audit log must never hold a phone number: %+v", a)
		}
	}
	want := []string{"DELETE /api/v1/contacts/{number}/data", "POST /api/v1/api-keys", "POST /api/v1/tenants/{id}/api-keys", "POST /api/v1/tenants"}
	if strings.Join(routes, ",") != strings.Join(want, ",") {
		t.Fatalf("audited routes (newest first):\n got %v\nwant %v", routes, want)
	}
	if got[2].TenantID != tid || got[2].Target != tid || got[2].Actor != "admin" {
		t.Errorf("an admin acting on a tenant is filed under that tenant: %+v", got[2])
	}
	if got[1].Actor != "tenant" || got[1].KeyID == "" || got[1].TenantID == "" || got[1].Status != 201 {
		t.Errorf("a tenant entry names the tenant and the key that acted: %+v", got[1])
	}
}

func TestAuditEndpointPagesNewestFirstAndCountsAdminAuthFailures(t *testing.T) {
	h, e := auditHarness(t, apihttp.KeyAuthenticator{AdminKey: "admin-key"})
	for i := 0; i < 3; i++ {
		h.call("GET", "/api/v1/nodes", h.admin, "")
	}
	c, body, _ := h.call("GET", "/api/v1/audit?limit=2", h.admin, "")
	entries, _ := body["entries"].([]any)
	if c != 200 || len(entries) != 2 || body["next_before"] == nil {
		t.Fatalf("first page: %d %v", c, body)
	}
	_, body, _ = h.call("GET", "/api/v1/audit?limit=10&before="+body["next_before"].(string), h.admin, "")
	if entries, _ := body["entries"].([]any); len(entries) < 1 {
		t.Errorf("second page: %v", body)
	}
	if c, _, _ := h.call("GET", "/api/v1/audit?limit=0", h.admin, ""); c != 400 {
		t.Errorf("limit out of range: %d", c)
	}
	if c, _, _ := h.call("GET", "/api/v1/audit", h.key1, ""); c != 403 {
		t.Errorf("tenants cannot read the audit log: %d", c)
	}
	h.call("GET", "/api/v1/audit", "wrong", "")
	if n := testutil.ToFloat64(e.Metrics.AdminAuthFailures); n != 2 {
		t.Errorf("admin auth failures counted: %v", n)
	}
}
