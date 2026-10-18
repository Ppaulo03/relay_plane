-- Append-only log of privileged actions: every admin request and the security-relevant requests of tenants (API keys,
-- subscriptions and their secrets, contact erasure, instance deletion). No request bodies, secrets or phone numbers: the route
-- pattern and the resource id of the path only. Kept for RETENTION_AUDIT (default 365 days).
CREATE TABLE audit_log (
    id         text        PRIMARY KEY,
    at         timestamptz NOT NULL,
    actor      text        NOT NULL,
    tenant_id  text        NOT NULL DEFAULT '',
    key_id     text        NOT NULL DEFAULT '',
    route      text        NOT NULL,
    target     text        NOT NULL DEFAULT '',
    status     integer     NOT NULL,
    request_id text        NOT NULL DEFAULT ''
);
CREATE INDEX audit_log_at ON audit_log (at DESC, id DESC);
CREATE INDEX audit_log_tenant_at ON audit_log (tenant_id, at DESC, id DESC);
