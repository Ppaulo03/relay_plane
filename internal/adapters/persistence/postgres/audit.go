package postgres

import (
	"context"
	"time"

	"github.com/relayplane/relayplane/internal/ports"
)

type auditRepo struct{ s *Store }

func (r auditRepo) Append(ctx context.Context, e ports.AuditEntry) error {
	_, err := r.s.pool.Exec(ctx, `INSERT INTO audit_log(id,at,actor,tenant_id,key_id,route,target,status,request_id)
		VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)`, e.ID, e.At, e.Actor, e.TenantID, e.KeyID, e.Route, e.Target, e.Status, e.RequestID)
	return err
}

func (r auditRepo) List(ctx context.Context, f ports.AuditFilter) ([]ports.AuditEntry, error) {
	limit := f.Limit
	if limit <= 0 {
		limit = 100
	}
	var before any
	if !f.Before.IsZero() {
		before = f.Before
	}
	rows, err := r.s.pool.Query(ctx, `SELECT id,at,actor,tenant_id,key_id,route,target,status,request_id FROM audit_log
		WHERE ($1 = '' OR tenant_id = $1) AND ($2::timestamptz IS NULL OR at < $2)
		ORDER BY at DESC, id DESC LIMIT $3`, f.TenantID, before, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ports.AuditEntry
	for rows.Next() {
		var e ports.AuditEntry
		if err := rows.Scan(&e.ID, &e.At, &e.Actor, &e.TenantID, &e.KeyID, &e.Route, &e.Target, &e.Status, &e.RequestID); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

func (r auditRepo) PurgeBefore(ctx context.Context, cutoff time.Time) (int64, error) {
	tag, err := r.s.pool.Exec(ctx, `DELETE FROM audit_log WHERE at < $1`, cutoff)
	return tag.RowsAffected(), err
}
