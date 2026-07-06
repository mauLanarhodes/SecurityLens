package store

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"securitylens/internal/model"
)

// UpsertAlert persists a detector candidate with event-time dedup.
//
// Overlapping sweep windows fire the same burst more than once; and a burst
// straddling a window boundary can fire with slightly different evidence
// spans. Both collapse here: a candidate whose evidence span overlaps (within
// `pad`) an existing alert of the same type on the same entity merges into
// that alert instead of creating a new one. Returns the stored alert and
// whether it was newly created.
func (s *Store) UpsertAlert(ctx context.Context, c model.Candidate, pad time.Duration) (model.Alert, bool, error) {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return model.Alert{}, false, err
	}
	defer tx.Rollback(ctx)

	var existing model.Alert
	var evJSON []byte
	err = tx.QueryRow(ctx, `
		SELECT id, window_start, window_end, count, evidence
		FROM alerts
		WHERE alert_type = $1 AND entity = $2
		  AND window_start <= $3 AND window_end >= $4
		ORDER BY created_at LIMIT 1 FOR UPDATE`,
		c.AlertType, c.Entity, c.EvEnd.Add(pad), c.EvStart.Add(-pad)).
		Scan(&existing.ID, &existing.WindowStart, &existing.WindowEnd, &existing.Count, &evJSON)

	switch err {
	case nil:
		// Merge: extend the evidence span; bump count only when the span grows
		// (i.e. genuinely new activity, not the same burst seen again).
		newStart, newEnd := existing.WindowStart, existing.WindowEnd
		grew := false
		if c.EvStart.Before(newStart) {
			newStart, grew = c.EvStart, true
		}
		if c.EvEnd.After(newEnd) {
			newEnd, grew = c.EvEnd, true
		}
		count := existing.Count
		if grew {
			count++
		}
		// Keep whichever evidence covers more events.
		ev := evJSON
		if grew || len(evJSON) == 0 {
			ev, _ = json.Marshal(c.Evidence)
		}
		_, err = tx.Exec(ctx, `
			UPDATE alerts SET window_start=$2, window_end=$3, count=$4, evidence=$5, title=$6
			WHERE id=$1`,
			existing.ID, newStart, newEnd, count, ev, c.Title)
		if err != nil {
			return model.Alert{}, false, err
		}
		if err := tx.Commit(ctx); err != nil {
			return model.Alert{}, false, err
		}
		a, err := s.GetAlert(ctx, existing.ID)
		return a, false, err

	case pgx.ErrNoRows:
		a := model.Alert{
			ID:          uuid.NewString(),
			AlertType:   c.AlertType,
			Severity:    c.Severity,
			Entity:      c.Entity,
			Username:    c.Username,
			SrcIP:       c.SrcIP,
			Title:       c.Title,
			Status:      "open",
			Count:       1,
			WindowStart: c.EvStart,
			WindowEnd:   c.EvEnd,
			DedupKey:    fmt.Sprintf("%s|%s|%d", c.AlertType, c.Entity, c.EvStart.Unix()),
		}
		ev, _ := json.Marshal(c.Evidence)
		_, err = tx.Exec(ctx, `
			INSERT INTO alerts (id, alert_type, severity, entity, username, src_ip, title, status, count,
			                    window_start, window_end, dedup_key, evidence)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)
			ON CONFLICT (dedup_key) DO NOTHING`,
			a.ID, a.AlertType, a.Severity, a.Entity, a.Username, a.SrcIP, a.Title, a.Status, a.Count,
			a.WindowStart, a.WindowEnd, a.DedupKey, ev)
		if err != nil {
			return model.Alert{}, false, err
		}
		if err := tx.Commit(ctx); err != nil {
			return model.Alert{}, false, err
		}
		stored, err := s.GetAlert(ctx, a.ID)
		if err == pgx.ErrNoRows {
			// dedup_key conflict swallowed the insert; treat as merged
			return model.Alert{}, false, nil
		}
		return stored, true, err

	default:
		return model.Alert{}, false, err
	}
}

// CorrelateAlert attaches an alert to an open incident on a matching entity
// whose activity is within `gap` of the alert, creating one if none exists.
// An incident matches if its entity equals the alert's entity, username, or
// source IP — so a stuffing incident keyed on the attacker IP also absorbs
// the identity-anomaly alert raised on the victim account.
func (s *Store) CorrelateAlert(ctx context.Context, a model.Alert, gap time.Duration) (string, error) {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return "", err
	}
	defer tx.Rollback(ctx)

	ents := []string{a.Entity}
	if a.Username != "" && a.Username != a.Entity {
		ents = append(ents, a.Username)
	}
	if a.SrcIP != "" && a.SrcIP != a.Entity {
		ents = append(ents, a.SrcIP)
	}

	var incID string
	var sev string
	err = tx.QueryRow(ctx, `
		SELECT id, severity FROM incidents
		WHERE status = 'open' AND entity = ANY($1)
		  AND last_seen >= $2 AND first_seen <= $3
		ORDER BY created_at LIMIT 1 FOR UPDATE`,
		ents, a.WindowStart.Add(-gap), a.WindowEnd.Add(gap)).Scan(&incID, &sev)

	switch err {
	case pgx.ErrNoRows:
		incID = uuid.NewString()
		_, err = tx.Exec(ctx, `
			INSERT INTO incidents (id, entity, title, severity, status, alert_count, first_seen, last_seen)
			VALUES ($1,$2,$3,$4,'open',1,$5,$6)`,
			incID, a.Entity, "Incident: "+a.Title, a.Severity, a.WindowStart, a.WindowEnd)
	case nil:
		if model.SeverityRank(a.Severity) > model.SeverityRank(sev) {
			sev = a.Severity
		}
		_, err = tx.Exec(ctx, `
			UPDATE incidents SET
				alert_count = (SELECT count(*) FROM alerts WHERE incident_id = incidents.id) + 1,
				severity = $2,
				first_seen = least(first_seen, $3),
				last_seen = greatest(last_seen, $4)
			WHERE id = $1`, incID, sev, a.WindowStart, a.WindowEnd)
	default:
		return "", err
	}
	if err != nil {
		return "", err
	}
	if _, err := tx.Exec(ctx, `UPDATE alerts SET incident_id=$2 WHERE id=$1`, a.ID, incID); err != nil {
		return "", err
	}
	return incID, tx.Commit(ctx)
}

const alertCols = `id, created_at, alert_type, severity, entity, username, src_ip, title, status, count,
	window_start, window_end, dedup_key, evidence, triage, incident_id`

func scanAlert(row pgx.Row) (model.Alert, error) {
	var a model.Alert
	var ev, tr []byte
	var inc *string
	err := row.Scan(&a.ID, &a.CreatedAt, &a.AlertType, &a.Severity, &a.Entity, &a.Username, &a.SrcIP,
		&a.Title, &a.Status, &a.Count, &a.WindowStart, &a.WindowEnd, &a.DedupKey, &ev, &tr, &inc)
	if err != nil {
		return a, err
	}
	if len(ev) > 0 {
		a.Evidence = &model.Evidence{}
		_ = json.Unmarshal(ev, a.Evidence)
	}
	if len(tr) > 0 {
		a.Triage = &model.Triage{}
		_ = json.Unmarshal(tr, a.Triage)
	}
	if inc != nil {
		a.IncidentID = *inc
	}
	for _, t := range []*time.Time{&a.CreatedAt, &a.WindowStart, &a.WindowEnd} {
		*t = t.UTC()
	}
	return a, nil
}

func (s *Store) GetAlert(ctx context.Context, id string) (model.Alert, error) {
	return scanAlert(s.Pool.QueryRow(ctx, `SELECT `+alertCols+` FROM alerts WHERE id=$1`, id))
}

// AlertFilter narrows ListAlerts.
type AlertFilter struct {
	Status    string
	AlertType string
	Limit     int
}

func (s *Store) ListAlerts(ctx context.Context, f AlertFilter) ([]model.Alert, error) {
	q := `SELECT ` + alertCols + ` FROM alerts WHERE 1=1`
	args := []any{}
	if f.Status != "" {
		args = append(args, f.Status)
		q += fmt.Sprintf(" AND status=$%d", len(args))
	}
	if f.AlertType != "" {
		args = append(args, f.AlertType)
		q += fmt.Sprintf(" AND alert_type=$%d", len(args))
	}
	limit := f.Limit
	if limit <= 0 || limit > 500 {
		limit = 200
	}
	q += fmt.Sprintf(" ORDER BY window_start DESC LIMIT %d", limit)
	rows, err := s.Pool.Query(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.Alert
	for rows.Next() {
		a, err := scanAlert(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

func (s *Store) SetAlertStatus(ctx context.Context, id, status string) error {
	ct, err := s.Pool.Exec(ctx, `UPDATE alerts SET status=$2 WHERE id=$1`, id, status)
	if err == nil && ct.RowsAffected() == 0 {
		return pgx.ErrNoRows
	}
	return err
}

func (s *Store) SetTriage(ctx context.Context, id string, t model.Triage) error {
	b, _ := json.Marshal(t)
	_, err := s.Pool.Exec(ctx, `UPDATE alerts SET triage=$2 WHERE id=$1`, id, b)
	return err
}

func (s *Store) ListIncidents(ctx context.Context, limit int) ([]model.Incident, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	rows, err := s.Pool.Query(ctx, `
		SELECT id, created_at, entity, title, severity, status, alert_count, first_seen, last_seen
		FROM incidents ORDER BY last_seen DESC LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.Incident
	for rows.Next() {
		var i model.Incident
		if err := rows.Scan(&i.ID, &i.CreatedAt, &i.Entity, &i.Title, &i.Severity, &i.Status,
			&i.AlertCount, &i.FirstSeen, &i.LastSeen); err != nil {
			return nil, err
		}
		out = append(out, i)
	}
	return out, rows.Err()
}

func (s *Store) GetIncident(ctx context.Context, id string) (model.Incident, error) {
	var i model.Incident
	err := s.Pool.QueryRow(ctx, `
		SELECT id, created_at, entity, title, severity, status, alert_count, first_seen, last_seen
		FROM incidents WHERE id=$1`, id).
		Scan(&i.ID, &i.CreatedAt, &i.Entity, &i.Title, &i.Severity, &i.Status,
			&i.AlertCount, &i.FirstSeen, &i.LastSeen)
	if err != nil {
		return i, err
	}
	rows, err := s.Pool.Query(ctx, `SELECT `+alertCols+` FROM alerts WHERE incident_id=$1 ORDER BY window_start`, id)
	if err != nil {
		return i, err
	}
	defer rows.Close()
	for rows.Next() {
		a, err := scanAlert(rows)
		if err != nil {
			return i, err
		}
		i.Alerts = append(i.Alerts, a)
	}
	return i, rows.Err()
}
