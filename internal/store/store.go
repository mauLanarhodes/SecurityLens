// Package store is the PostgreSQL access layer. All SQL lives here.
//
// Label firewall: WindowEvents and every other query used on the detection
// path selects only operational columns. The ground-truth columns
// (logs.attack_id, logs.attack_type, table attacks) are read exclusively by
// the evaluator and tests.
package store

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"securitylens/internal/model"
	"securitylens/migrations"
)

type Store struct {
	Pool *pgxpool.Pool
}

func New(ctx context.Context, dsn string) (*Store, error) {
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, fmt.Errorf("parse dsn: %w", err)
	}
	cfg.MaxConns = 10
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, err
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("ping: %w", err)
	}
	return &Store{Pool: pool}, nil
}

func (s *Store) Close() { s.Pool.Close() }

// Migrate applies every embedded migration in filename order. Migrations are
// idempotent, so this is safe on every boot.
func (s *Store) Migrate(ctx context.Context) error {
	entries, err := migrations.FS.ReadDir(".")
	if err != nil {
		return err
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".sql") {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)
	for _, n := range names {
		sql, err := migrations.FS.ReadFile(n)
		if err != nil {
			return err
		}
		if _, err := s.Pool.Exec(ctx, string(sql)); err != nil {
			return fmt.Errorf("migration %s: %w", n, err)
		}
	}
	return nil
}

func (s *Store) Health(ctx context.Context) error {
	return s.Pool.Ping(ctx)
}

// LabeledEvent carries a log event plus its ground-truth label for seeding.
type LabeledEvent struct {
	model.LogEvent
	AttackID   string
	AttackType string
}

// InsertLogEvents bulk-loads events via COPY.
func (s *Store) InsertLogEvents(ctx context.Context, events []LabeledEvent) (int64, error) {
	rows := make([][]any, len(events))
	for i, e := range events {
		var extra []byte
		if len(e.Extra) > 0 {
			extra, _ = json.Marshal(e.Extra)
		}
		rows[i] = []any{
			e.TS.UTC(), e.Source, e.EventType, e.Username, e.SrcIP, e.DstHost,
			e.Status, e.BytesOut, e.Message, extra, e.AttackID, e.AttackType,
		}
	}
	return s.Pool.CopyFrom(ctx, pgx.Identifier{"logs"},
		[]string{"ts", "source", "event_type", "username", "src_ip", "dst_host",
			"status", "bytes_out", "message", "extra", "attack_id", "attack_type"},
		pgx.CopyFromRows(rows))
}

// MinMaxLogTS returns the event-time range of the logs table.
func (s *Store) MinMaxLogTS(ctx context.Context) (time.Time, time.Time, bool, error) {
	var min, max *time.Time
	err := s.Pool.QueryRow(ctx, `SELECT min(ts), max(ts) FROM logs`).Scan(&min, &max)
	if err != nil {
		return time.Time{}, time.Time{}, false, err
	}
	if min == nil || max == nil {
		return time.Time{}, time.Time{}, false, nil
	}
	return min.UTC(), max.UTC(), true, nil
}

func (s *Store) CountLogs(ctx context.Context) (int64, error) {
	var n int64
	err := s.Pool.QueryRow(ctx, `SELECT count(*) FROM logs`).Scan(&n)
	return n, err
}

// WindowEvents loads the operational fields of all events in [start, end),
// ordered by time. Ground-truth label columns are deliberately not selected.
func (s *Store) WindowEvents(ctx context.Context, start, end time.Time) ([]model.LogEvent, error) {
	rows, err := s.Pool.Query(ctx, `
		SELECT id, ts, source, event_type, username, src_ip, dst_host, status, bytes_out, message, extra
		FROM logs WHERE ts >= $1 AND ts < $2 ORDER BY ts, id`, start, end)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanEvents(rows)
}

// RecentLogs returns the newest events for the dashboard feed.
func (s *Store) RecentLogs(ctx context.Context, limit int, source string) ([]model.LogEvent, error) {
	q := `SELECT id, ts, source, event_type, username, src_ip, dst_host, status, bytes_out, message, extra
	      FROM logs`
	args := []any{}
	if source != "" {
		q += ` WHERE source = $1`
		args = append(args, source)
	}
	q += fmt.Sprintf(` ORDER BY ts DESC, id DESC LIMIT %d`, limit)
	rows, err := s.Pool.Query(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	evs, err := scanEvents(rows)
	if err != nil {
		return nil, err
	}
	// reverse to chronological order
	for i, j := 0, len(evs)-1; i < j; i, j = i+1, j-1 {
		evs[i], evs[j] = evs[j], evs[i]
	}
	return evs, nil
}

// EntityActivity returns an entity's events around a time span (for the
// investigation endpoint).
func (s *Store) EntityActivity(ctx context.Context, username, srcIP string, start, end time.Time, limit int) ([]model.LogEvent, error) {
	rows, err := s.Pool.Query(ctx, `
		SELECT id, ts, source, event_type, username, src_ip, dst_host, status, bytes_out, message, extra
		FROM logs
		WHERE ts >= $1 AND ts < $2 AND (($3 <> '' AND username = $3) OR ($4 <> '' AND src_ip = $4))
		ORDER BY ts, id LIMIT $5`, start, end, username, srcIP, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanEvents(rows)
}

func scanEvents(rows pgx.Rows) ([]model.LogEvent, error) {
	var out []model.LogEvent
	for rows.Next() {
		var e model.LogEvent
		var extra []byte
		if err := rows.Scan(&e.ID, &e.TS, &e.Source, &e.EventType, &e.Username, &e.SrcIP,
			&e.DstHost, &e.Status, &e.BytesOut, &e.Message, &extra); err != nil {
			return nil, err
		}
		e.TS = e.TS.UTC()
		if len(extra) > 0 {
			_ = json.Unmarshal(extra, &e.Extra)
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// TimelinePoint is one bucket of the activity timeline.
type TimelinePoint struct {
	Bucket time.Time `json:"bucket"`
	Logs   int64     `json:"logs"`
	Alerts int64     `json:"alerts"`
}

// Timeline aggregates log and alert counts into hourly buckets.
func (s *Store) Timeline(ctx context.Context) ([]TimelinePoint, error) {
	rows, err := s.Pool.Query(ctx, `
		WITH l AS (
			SELECT date_trunc('hour', ts) b, count(*) n FROM logs GROUP BY 1
		), a AS (
			SELECT date_trunc('hour', window_start) b, count(*) n FROM alerts GROUP BY 1
		)
		SELECT l.b, l.n, COALESCE(a.n, 0) FROM l LEFT JOIN a ON a.b = l.b ORDER BY l.b`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []TimelinePoint
	for rows.Next() {
		var p TimelinePoint
		if err := rows.Scan(&p.Bucket, &p.Logs, &p.Alerts); err != nil {
			return nil, err
		}
		p.Bucket = p.Bucket.UTC()
		out = append(out, p)
	}
	return out, rows.Err()
}

// GetState / SetState store pipeline state such as the sweep watermark.
func (s *Store) GetState(ctx context.Context, key string) (string, bool, error) {
	var v string
	err := s.Pool.QueryRow(ctx, `SELECT value FROM detect_state WHERE key=$1`, key).Scan(&v)
	if err == pgx.ErrNoRows {
		return "", false, nil
	}
	return v, err == nil, err
}

func (s *Store) SetState(ctx context.Context, key, value string) error {
	_, err := s.Pool.Exec(ctx, `
		INSERT INTO detect_state (key, value) VALUES ($1,$2)
		ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value`, key, value)
	return err
}

// ResetDetections clears alerts, incidents, and pipeline state so a fresh
// drain (eval or integration test) starts from a clean slate.
func (s *Store) ResetDetections(ctx context.Context) error {
	_, err := s.Pool.Exec(ctx, `TRUNCATE alerts, incidents, detect_state`)
	return err
}

// ResetAll additionally clears logs and the attack manifest (used by the seeder).
func (s *Store) ResetAll(ctx context.Context) error {
	_, err := s.Pool.Exec(ctx, `TRUNCATE logs, attacks, alerts, incidents, detect_state, llm_usage`)
	return err
}
