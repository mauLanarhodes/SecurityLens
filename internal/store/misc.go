package store

import (
	"context"
	"encoding/json"
	"time"
)

// Attack is one row of the ground-truth manifest. Evaluation/tests only.
type Attack struct {
	AttackID    string    `json:"attack_id"`
	AttackType  string    `json:"attack_type"`
	Entity      string    `json:"entity"`
	TSStart     time.Time `json:"ts_start"`
	TSEnd       time.Time `json:"ts_end"`
	Description string    `json:"description"`
}

func (s *Store) InsertAttacks(ctx context.Context, atks []Attack) error {
	for _, a := range atks {
		if _, err := s.Pool.Exec(ctx, `
			INSERT INTO attacks (attack_id, attack_type, entity, ts_start, ts_end, description)
			VALUES ($1,$2,$3,$4,$5,$6) ON CONFLICT (attack_id) DO NOTHING`,
			a.AttackID, a.AttackType, a.Entity, a.TSStart.UTC(), a.TSEnd.UTC(), a.Description); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) ListAttacks(ctx context.Context) ([]Attack, error) {
	rows, err := s.Pool.Query(ctx, `
		SELECT attack_id, attack_type, entity, ts_start, ts_end, description FROM attacks ORDER BY ts_start`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Attack
	for rows.Next() {
		var a Attack
		if err := rows.Scan(&a.AttackID, &a.AttackType, &a.Entity, &a.TSStart, &a.TSEnd, &a.Description); err != nil {
			return nil, err
		}
		a.TSStart, a.TSEnd = a.TSStart.UTC(), a.TSEnd.UTC()
		out = append(out, a)
	}
	return out, rows.Err()
}

// LLMUsage is one recorded LLM invocation (or cache hit).
type LLMUsage struct {
	Feature      string
	Model        string
	Mock         bool
	Cached       bool
	InputTokens  int
	OutputTokens int
	LatencyMS    int
}

func (s *Store) InsertLLMUsage(ctx context.Context, u LLMUsage) error {
	_, err := s.Pool.Exec(ctx, `
		INSERT INTO llm_usage (feature, model, mock, cached, input_tokens, output_tokens, latency_ms)
		VALUES ($1,$2,$3,$4,$5,$6,$7)`,
		u.Feature, u.Model, u.Mock, u.Cached, u.InputTokens, u.OutputTokens, u.LatencyMS)
	return err
}

// LLMUsageSummary aggregates llm_usage for the metrics endpoint.
func (s *Store) LLMUsageSummary(ctx context.Context) (map[string]any, error) {
	rows, err := s.Pool.Query(ctx, `
		SELECT feature, count(*), count(*) FILTER (WHERE cached), count(*) FILTER (WHERE mock),
		       COALESCE(sum(input_tokens),0), COALESCE(sum(output_tokens),0), COALESCE(avg(latency_ms),0)
		FROM llm_usage GROUP BY feature ORDER BY feature`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	features := []map[string]any{}
	for rows.Next() {
		var feature string
		var calls, cached, mock, inTok, outTok int64
		var avgLat float64
		if err := rows.Scan(&feature, &calls, &cached, &mock, &inTok, &outTok, &avgLat); err != nil {
			return nil, err
		}
		features = append(features, map[string]any{
			"feature": feature, "calls": calls, "cached": cached, "mock": mock,
			"input_tokens": inTok, "output_tokens": outTok, "avg_latency_ms": avgLat,
		})
	}
	return map[string]any{"features": features}, rows.Err()
}

func (s *Store) InsertEvalRun(ctx context.Context, dataset string, result any) error {
	b, err := json.Marshal(result)
	if err != nil {
		return err
	}
	_, err = s.Pool.Exec(ctx, `INSERT INTO eval_runs (dataset, result) VALUES ($1,$2)`, dataset, b)
	return err
}

// EvalRun is a stored evaluation result.
type EvalRun struct {
	ID      int64           `json:"id"`
	TS      time.Time       `json:"ts"`
	Dataset string          `json:"dataset"`
	Result  json.RawMessage `json:"result"`
}

func (s *Store) LatestEvalRuns(ctx context.Context, limit int) ([]EvalRun, error) {
	if limit <= 0 {
		limit = 10
	}
	rows, err := s.Pool.Query(ctx, `SELECT id, ts, dataset, result FROM eval_runs ORDER BY ts DESC LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []EvalRun
	for rows.Next() {
		var r EvalRun
		if err := rows.Scan(&r.ID, &r.TS, &r.Dataset, &r.Result); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// AlertStats aggregates alert volume by type and severity for metrics.
func (s *Store) AlertStats(ctx context.Context) (map[string]any, error) {
	byType := map[string]int64{}
	rows, err := s.Pool.Query(ctx, `SELECT alert_type, count(*) FROM alerts GROUP BY 1`)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var t string
		var n int64
		if err := rows.Scan(&t, &n); err != nil {
			rows.Close()
			return nil, err
		}
		byType[t] = n
	}
	rows.Close()
	if rows.Err() != nil {
		return nil, rows.Err()
	}

	bySev := map[string]int64{}
	rows, err = s.Pool.Query(ctx, `SELECT severity, count(*) FROM alerts GROUP BY 1`)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var t string
		var n int64
		if err := rows.Scan(&t, &n); err != nil {
			rows.Close()
			return nil, err
		}
		bySev[t] = n
	}
	rows.Close()
	if rows.Err() != nil {
		return nil, rows.Err()
	}

	var total, open, dismissed int64
	err = s.Pool.QueryRow(ctx, `
		SELECT count(*), count(*) FILTER (WHERE status='open'), count(*) FILTER (WHERE status='dismissed')
		FROM alerts`).Scan(&total, &open, &dismissed)
	if err != nil {
		return nil, err
	}
	var incidents int64
	if err := s.Pool.QueryRow(ctx, `SELECT count(*) FROM incidents`).Scan(&incidents); err != nil {
		return nil, err
	}
	return map[string]any{
		"total": total, "open": open, "dismissed": dismissed,
		"by_type": byType, "by_severity": bySev, "incidents": incidents,
	}, nil
}
