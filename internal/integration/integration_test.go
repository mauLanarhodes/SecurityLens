//go:build integration

// End-to-end detection test: seeds a real Postgres + Redis with a labelled
// dataset, drains the pipeline exactly as cmd/eval does, and asserts 100%
// per-type recall with zero benign alerts, plus dedup stability (a second
// drain over the same data must not create new alerts).
package integration

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"

	"securitylens/internal/detect"
	"securitylens/internal/eval"
	"securitylens/internal/gen"
	"securitylens/internal/pipeline"
	"securitylens/internal/store"
)

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func TestEndToEndDetection(t *testing.T) {
	dsn := envOr("DATABASE_URL_TEST", "postgres://lens:lens@127.0.0.1:5432/securitylens_test?sslmode=disable")
	raddr := envOr("REDIS_ADDR", "127.0.0.1:6379")
	ctx := context.Background()

	st, err := store.New(ctx, dsn)
	if err != nil {
		t.Skipf("postgres not available: %v", err)
	}
	defer st.Close()
	// Redis DB 8 keeps test baselines away from the dev instance's state.
	rdb := redis.NewClient(&redis.Options{Addr: raddr, DB: 8})
	if err := rdb.Ping(ctx).Err(); err != nil {
		t.Skipf("redis not available: %v", err)
	}
	defer rdb.FlushDB(ctx)

	if err := st.Migrate(ctx); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	if err := st.ResetAll(ctx); err != nil {
		t.Fatalf("reset: %v", err)
	}

	ds := gen.Generate(gen.Params{Logs: 12000, Days: 8, Seed: 5,
		Start: time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC)})
	if _, err := st.InsertLogEvents(ctx, ds.Events); err != nil {
		t.Fatalf("insert: %v", err)
	}
	if err := st.InsertAttacks(ctx, ds.Attacks); err != nil {
		t.Fatalf("attacks: %v", err)
	}

	bl := detect.NewBaselines(rdb)
	p := pipeline.New(st, bl, 10*time.Minute, detect.Defaults())
	windows, events, created, err := p.Drain(ctx)
	if err != nil {
		t.Fatalf("drain: %v", err)
	}
	t.Logf("drained %d windows / %d window-events, %d alerts created", windows, events, created)

	attacks, err := st.ListAttacks(ctx)
	if err != nil {
		t.Fatal(err)
	}
	alerts, err := st.ListAlerts(ctx, store.AlertFilter{Limit: 500})
	if err != nil {
		t.Fatal(err)
	}
	r := eval.Score(attacks, alerts, 10*time.Minute)

	if r.Overall.Recall != 1 {
		t.Errorf("recall %.2f != 1.0; missed attacks: %v", r.Overall.Recall, r.MissedAttacks)
	}
	if r.BenignFP != 0 {
		t.Errorf("%d benign false positives: %v", r.BenignFP, r.FalsePositiveIDs)
	}
	for typ, s := range r.PerType {
		if s.Attacks > 0 && s.Detected < s.Attacks {
			t.Errorf("type %s: detected %d/%d", typ, s.Detected, s.Attacks)
		}
	}

	// correlation: every alert must belong to an incident
	incidents, err := st.ListIncidents(ctx, 500)
	if err != nil {
		t.Fatal(err)
	}
	if len(incidents) == 0 {
		t.Error("no incidents created")
	}
	for _, a := range alerts {
		if a.IncidentID == "" {
			t.Errorf("alert %s (%s) not correlated into an incident", a.ID, a.AlertType)
		}
	}

	// dedup stability: draining the same data again must merge, never duplicate
	before := len(alerts)
	if _, _, _, err := p.Drain(ctx); err != nil {
		t.Fatalf("second drain: %v", err)
	}
	alerts2, err := st.ListAlerts(ctx, store.AlertFilter{Limit: 500})
	if err != nil {
		t.Fatal(err)
	}
	if len(alerts2) != before {
		t.Errorf("second drain changed alert count: %d -> %d (dedup unstable)", before, len(alerts2))
	}
}
