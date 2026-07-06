// Package pipeline drives the detection engine: it sweeps event-time windows
// out of Postgres, fans each window out to every detector, dedups candidates
// into alerts, correlates alerts into incidents, and maintains baselines.
package pipeline

import (
	"context"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"

	"securitylens/internal/detect"
	"securitylens/internal/model"
	"securitylens/internal/store"
)

// MergePad is how close (in event time) two same-type/same-entity findings
// must be to merge into one alert.
const MergePad = 15 * time.Minute

// IncidentGap is the correlation window for grouping alerts into incidents.
const IncidentGap = time.Hour

const watermarkKey = "sweep_watermark"

type Pipeline struct {
	St        *store.Store
	Baselines *detect.Baselines
	Detectors []detect.Detector
	Step      time.Duration // windows are [t, t+2*Step), advancing by Step

	// OnAlert, if set, is called for every created or updated alert (SSE feed).
	OnAlert func(a model.Alert, created bool)
}

func New(st *store.Store, bl *detect.Baselines, step time.Duration, th detect.Thresholds) *Pipeline {
	return &Pipeline{St: st, Baselines: bl, Detectors: detect.All(th), Step: step}
}

// sweep runs detection over the window [start, start+2*Step) and then merges
// the window's leading step [start, start+Step) into the baselines. Detection
// always runs before the baseline update so an attack's own events can never
// vouch for themselves; the leading-step rule means every event is merged
// exactly once even though successive windows overlap.
func (p *Pipeline) sweep(ctx context.Context, start time.Time) (int, int, error) {
	w := detect.Window{Start: start, End: start.Add(2 * p.Step)}
	events, err := p.St.WindowEvents(ctx, w.Start, w.End)
	if err != nil {
		return 0, 0, err
	}
	alerts := 0
	if len(events) > 0 {
		view := p.Baselines.View()
		for _, d := range p.Detectors {
			for _, c := range d.Detect(w, events, view) {
				a, created, err := p.St.UpsertAlert(ctx, c, MergePad)
				if err != nil {
					return 0, 0, fmt.Errorf("upsert alert: %w", err)
				}
				if a.ID == "" { // lost a dedup race; another writer owns it
					continue
				}
				if _, err := p.St.CorrelateAlert(ctx, a, IncidentGap); err != nil {
					return 0, 0, fmt.Errorf("correlate: %w", err)
				}
				if created {
					alerts++
				}
				if p.OnAlert != nil {
					p.OnAlert(a, created)
				}
			}
		}
		lead := events[:0:0]
		cut := start.Add(p.Step)
		for _, e := range events {
			if e.TS.Before(cut) {
				lead = append(lead, e)
			}
		}
		if err := p.Baselines.Update(ctx, lead); err != nil {
			return 0, 0, fmt.Errorf("baseline update: %w", err)
		}
	}
	return len(events), alerts, nil
}

// Drain backfills detection over the entire log range (evaluator, first boot,
// integration test). It resets baselines and swept state first.
func (p *Pipeline) Drain(ctx context.Context) (windows int, events int, alerts int, err error) {
	min, max, ok, err := p.St.MinMaxLogTS(ctx)
	if err != nil || !ok {
		return 0, 0, 0, err
	}
	if err := p.Baselines.Reset(ctx); err != nil {
		return 0, 0, 0, err
	}
	start := min.Truncate(p.Step)
	for t := start; t.Before(max); t = t.Add(p.Step) {
		ne, na, err := p.sweep(ctx, t)
		if err != nil {
			return windows, events, alerts, err
		}
		windows++
		events += ne
		alerts += na
	}
	if err := p.St.SetState(ctx, watermarkKey, max.Truncate(p.Step).Add(p.Step).Format(time.RFC3339Nano)); err != nil {
		return windows, events, alerts, err
	}
	return windows, events, alerts, nil
}

const leaseKey = "pipeline_lease"
const leaseTTL = 30 * time.Second

// RunLive sweeps newly-settled windows on a ticker. A window [t, t+2*Step) is
// settled once now-lag >= t+2*Step. The watermark (next window start) is
// persisted so restarts resume where they left off.
//
// A Redis single-writer lease ensures only one pipeline instance sweeps at a
// time: two concurrent instances would race on the shared per-user baselines
// (each keeps its own in-memory copy while write-through mutating Redis),
// which produces spurious identity/off-hours alerts during warm-up. A second
// instance holds off until the lease lapses, then takes over from the
// persisted watermark.
func (p *Pipeline) RunLive(ctx context.Context, interval, lag time.Duration) {
	rdb := p.Baselines.Redis()
	owner, _ := os.Hostname()
	owner = fmt.Sprintf("%s/%s", owner, uuid.NewString()[:8])
	held := false
	if err := p.Baselines.Load(ctx); err != nil {
		log.Printf("pipeline: baseline load: %v", err)
	}
	tick := time.NewTicker(interval)
	defer tick.Stop()
	for {
		ok, err := acquireLease(ctx, rdb, owner, held)
		switch {
		case err != nil:
			log.Printf("pipeline: lease: %v", err)
		case !ok:
			if held {
				log.Printf("pipeline: lost single-writer lease, standing down")
			}
			held = false
		default:
			if !held {
				log.Printf("pipeline: acquired single-writer lease as %s", owner)
				// Reload baselines from Redis in case another writer advanced them.
				if err := p.Baselines.Load(ctx); err != nil {
					log.Printf("pipeline: baseline reload: %v", err)
				}
			}
			held = true
			if err := p.liveStep(ctx, lag); err != nil && ctx.Err() == nil {
				log.Printf("pipeline: %v", err)
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
	}
}

// acquireLease takes or renews the single-writer lease. If held, it renews
// (extending the TTL); otherwise it tries to claim a free slot.
func acquireLease(ctx context.Context, rdb *redis.Client, owner string, held bool) (bool, error) {
	if held {
		// Renew only if we still own it (compare-and-extend).
		cur, err := rdb.Get(ctx, leaseKey).Result()
		if err == redis.Nil {
			return rdb.SetNX(ctx, leaseKey, owner, leaseTTL).Result()
		}
		if err != nil {
			return false, err
		}
		if cur != owner {
			return false, nil
		}
		return rdb.Set(ctx, leaseKey, owner, leaseTTL).Err() == nil, nil
	}
	return rdb.SetNX(ctx, leaseKey, owner, leaseTTL).Result()
}

func (p *Pipeline) liveStep(ctx context.Context, lag time.Duration) error {
	var next time.Time
	if v, ok, err := p.St.GetState(ctx, watermarkKey); err != nil {
		return err
	} else if ok {
		next, err = time.Parse(time.RFC3339Nano, v)
		if err != nil {
			return err
		}
	} else {
		min, _, ok, err := p.St.MinMaxLogTS(ctx)
		if err != nil {
			return err
		}
		if !ok {
			return nil // no logs yet
		}
		// Fresh watermark means a fresh (or reseeded) dataset: stale baselines
		// from a previous dataset would mass-flag benign activity as new-origin
		// logins, so start the behavioural state from zero too.
		if err := p.Baselines.Reset(ctx); err != nil {
			return err
		}
		next = min.Truncate(p.Step)
	}
	for {
		settled := time.Now().UTC().Add(-lag)
		if !next.Add(2 * p.Step).Before(settled) {
			return nil
		}
		if _, _, err := p.sweep(ctx, next); err != nil {
			return err
		}
		next = next.Add(p.Step)
		if err := p.St.SetState(ctx, watermarkKey, next.Format(time.RFC3339Nano)); err != nil {
			return err
		}
	}
}
