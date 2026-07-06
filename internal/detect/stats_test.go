package detect

import (
	"context"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"

	"securitylens/internal/model"
)

// blWith builds an in-memory baseline view without Redis (write-through unused).
func blWith(users map[string]*UserBaseline) *BaselineView {
	return (&Baselines{users: users}).View()
}

func matureBaseline(ips []string, hours []int) *UserBaseline {
	ub := &UserBaseline{IPs: map[string]bool{}, Days: map[string]bool{"20260601": true, "20260602": true, "20260603": true}}
	for _, ip := range ips {
		ub.IPs[ip] = true
	}
	for _, h := range hours {
		ub.Hours[h] = 10
	}
	ub.Logins = 20
	ub.Events = 200
	return ub
}

func TestIdentityAnomalyNewIPSuccessOnly(t *testing.T) {
	d := &IdentityAnomaly{Defaults()}
	bl := blWith(map[string]*UserBaseline{
		"alice": matureBaseline([]string{"10.0.0.1", "10.0.0.2"}, []int{9, 10, 11}),
		"newbie": {IPs: map[string]bool{}, Days: map[string]bool{}}, // immature
	})
	evs := []model.LogEvent{
		ev(0, model.EvConsoleLogin, "alice", "66.66.66.66", "", model.StatusSuccess), // new IP: fires
		ev(1, model.EvConsoleLogin, "alice", "10.0.0.1", "", model.StatusSuccess),    // known IP
		ev(2, model.EvConsoleLogin, "alice", "77.77.77.77", "", model.StatusFailure), // stuffing spillover: ignored
		ev(3, model.EvConsoleLogin, "newbie", "88.88.88.88", "", model.StatusSuccess), // immature: gated
	}
	got := d.Detect(win(), evs, bl)
	if len(got) != 1 || got[0].Username != "alice" || got[0].SrcIP != "66.66.66.66" {
		t.Fatalf("want alice/66.66.66.66 only, got %+v", got)
	}
}

func TestOffHoursDeadBandAndSuccessOnly(t *testing.T) {
	d := &OffHoursAccess{Defaults()}
	// baseline active hours 8-18 UTC; shoulder 19-20 seen
	bl := blWith(map[string]*UserBaseline{
		"bob":  matureBaseline([]string{"10.0.0.3"}, []int{8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20}),
		"carol": matureBaseline([]string{"10.0.0.4"}, []int{8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18}),
	})
	at := func(user string, hour int, status string) model.LogEvent {
		e := ev(0, model.EvAPICall, user, "10.0.0.3", "", status)
		e.TS = time.Date(2026, 6, 4, hour, 30, 0, 0, time.UTC)
		return e
	}
	evs := []model.LogEvent{
		at("bob", 3, model.StatusSuccess),   // deep night, dead band: fires
		at("bob", 21, model.StatusSuccess),  // adjacent to populated 20: suppressed
		at("carol", 3, model.StatusFailure), // failure: never counts
		at("carol", 19, model.StatusSuccess), // first-ever evening shoulder, 18 populated: suppressed
	}
	got := d.Detect(Window{Start: evs[0].TS.Add(-10 * time.Minute), End: evs[0].TS.Add(10 * time.Minute)}, evs, bl)
	if len(got) != 1 || got[0].Username != "bob" {
		t.Fatalf("want bob only, got %+v", got)
	}
}

// TestBaselineConstruction verifies the write-through learner: successes feed
// the baseline, failures never do (a stuffing burst must not whitelist the
// attacker IP), and every counter lands where the detectors read it.
func TestBaselineConstruction(t *testing.T) {
	rdb := redis.NewClient(&redis.Options{Addr: redisAddr(), DB: 9})
	ctx := context.Background()
	if err := rdb.Ping(ctx).Err(); err != nil {
		t.Skipf("redis not available: %v", err)
	}
	defer rdb.FlushDB(ctx)

	b := NewBaselines(rdb)
	if err := b.Reset(ctx); err != nil {
		t.Fatal(err)
	}
	evs := []model.LogEvent{
		ev(0, model.EvConsoleLogin, "dave", "10.1.1.1", "", model.StatusSuccess),
		ev(1, model.EvAPICall, "dave", "10.1.1.2", "", model.StatusSuccess),
		ev(2, model.EvConsoleLogin, "dave", "6.6.6.6", "", model.StatusFailure), // must not learn
		ev(3, model.EvSSHLogin, "dave", "10.1.1.1", "web-01", model.StatusSuccess),
	}
	if err := b.Update(ctx, evs); err != nil {
		t.Fatal(err)
	}

	check := func(b *Baselines, label string) {
		ub := b.View().User("dave")
		if ub == nil {
			t.Fatalf("%s: no baseline", label)
		}
		if !ub.IPs["10.1.1.1"] || !ub.IPs["10.1.1.2"] {
			t.Fatalf("%s: missing learned IPs: %+v", label, ub.IPs)
		}
		if ub.IPs["6.6.6.6"] {
			t.Fatalf("%s: learned an IP from a FAILED login", label)
		}
		if ub.Logins != 1 || ub.Events != 3 {
			t.Fatalf("%s: logins=%d events=%d, want 1/3", label, ub.Logins, ub.Events)
		}
		if ub.Hours[t0.UTC().Hour()] == 0 {
			t.Fatalf("%s: hour histogram not updated", label)
		}
	}
	check(b, "in-memory")

	// a fresh process must reload identical state from Redis
	b2 := NewBaselines(rdb)
	if err := b2.Load(ctx); err != nil {
		t.Fatal(err)
	}
	check(b2, "reloaded")
}

func redisAddr() string {
	return "127.0.0.1:6379"
}
