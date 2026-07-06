package gen

import (
	"math/rand"
	"testing"
	"time"
)

// The zero-benign-FP result rests on these generator invariants; if one
// breaks, precision claims break with it.
func TestGeneratorInvariants(t *testing.T) {
	start := time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC)
	p := Params{Logs: 12000, Days: 10, Seed: 3, Start: start}
	ds := Generate(p)

	if len(ds.Events) < 11000 {
		t.Fatalf("too few events: %d", len(ds.Events))
	}
	types := map[string]int{}
	for _, a := range ds.Attacks {
		types[a.AttackType]++
		if a.TSStart.Before(start.AddDate(0, 0, attackDayMin)) {
			t.Fatalf("attack %s starts on day <%d (baseline warm-up violated): %s", a.AttackID, attackDayMin, a.TSStart)
		}
	}
	for _, typ := range []string{"credential_stuffing", "privilege_escalation", "sensitive_data_exposure",
		"identity_anomaly", "lateral_movement", "off_hours_access", "data_exfiltration"} {
		if types[typ] == 0 {
			t.Errorf("no %s attack generated", typ)
		}
	}

	// rebuild the fleet deterministically to know each user's benign origins
	g := &generator{r: rand.New(rand.NewSource(p.Seed)), p: p, usedIP: map[string]bool{}}
	g.makeFleet()
	origin := map[string]map[string]bool{}
	for _, u := range g.users {
		origin[u.name] = map[string]bool{u.homeIP: true}
		if u.officeIP != "" {
			origin[u.name][u.officeIP] = true
		}
	}

	for _, e := range ds.Events {
		if e.AttackID != "" {
			continue
		}
		// benign transfers stay far below the exfil threshold
		if e.EventType == "data_transfer" && e.BytesOut > 25_000_000 {
			t.Fatalf("benign transfer too large: %d bytes", e.BytesOut)
		}
		// benign auth/API/ssh traffic only ever comes from baseline origins
		switch e.EventType {
		case "console_login", "api_call", "ssh_login":
			if o, ok := origin[e.Username]; ok && e.SrcIP != "" && !o[e.SrcIP] {
				t.Fatalf("benign %s for %s from non-baseline IP %s", e.EventType, e.Username, e.SrcIP)
			}
		}
	}
}

func TestGeneratorDeterministic(t *testing.T) {
	start := time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC)
	a := Generate(Params{Logs: 5000, Days: 7, Seed: 11, Start: start})
	b := Generate(Params{Logs: 5000, Days: 7, Seed: 11, Start: start})
	if len(a.Events) != len(b.Events) || len(a.Attacks) != len(b.Attacks) {
		t.Fatalf("same seed produced different sizes: %d/%d vs %d/%d",
			len(a.Events), len(a.Attacks), len(b.Events), len(b.Attacks))
	}
	for i := range a.Events {
		x, y := a.Events[i], b.Events[i]
		if !x.TS.Equal(y.TS) || x.Message != y.Message || x.Username != y.Username || x.AttackID != y.AttackID {
			t.Fatalf("event %d differs between runs", i)
		}
	}
	c := Generate(Params{Logs: 5000, Days: 7, Seed: 12, Start: start})
	if len(c.Events) == len(a.Events) && c.Events[100].Message == a.Events[100].Message &&
		c.Events[100].TS.Equal(a.Events[100].TS) {
		t.Fatal("different seeds produced suspiciously identical output")
	}
}
