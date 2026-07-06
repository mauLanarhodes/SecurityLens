package detect

import (
	"fmt"
	"sort"

	"securitylens/internal/model"
)

// IdentityAnomaly: a *successful* login from a source IP the user has never
// authenticated from. Failed logins from new IPs are ignored — that is
// credential-stuffing spillover, not victim behaviour. A maturity gate keeps
// brand-new users (no meaningful baseline yet) from alerting.
type IdentityAnomaly struct{ Th Thresholds }

func (d *IdentityAnomaly) Name() string { return "identity_anomaly" }

func (d *IdentityAnomaly) Detect(w Window, events []model.LogEvent, bl *BaselineView) []model.Candidate {
	type key struct{ user, ip string }
	byKey := map[key][]model.LogEvent{}
	for _, e := range events {
		if e.EventType != model.EvConsoleLogin || e.Status != model.StatusSuccess ||
			e.Username == "" || e.SrcIP == "" {
			continue
		}
		b := bl.User(e.Username)
		if b == nil || b.Logins < d.Th.IdentityMinLogins || b.IPs[e.SrcIP] {
			continue
		}
		k := key{e.Username, e.SrcIP}
		byKey[k] = append(byKey[k], e)
	}
	var out []model.Candidate
	for k, evs := range byKey {
		start, end := span(evs)
		b := bl.User(k.user)
		out = append(out, model.Candidate{
			AlertType: model.TypeIdentityAnomaly,
			Severity:  model.SevMedium,
			Entity:    k.user,
			Username:  k.user,
			SrcIP:     k.ip,
			Title:     fmt.Sprintf("Identity anomaly: %s authenticated from never-seen IP %s", k.user, k.ip),
			EvStart:   start, EvEnd: end,
			Evidence: model.Evidence{
				Counts: map[string]int64{"logins_from_new_ip": int64(len(evs)), "known_ips": int64(len(b.IPs))},
				Notes: []string{fmt.Sprintf("baseline holds %d known origin IPs from %d successful logins; %s is not among them",
					len(b.IPs), b.Logins, k.ip)},
				Samples: sampleEvents(evs, 5),
			},
		})
	}
	sortCands(out)
	return out
}

// OffHoursAccess: *successful* access in an hour of day where the user's
// baseline — and the two hours either side — show zero historical activity.
// The dead-band check separates true deep-night access from the first-ever
// event in a shoulder hour near the user's normal band. Counting only
// successes matters: a stuffing burst lands failures on victims at one
// instant, which is deep night for victims in negative-offset timezones.
type OffHoursAccess struct{ Th Thresholds }

func (d *OffHoursAccess) Name() string { return "off_hours_access" }

func (d *OffHoursAccess) Detect(w Window, events []model.LogEvent, bl *BaselineView) []model.Candidate {
	byUser := map[string][]model.LogEvent{}
	for _, e := range events {
		if !isSuccessfulAccess(e) || e.Username == "" {
			continue
		}
		b := bl.User(e.Username)
		if b == nil || b.Events < d.Th.OffHoursMinEvents || int64(len(b.Days)) < d.Th.OffHoursMinDays {
			continue
		}
		h := e.TS.UTC().Hour()
		dead := true
		for _, d := range []int{-2, -1, 0, 1, 2} {
			if b.Hours[((h+d)%24+24)%24] != 0 {
				dead = false
				break
			}
		}
		if dead {
			byUser[e.Username] = append(byUser[e.Username], e)
		}
	}
	var out []model.Candidate
	for u, evs := range byUser {
		start, end := span(evs)
		hours := map[int]bool{}
		for _, e := range evs {
			hours[e.TS.UTC().Hour()] = true
		}
		hs := make([]int, 0, len(hours))
		for h := range hours {
			hs = append(hs, h)
		}
		sort.Ints(hs)
		out = append(out, model.Candidate{
			AlertType: model.TypeOffHoursAccess,
			Severity:  model.SevMedium,
			Entity:    u,
			Username:  u,
			SrcIP:     evs[0].SrcIP,
			Title:     fmt.Sprintf("Off-hours access: %s active in hours with no historical activity", u),
			EvStart:   start, EvEnd: end,
			Evidence: model.Evidence{
				Counts: map[string]int64{"events": int64(len(evs))},
				Notes: []string{fmt.Sprintf("successful access at UTC hour(s) %v; user's baseline and adjacent hours are empty there", hs)},
				Samples: sampleEvents(evs, 5),
			},
		})
	}
	sortCands(out)
	return out
}
