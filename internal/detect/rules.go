package detect

import (
	"fmt"
	"sort"

	"securitylens/internal/model"
)

// CredentialStuffing: many failed logins from one source IP against many
// accounts within a window.
type CredentialStuffing struct{ Th Thresholds }

func (d *CredentialStuffing) Name() string { return "credential_stuffing" }

func (d *CredentialStuffing) Detect(w Window, events []model.LogEvent, _ *BaselineView) []model.Candidate {
	type agg struct {
		fails []model.LogEvent
		users map[string]bool
	}
	byIP := map[string]*agg{}
	for _, e := range events {
		if e.Status != model.StatusFailure || e.SrcIP == "" {
			continue
		}
		if e.EventType != model.EvConsoleLogin && e.EventType != model.EvSSHLogin {
			continue
		}
		a := byIP[e.SrcIP]
		if a == nil {
			a = &agg{users: map[string]bool{}}
			byIP[e.SrcIP] = a
		}
		a.fails = append(a.fails, e)
		a.users[e.Username] = true
	}
	var out []model.Candidate
	for ip, a := range byIP {
		if len(a.fails) < d.Th.StuffingFailures || len(a.users) < d.Th.StuffingMinUsers {
			continue
		}
		start, end := span(a.fails)
		out = append(out, model.Candidate{
			AlertType: model.TypeCredentialStuffing,
			Severity:  model.SevHigh,
			Entity:    ip,
			SrcIP:     ip,
			Title:     fmt.Sprintf("Credential stuffing: %d failed logins from %s", len(a.fails), ip),
			EvStart:   start, EvEnd: end,
			Evidence: model.Evidence{
				Counts: map[string]int64{"failed_logins": int64(len(a.fails)), "distinct_users": int64(len(a.users))},
				Notes: []string{fmt.Sprintf("%d distinct accounts targeted from a single source in %s",
					len(a.users), end.Sub(start).Round(1e9))},
				Samples: sampleEvents(a.fails, 5),
			},
		})
	}
	sortCands(out)
	return out
}

// PrivilegeEscalation: a successful permission change where the actor granted
// an elevated right to themselves.
type PrivilegeEscalation struct{}

func (d *PrivilegeEscalation) Name() string { return "privilege_escalation" }

var elevatedPerms = map[string]bool{"admin": true, "root": true, "*": true, "iam_full": true, "owner": true}

func (d *PrivilegeEscalation) Detect(w Window, events []model.LogEvent, _ *BaselineView) []model.Candidate {
	byUser := map[string][]model.LogEvent{}
	for _, e := range events {
		if e.EventType != model.EvPermissionChange || e.Status != model.StatusSuccess {
			continue
		}
		if e.Extra["target_user"] != e.Username || !elevatedPerms[e.Extra["permission"]] {
			continue
		}
		byUser[e.Username] = append(byUser[e.Username], e)
	}
	var out []model.Candidate
	for u, evs := range byUser {
		start, end := span(evs)
		out = append(out, model.Candidate{
			AlertType: model.TypePrivilegeEscalation,
			Severity:  model.SevCritical,
			Entity:    u,
			Username:  u,
			SrcIP:     evs[0].SrcIP,
			Title:     fmt.Sprintf("Privilege escalation: %s self-granted %q", u, evs[0].Extra["permission"]),
			EvStart:   start, EvEnd: end,
			Evidence: model.Evidence{
				Counts:  map[string]int64{"self_grants": int64(len(evs))},
				Notes:   []string{"actor and target of the permission change are the same principal"},
				Samples: sampleEvents(evs, 5),
			},
		})
	}
	sortCands(out)
	return out
}

// LateralMovement: one identity reaching many distinct hosts over SSH in a
// burst. Only successful SSH counts; API calls carry no destination host.
type LateralMovement struct{ Th Thresholds }

func (d *LateralMovement) Name() string { return "lateral_movement" }

func (d *LateralMovement) Detect(w Window, events []model.LogEvent, _ *BaselineView) []model.Candidate {
	type agg struct {
		evs   []model.LogEvent
		hosts map[string]bool
	}
	byUser := map[string]*agg{}
	for _, e := range events {
		if e.EventType != model.EvSSHLogin || e.Status != model.StatusSuccess || e.Username == "" || e.DstHost == "" {
			continue
		}
		a := byUser[e.Username]
		if a == nil {
			a = &agg{hosts: map[string]bool{}}
			byUser[e.Username] = a
		}
		a.evs = append(a.evs, e)
		a.hosts[e.DstHost] = true
	}
	var out []model.Candidate
	for u, a := range byUser {
		if len(a.hosts) < d.Th.LateralDistinctHosts {
			continue
		}
		start, end := span(a.evs)
		out = append(out, model.Candidate{
			AlertType: model.TypeLateralMovement,
			Severity:  model.SevHigh,
			Entity:    u,
			Username:  u,
			SrcIP:     a.evs[0].SrcIP,
			Title:     fmt.Sprintf("Lateral movement: %s reached %d hosts in %s", u, len(a.hosts), end.Sub(start).Round(1e9)),
			EvStart:   start, EvEnd: end,
			Evidence: model.Evidence{
				Counts:  map[string]int64{"distinct_hosts": int64(len(a.hosts)), "ssh_logins": int64(len(a.evs))},
				Notes:   []string{"fan-out far exceeds the user's normal host set"},
				Samples: sampleEvents(a.evs, 5),
			},
		})
	}
	sortCands(out)
	return out
}

// DataExfiltration: outbound byte volume per user above threshold in a window.
type DataExfiltration struct{ Th Thresholds }

func (d *DataExfiltration) Name() string { return "data_exfiltration" }

func (d *DataExfiltration) Detect(w Window, events []model.LogEvent, _ *BaselineView) []model.Candidate {
	type agg struct {
		evs   []model.LogEvent
		bytes int64
	}
	byUser := map[string]*agg{}
	for _, e := range events {
		if e.EventType != model.EvDataTransfer || e.Username == "" {
			continue
		}
		a := byUser[e.Username]
		if a == nil {
			a = &agg{}
			byUser[e.Username] = a
		}
		a.evs = append(a.evs, e)
		a.bytes += e.BytesOut
	}
	var out []model.Candidate
	for u, a := range byUser {
		if a.bytes < d.Th.ExfilBytes {
			continue
		}
		start, end := span(a.evs)
		out = append(out, model.Candidate{
			AlertType: model.TypeDataExfiltration,
			Severity:  model.SevCritical,
			Entity:    u,
			Username:  u,
			SrcIP:     a.evs[0].SrcIP,
			Title:     fmt.Sprintf("Data exfiltration: %s moved %d MB outbound in %s", u, a.bytes/1_000_000, end.Sub(start).Round(1e9)),
			EvStart:   start, EvEnd: end,
			Evidence: model.Evidence{
				Counts:  map[string]int64{"bytes_out": a.bytes, "transfers": int64(len(a.evs))},
				Notes:   []string{fmt.Sprintf("outbound volume %.0fx the alerting threshold", float64(a.bytes)/float64(d.Th.ExfilBytes))},
				Samples: sampleEvents(a.evs, 5),
			},
		})
	}
	sortCands(out)
	return out
}

// sortCands keeps detector output deterministic (map iteration is not).
func sortCands(cs []model.Candidate) {
	sort.Slice(cs, func(i, j int) bool {
		if !cs[i].EvStart.Equal(cs[j].EvStart) {
			return cs[i].EvStart.Before(cs[j].EvStart)
		}
		return cs[i].Entity < cs[j].Entity
	})
}
