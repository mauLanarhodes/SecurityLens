// Package eval scores alerts against the ground-truth attack manifest.
// It is the only non-test package allowed to reason about attack labels.
package eval

import (
	"time"

	"securitylens/internal/model"
	"securitylens/internal/store"
)

// TypeScore is one row of the evaluation table.
type TypeScore struct {
	Attacks  int     `json:"attacks"`
	Detected int     `json:"detected"`
	Recall   float64 `json:"recall"`
	Alerts   int     `json:"alerts"`
	TP       int     `json:"tp"` // alerts matching a same-type attack
	FP       int     `json:"fp"` // alerts matching no attack at all (benign FP)
	CrossTP  int     `json:"cross_tp"` // alerts matching a different-type attack
}

// Result is the full evaluation output.
type Result struct {
	Dataset              string               `json:"dataset"`
	Logs                 int64                `json:"logs"`
	Windows              int                  `json:"windows"`
	DrainSeconds         float64              `json:"drain_seconds"`
	PerType              map[string]TypeScore `json:"per_type"`
	Overall              TypeScore            `json:"overall"`
	TypeExactPrecision   float64              `json:"type_exact_precision"`
	OperationalPrecision float64              `json:"operational_precision"`
	BenignFP             int                  `json:"benign_fp"`
	MissedAttacks        []string             `json:"missed_attacks,omitempty"`
	FalsePositiveIDs     []string             `json:"false_positive_ids,omitempty"`
}

// entityMatches: the alert points at the attack's entity, whichever field
// carries it (a stuffing attack is keyed on the attacker IP, which an
// identity-anomaly alert carries in src_ip).
func entityMatches(al model.Alert, atk store.Attack) bool {
	return al.Entity == atk.Entity || al.Username == atk.Entity || al.SrcIP == atk.Entity
}

func overlaps(al model.Alert, atk store.Attack, pad time.Duration) bool {
	return !al.WindowStart.After(atk.TSEnd.Add(pad)) && !al.WindowEnd.Before(atk.TSStart.Add(-pad))
}

// Score evaluates every alert and attack pairing with a time-overlap pad.
func Score(attacks []store.Attack, alerts []model.Alert, pad time.Duration) Result {
	r := Result{PerType: map[string]TypeScore{}}

	for _, t := range model.AllAlertTypes {
		r.PerType[t] = TypeScore{}
	}
	for _, atk := range attacks {
		s := r.PerType[atk.AttackType]
		s.Attacks++
		r.PerType[atk.AttackType] = s
	}

	// attack -> detected by a same-type alert
	for _, atk := range attacks {
		hit := false
		for _, al := range alerts {
			if al.AlertType == atk.AttackType && entityMatches(al, atk) && overlaps(al, atk, pad) {
				hit = true
				break
			}
		}
		s := r.PerType[atk.AttackType]
		if hit {
			s.Detected++
		} else {
			r.MissedAttacks = append(r.MissedAttacks, atk.AttackID)
		}
		r.PerType[atk.AttackType] = s
	}

	// alert -> exact TP / cross-type TP / benign FP
	for _, al := range alerts {
		s := r.PerType[al.AlertType]
		s.Alerts++
		exact, cross := false, false
		for _, atk := range attacks {
			if !entityMatches(al, atk) || !overlaps(al, atk, pad) {
				continue
			}
			if atk.AttackType == al.AlertType {
				exact = true
			} else {
				cross = true
			}
		}
		switch {
		case exact:
			s.TP++
		case cross:
			s.CrossTP++
		default:
			s.FP++
			r.BenignFP++
			r.FalsePositiveIDs = append(r.FalsePositiveIDs, al.ID)
		}
		r.PerType[al.AlertType] = s
	}

	for _, s := range r.PerType {
		r.Overall.Attacks += s.Attacks
		r.Overall.Detected += s.Detected
		r.Overall.Alerts += s.Alerts
		r.Overall.TP += s.TP
		r.Overall.FP += s.FP
		r.Overall.CrossTP += s.CrossTP
	}
	for t, s := range r.PerType {
		if s.Attacks > 0 {
			s.Recall = float64(s.Detected) / float64(s.Attacks)
		}
		r.PerType[t] = s
	}
	if r.Overall.Attacks > 0 {
		r.Overall.Recall = float64(r.Overall.Detected) / float64(r.Overall.Attacks)
	}
	if r.Overall.Alerts > 0 {
		r.TypeExactPrecision = float64(r.Overall.TP) / float64(r.Overall.Alerts)
		r.OperationalPrecision = float64(r.Overall.TP+r.Overall.CrossTP) / float64(r.Overall.Alerts)
	}
	return r
}
