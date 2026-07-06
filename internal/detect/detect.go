// Package detect holds the detection engine's detectors and baselines.
//
// LABEL FIREWALL: nothing in this package may reference the ground-truth
// labels the synthetic dataset carries for evaluation. The invariant "no
// label-column reference anywhere under internal/detect/" is enforced by
// `make check-label-firewall`. Detectors see only operational fields.
package detect

import (
	"time"

	"securitylens/internal/model"
)

// Window is one event-time sweep window. Successive windows overlap by one
// step (length = 2 steps) so a burst shorter than the step is always fully
// contained in at least one window; event-time dedup collapses the duplicate
// firings downstream.
type Window struct {
	Start time.Time
	End   time.Time
}

// Detector is a pure function over one window's events. Implementations must
// not mutate shared state; stats detectors read a pre-fetched BaselineView.
type Detector interface {
	Name() string
	Detect(w Window, events []model.LogEvent, bl *BaselineView) []model.Candidate
}

// Thresholds centralizes every tunable so tests and tuning runs can vary them.
type Thresholds struct {
	StuffingFailures      int   // failed logins from one IP per window
	StuffingMinUsers      int   // distinct targeted accounts
	LateralDistinctHosts  int   // distinct ssh destinations per user per window
	ExfilBytes            int64 // outbound bytes per user per window
	IdentityMinLogins     int64 // baseline maturity: successful logins seen
	OffHoursMinEvents     int64 // baseline maturity: successful events seen
	OffHoursMinDays       int64 // baseline maturity: distinct active days
}

// Defaults returns the tuned production thresholds.
func Defaults() Thresholds {
	return Thresholds{
		StuffingFailures:     12,
		StuffingMinUsers:     5,
		LateralDistinctHosts: 6,
		ExfilBytes:           150_000_000,
		IdentityMinLogins:    5,
		OffHoursMinEvents:    40,
		OffHoursMinDays:      3,
	}
}

// All returns every production detector wired with thresholds th.
func All(th Thresholds) []Detector {
	return []Detector{
		&CredentialStuffing{th},
		&PrivilegeEscalation{},
		&LateralMovement{th},
		&DataExfiltration{th},
		&SensitiveDataExposure{},
		&IdentityAnomaly{th},
		&OffHoursAccess{th},
	}
}

// isSuccessfulAccess reports whether an event is a successful interactive
// access (login or API activity). Behavioural detectors deliberately ignore
// failed/denied events: a credential-stuffing burst lands failures on dozens
// of victims at one instant, and counting those as victim behaviour was the
// dominant false-positive source (see NOTES.md).
func isSuccessfulAccess(e model.LogEvent) bool {
	if e.Status != model.StatusSuccess {
		return false
	}
	switch e.EventType {
	case model.EvConsoleLogin, model.EvAPICall, model.EvSSHLogin:
		return true
	}
	return false
}

func sampleEvents(evs []model.LogEvent, n int) []model.LogEvent {
	if len(evs) <= n {
		out := make([]model.LogEvent, len(evs))
		copy(out, evs)
		return out
	}
	out := make([]model.LogEvent, 0, n)
	step := len(evs) / n
	for i := 0; i < len(evs) && len(out) < n; i += step {
		out = append(out, evs[i])
	}
	return out
}

func span(evs []model.LogEvent) (time.Time, time.Time) {
	min, max := evs[0].TS, evs[0].TS
	for _, e := range evs[1:] {
		if e.TS.Before(min) {
			min = e.TS
		}
		if e.TS.After(max) {
			max = e.TS
		}
	}
	return min, max
}
