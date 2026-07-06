// Package model defines the shared types that flow through SecurityLens:
// normalized log events, alert candidates, alerts, and incidents.
package model

import (
	"time"
)

// LogEvent is the normalized form every source (CloudTrail, SSH, nginx, app)
// is parsed into before detection. Detectors read ONLY operational fields;
// the ground-truth attack labels live in the database for the evaluator and
// are never present on this struct on the detection path.
type LogEvent struct {
	ID        int64             `json:"id"`
	TS        time.Time         `json:"ts"`
	Source    string            `json:"source"`     // cloudtrail | ssh | nginx | app
	EventType string            `json:"event_type"` // console_login, api_call, ssh_login, http_request, app_log, permission_change, data_transfer
	Username  string            `json:"username,omitempty"`
	SrcIP     string            `json:"src_ip,omitempty"`
	DstHost   string            `json:"dst_host,omitempty"`
	Status    string            `json:"status,omitempty"` // success | failure | denied | info
	BytesOut  int64             `json:"bytes_out,omitempty"`
	Message   string            `json:"message,omitempty"`
	Extra     map[string]string `json:"extra,omitempty"`
}

// Event types.
const (
	EvConsoleLogin     = "console_login"
	EvAPICall          = "api_call"
	EvSSHLogin         = "ssh_login"
	EvHTTPRequest      = "http_request"
	EvAppLog           = "app_log"
	EvPermissionChange = "permission_change"
	EvDataTransfer     = "data_transfer"
)

// Statuses.
const (
	StatusSuccess = "success"
	StatusFailure = "failure"
	StatusDenied  = "denied"
	StatusInfo    = "info"
)

// Alert types (one per detector).
const (
	TypeCredentialStuffing    = "credential_stuffing"
	TypePrivilegeEscalation   = "privilege_escalation"
	TypeSensitiveDataExposure = "sensitive_data_exposure"
	TypeIdentityAnomaly       = "identity_anomaly"
	TypeLateralMovement       = "lateral_movement"
	TypeOffHoursAccess        = "off_hours_access"
	TypeDataExfiltration      = "data_exfiltration"
)

// AllAlertTypes lists every detector-owned alert type.
var AllAlertTypes = []string{
	TypeCredentialStuffing,
	TypePrivilegeEscalation,
	TypeSensitiveDataExposure,
	TypeIdentityAnomaly,
	TypeLateralMovement,
	TypeOffHoursAccess,
	TypeDataExfiltration,
}

// Severities.
const (
	SevCritical = "critical"
	SevHigh     = "high"
	SevMedium   = "medium"
	SevLow      = "low"
)

// Evidence is the structured supporting data attached to an alert.
type Evidence struct {
	Counts  map[string]int64 `json:"counts,omitempty"`
	Notes   []string         `json:"notes,omitempty"`
	Samples []LogEvent       `json:"samples,omitempty"`
}

// Candidate is a detector finding before dedup/persistence.
type Candidate struct {
	AlertType string
	Severity  string
	Entity    string // canonical entity the alert is about (username or src IP)
	Username  string
	SrcIP     string
	Title     string
	EvStart   time.Time // event-time span of the supporting evidence
	EvEnd     time.Time
	Evidence  Evidence
}

// Alert is a persisted, deduplicated alert.
type Alert struct {
	ID          string     `json:"id"`
	CreatedAt   time.Time  `json:"created_at"`
	AlertType   string     `json:"alert_type"`
	Severity    string     `json:"severity"`
	Entity      string     `json:"entity"`
	Username    string     `json:"username,omitempty"`
	SrcIP       string     `json:"src_ip,omitempty"`
	Title       string     `json:"title"`
	Status      string     `json:"status"`
	Count       int        `json:"count"`
	WindowStart time.Time  `json:"window_start"`
	WindowEnd   time.Time  `json:"window_end"`
	DedupKey    string     `json:"dedup_key"`
	Evidence    *Evidence  `json:"evidence,omitempty"`
	Triage      *Triage    `json:"triage,omitempty"`
	IncidentID  string     `json:"incident_id,omitempty"`
}

// Triage is the LLM verdict attached to an alert.
type Triage struct {
	Verdict    string   `json:"verdict"` // likely_true_positive | likely_false_positive | needs_review
	Confidence float64  `json:"confidence"`
	Reasoning  string   `json:"reasoning"`
	NextSteps  []string `json:"next_steps"`
	Model      string   `json:"model"`
	Mock       bool     `json:"mock"`
	Cached     bool     `json:"cached"`
	At         time.Time `json:"at"`
}

// Incident is a correlated group of alerts on one entity.
type Incident struct {
	ID         string    `json:"id"`
	CreatedAt  time.Time `json:"created_at"`
	Entity     string    `json:"entity"`
	Title      string    `json:"title"`
	Severity   string    `json:"severity"`
	Status     string    `json:"status"`
	AlertCount int       `json:"alert_count"`
	FirstSeen  time.Time `json:"first_seen"`
	LastSeen   time.Time `json:"last_seen"`
	Alerts     []Alert   `json:"alerts,omitempty"`
}

// SeverityRank orders severities for max() comparisons.
func SeverityRank(s string) int {
	switch s {
	case SevCritical:
		return 4
	case SevHigh:
		return 3
	case SevMedium:
		return 2
	case SevLow:
		return 1
	}
	return 0
}
