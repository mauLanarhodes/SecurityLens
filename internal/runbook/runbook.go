// Package runbook provides the per-alert-type response runbooks served with
// every alert detail.
package runbook

import "securitylens/internal/model"

// Runbook is the analyst playbook for one alert type.
type Runbook struct {
	AlertType    string   `json:"alert_type"`
	Title        string   `json:"title"`
	Summary      string   `json:"summary"`
	Steps        []string `json:"steps"`
	EscalateWhen []string `json:"escalate_when"`
}

var books = map[string]Runbook{
	model.TypeCredentialStuffing: {
		Title:   "Credential stuffing / brute force",
		Summary: "Many failed logins against many accounts from one source IP.",
		Steps: []string{
			"Block or rate-limit the source IP at the edge (WAF / firewall)",
			"Check for any successful login from the same IP in the alert window — that account is breached",
			"Force password reset + session revocation for any breached account",
			"Search the IP against threat intel and prior alert history",
		},
		EscalateWhen: []string{
			"Any success from the attacking IP (breakthrough)",
			"The source is inside the corporate network",
		},
	},
	model.TypePrivilegeEscalation: {
		Title:   "Privilege escalation (self-grant)",
		Summary: "An identity granted itself an elevated permission.",
		Steps: []string{
			"Revert the permission change immediately",
			"Suspend the actor identity pending review",
			"Audit every action the identity took after the grant",
			"Determine how the identity obtained permission-change rights",
		},
		EscalateWhen: []string{
			"The identity used the elevated right before revert",
			"The change was made outside a change-management window",
		},
	},
	model.TypeSensitiveDataExposure: {
		Title:   "Sensitive data exposure",
		Summary: "Live credentials or PII observed in log output.",
		Steps: []string{
			"Rotate every exposed credential now — assume it is compromised",
			"Purge or redact the affected log entries at the source and in storage",
			"Identify the code path that logged the secret and fix it",
			"Check access logs for who read the exposed material",
		},
		EscalateWhen: []string{
			"The exposed credential shows use after the exposure time",
			"PII exposure that meets breach-notification thresholds",
		},
	},
	model.TypeIdentityAnomaly: {
		Title:   "Identity anomaly (new location)",
		Summary: "A successful authentication from an origin the user has never used.",
		Steps: []string{
			"Contact the user out-of-band to confirm the login",
			"Review activity performed from the new IP since login",
			"If unconfirmed, revoke sessions and reset credentials",
			"Check the IP against VPN/proxy and threat-intel lists",
		},
		EscalateWhen: []string{
			"The session performed privilege or data operations",
			"The same new IP appears across multiple accounts",
		},
	},
	model.TypeLateralMovement: {
		Title:   "Lateral movement",
		Summary: "One identity reached many hosts in a short burst.",
		Steps: []string{
			"Snapshot then isolate the source workstation/account",
			"Enumerate every host reached and check for dropped artifacts",
			"Review auth method used per hop (key, password, ticket)",
			"Hunt for the initial foothold in the hours before the burst",
		},
		EscalateWhen: []string{
			"Any reached host is a domain controller, DB, or secrets store",
			"Fan-out continues after containment",
		},
	},
	model.TypeOffHoursAccess: {
		Title:   "Off-hours access",
		Summary: "Successful access in hours where the user has no historical activity.",
		Steps: []string{
			"Confirm with the user/manager whether the activity was expected",
			"Review what was accessed during the off-hours session",
			"Correlate with travel, on-call, or maintenance schedules",
			"If unexplained, treat as a compromised credential",
		},
		EscalateWhen: []string{
			"Off-hours session touched sensitive data or admin surfaces",
			"Paired with a new-location anomaly for the same user",
		},
	},
	model.TypeDataExfiltration: {
		Title:   "Data exfiltration",
		Summary: "Outbound data volume far above any normal transfer for the identity.",
		Steps: []string{
			"Suspend the identity's egress (proxy block / credential freeze)",
			"Identify destination(s) and total bytes moved",
			"Determine what data source the transfers read from",
			"Preserve evidence: flow logs, storage access logs, endpoint state",
		},
		EscalateWhen: []string{
			"Destination is an unknown external service",
			"Transferred data includes regulated or customer data",
		},
	},
}

// For returns the runbook for an alert type (ok=false for unknown types).
func For(alertType string) (Runbook, bool) {
	rb, ok := books[alertType]
	if ok {
		rb.AlertType = alertType
	}
	return rb, ok
}

// All returns every runbook keyed by alert type.
func All() map[string]Runbook {
	out := make(map[string]Runbook, len(books))
	for k, v := range books {
		v.AlertType = k
		out[k] = v
	}
	return out
}
