package eval

import (
	"testing"
	"time"

	"securitylens/internal/model"
	"securitylens/internal/store"
)

func TestScoreClassification(t *testing.T) {
	t0 := time.Date(2026, 6, 1, 10, 0, 0, 0, time.UTC)
	attacks := []store.Attack{
		{AttackID: "a1", AttackType: model.TypeCredentialStuffing, Entity: "6.6.6.6",
			TSStart: t0, TSEnd: t0.Add(5 * time.Minute)},
		{AttackID: "a2", AttackType: model.TypeDataExfiltration, Entity: "mallory",
			TSStart: t0.Add(2 * time.Hour), TSEnd: t0.Add(2*time.Hour + 10*time.Minute)},
	}
	alerts := []model.Alert{
		// exact TP
		{AlertType: model.TypeCredentialStuffing, Entity: "6.6.6.6", SrcIP: "6.6.6.6",
			WindowStart: t0, WindowEnd: t0.Add(4 * time.Minute)},
		// cross-type TP: identity alert on the breakthrough victim carries the attacker IP
		{AlertType: model.TypeIdentityAnomaly, Entity: "victim", Username: "victim", SrcIP: "6.6.6.6",
			WindowStart: t0.Add(4 * time.Minute), WindowEnd: t0.Add(6 * time.Minute)},
		// benign FP: right entity type, no attack anywhere near
		{AlertType: model.TypeOffHoursAccess, Entity: "innocent", Username: "innocent",
			WindowStart: t0.Add(30 * time.Hour), WindowEnd: t0.Add(30*time.Hour + 5*time.Minute)},
	}
	r := Score(attacks, alerts, 10*time.Minute)

	if r.Overall.Attacks != 2 || r.Overall.Detected != 1 {
		t.Fatalf("detection wrong: %+v (a2 has no exfil alert)", r.Overall)
	}
	if r.Overall.TP != 1 || r.Overall.CrossTP != 1 || r.BenignFP != 1 {
		t.Fatalf("classification wrong: TP=%d cross=%d FP=%d", r.Overall.TP, r.Overall.CrossTP, r.BenignFP)
	}
	if len(r.MissedAttacks) != 1 || r.MissedAttacks[0] != "a2" {
		t.Fatalf("missed attacks wrong: %v", r.MissedAttacks)
	}
	if r.TypeExactPrecision <= 0.32 || r.TypeExactPrecision >= 0.35 {
		t.Fatalf("type-exact precision want 1/3, got %f", r.TypeExactPrecision)
	}
	if r.OperationalPrecision <= 0.66 || r.OperationalPrecision >= 0.67 {
		t.Fatalf("operational precision want 2/3, got %f", r.OperationalPrecision)
	}
}

func TestScoreTimePad(t *testing.T) {
	t0 := time.Date(2026, 6, 1, 10, 0, 0, 0, time.UTC)
	attacks := []store.Attack{{AttackID: "a1", AttackType: model.TypeLateralMovement, Entity: "eve",
		TSStart: t0, TSEnd: t0.Add(5 * time.Minute)}}
	// alert window slightly after the manifest span: inside pad → detected
	alerts := []model.Alert{{AlertType: model.TypeLateralMovement, Entity: "eve", Username: "eve",
		WindowStart: t0.Add(7 * time.Minute), WindowEnd: t0.Add(9 * time.Minute)}}
	if r := Score(attacks, alerts, 10*time.Minute); r.Overall.Detected != 1 {
		t.Fatalf("pad should allow near-miss overlap: %+v", r.Overall)
	}
	if r := Score(attacks, alerts, time.Minute); r.Overall.Detected != 0 {
		t.Fatalf("tight pad should reject: %+v", r.Overall)
	}
}
