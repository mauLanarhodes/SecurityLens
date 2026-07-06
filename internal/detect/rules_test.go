package detect

import (
	"fmt"
	"testing"
	"time"

	"securitylens/internal/model"
)

var t0 = time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)

func win() Window { return Window{Start: t0.Add(-10 * time.Minute), End: t0.Add(10 * time.Minute)} }

func ev(mins int, typ, user, ip, host, status string) model.LogEvent {
	return model.LogEvent{TS: t0.Add(time.Duration(mins) * time.Minute), EventType: typ,
		Username: user, SrcIP: ip, DstHost: host, Status: status}
}

func TestCredentialStuffingFires(t *testing.T) {
	d := &CredentialStuffing{Defaults()}
	var evs []model.LogEvent
	for i := 0; i < 20; i++ {
		evs = append(evs, ev(i%5, model.EvConsoleLogin, fmt.Sprintf("user%d", i), "9.9.9.9", "", model.StatusFailure))
	}
	got := d.Detect(win(), evs, nil)
	if len(got) != 1 {
		t.Fatalf("want 1 candidate, got %d", len(got))
	}
	if got[0].Entity != "9.9.9.9" || got[0].AlertType != model.TypeCredentialStuffing {
		t.Fatalf("wrong candidate: %+v", got[0])
	}
}

func TestCredentialStuffingIgnoresScatteredFailures(t *testing.T) {
	d := &CredentialStuffing{Defaults()}
	var evs []model.LogEvent
	// typos: each user fails once or twice from their own IP
	for i := 0; i < 30; i++ {
		evs = append(evs, ev(i%9, model.EvConsoleLogin, fmt.Sprintf("user%d", i), fmt.Sprintf("10.0.0.%d", i), "", model.StatusFailure))
	}
	// one user fails repeatedly from one IP (broken script) but hits only 1 account
	for i := 0; i < 15; i++ {
		evs = append(evs, ev(i%9, model.EvConsoleLogin, "scriptuser", "10.1.1.1", "", model.StatusFailure))
	}
	if got := d.Detect(win(), evs, nil); len(got) != 0 {
		t.Fatalf("want 0 candidates, got %+v", got)
	}
}

func TestPrivilegeEscalationSelfGrantOnly(t *testing.T) {
	d := &PrivilegeEscalation{}
	selfGrant := ev(1, model.EvPermissionChange, "mallory", "1.2.3.4", "", model.StatusSuccess)
	selfGrant.Extra = map[string]string{"target_user": "mallory", "permission": "admin"}
	benignGrant := ev(2, model.EvPermissionChange, "alice-admin", "1.2.3.5", "", model.StatusSuccess)
	benignGrant.Extra = map[string]string{"target_user": "bob", "permission": "admin"}
	deniedSelf := ev(3, model.EvPermissionChange, "carl", "1.2.3.6", "", model.StatusDenied)
	deniedSelf.Extra = map[string]string{"target_user": "carl", "permission": "admin"}
	smallSelf := ev(4, model.EvPermissionChange, "dora", "1.2.3.7", "", model.StatusSuccess)
	smallSelf.Extra = map[string]string{"target_user": "dora", "permission": "s3_read"}

	got := d.Detect(win(), []model.LogEvent{selfGrant, benignGrant, deniedSelf, smallSelf}, nil)
	if len(got) != 1 || got[0].Entity != "mallory" {
		t.Fatalf("want exactly mallory, got %+v", got)
	}
}

func TestLateralMovementFanOut(t *testing.T) {
	d := &LateralMovement{Defaults()}
	var evs []model.LogEvent
	for i := 0; i < 8; i++ {
		evs = append(evs, ev(i, model.EvSSHLogin, "eve", "10.0.0.5", fmt.Sprintf("web-%02d", i), model.StatusSuccess))
	}
	// benign: 3 hosts repeatedly
	for i := 0; i < 9; i++ {
		evs = append(evs, ev(i, model.EvSSHLogin, "norm", "10.0.0.6", fmt.Sprintf("db-%02d", i%3), model.StatusSuccess))
	}
	// failures to many hosts don't count
	for i := 0; i < 8; i++ {
		evs = append(evs, ev(i, model.EvSSHLogin, "fran", "10.0.0.7", fmt.Sprintf("app-%02d", i), model.StatusFailure))
	}
	got := d.Detect(win(), evs, nil)
	if len(got) != 1 || got[0].Entity != "eve" {
		t.Fatalf("want exactly eve, got %+v", got)
	}
}

func TestDataExfiltrationVolume(t *testing.T) {
	d := &DataExfiltration{Defaults()}
	var evs []model.LogEvent
	for i := 0; i < 10; i++ {
		e := ev(i, model.EvDataTransfer, "smuggler", "10.0.0.9", "", model.StatusSuccess)
		e.BytesOut = 60_000_000
		evs = append(evs, e)
	}
	for i := 0; i < 5; i++ {
		e := ev(i, model.EvDataTransfer, "norm", "10.0.0.10", "", model.StatusSuccess)
		e.BytesOut = 10_000_000
		evs = append(evs, e)
	}
	got := d.Detect(win(), evs, nil)
	if len(got) != 1 || got[0].Entity != "smuggler" {
		t.Fatalf("want exactly smuggler, got %+v", got)
	}
	if got[0].Evidence.Counts["bytes_out"] != 600_000_000 {
		t.Fatalf("bytes_out wrong: %+v", got[0].Evidence.Counts)
	}
}

func TestDetectorsAreDeterministic(t *testing.T) {
	d := &CredentialStuffing{Defaults()}
	var evs []model.LogEvent
	for ip := 0; ip < 3; ip++ {
		for i := 0; i < 20; i++ {
			evs = append(evs, ev(i%5, model.EvConsoleLogin, fmt.Sprintf("u%d", i), fmt.Sprintf("9.9.9.%d", ip), "", model.StatusFailure))
		}
	}
	a := d.Detect(win(), evs, nil)
	b := d.Detect(win(), evs, nil)
	if len(a) != 3 || len(b) != 3 {
		t.Fatalf("want 3 candidates, got %d/%d", len(a), len(b))
	}
	for i := range a {
		if a[i].Entity != b[i].Entity {
			t.Fatalf("nondeterministic order: %v vs %v", a[i].Entity, b[i].Entity)
		}
	}
}
