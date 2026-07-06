package gen

import (
	"fmt"
	"time"

	"securitylens/internal/model"
	"securitylens/internal/store"
)

// attackDayMin is the first day attacks may start: baselines (identity IPs,
// activity hours) are warmed up on days 0-2 by the forced baseline pass.
const attackDayMin = 3

// makeAttacks injects one attack of every type plus scale-dependent extras,
// each fully labelled and recorded in the manifest.
func (g *generator) makeAttacks() {
	types := append([]string{}, model.AllAlertTypes...)
	// extras grow slowly with dataset size; weighted toward the noisy types
	extraPool := []string{
		model.TypeCredentialStuffing, model.TypeDataExfiltration, model.TypePrivilegeEscalation,
		model.TypeCredentialStuffing, model.TypeIdentityAnomaly, model.TypeLateralMovement,
		model.TypeDataExfiltration, model.TypeOffHoursAccess, model.TypeSensitiveDataExposure,
		model.TypePrivilegeEscalation,
	}
	nExtra := 0
	for n := g.p.Logs; n > 6000 && nExtra < len(extraPool); n /= 3 {
		nExtra++
	}
	if g.p.Logs >= 15000 {
		nExtra += 2
	}
	if nExtra > len(extraPool) {
		nExtra = len(extraPool)
	}
	types = append(types, extraPool[:nExtra]...)

	// distinct victim per user-entity attack keeps evaluation unambiguous
	victims := g.r.Perm(len(g.users))
	vi := 0
	nextVictim := func() *user {
		u := &g.users[victims[vi%len(victims)]]
		vi++
		return u
	}

	span := g.p.Days - attackDayMin
	for i, t := range types {
		id := fmt.Sprintf("atk-%03d", i+1)
		day := attackDayMin + g.r.Intn(span)
		switch t {
		case model.TypeCredentialStuffing:
			g.attackStuffing(id, day)
		case model.TypePrivilegeEscalation:
			g.attackPrivEsc(id, day, nextVictim())
		case model.TypeSensitiveDataExposure:
			g.attackSecretLeak(id, day, nextVictim())
		case model.TypeIdentityAnomaly:
			g.attackNewLocation(id, day, nextVictim())
		case model.TypeLateralMovement:
			g.attackLateral(id, day, nextVictim())
		case model.TypeOffHoursAccess:
			g.attackOffHours(id, day, nextVictim())
		case model.TypeDataExfiltration:
			g.attackExfil(id, day, nextVictim())
		}
	}
}

func (g *generator) manifest(id, typ, entity, desc string, evStart, evEnd time.Time) {
	g.atks = append(g.atks, store.Attack{
		AttackID: id, AttackType: typ, Entity: entity,
		TSStart: evStart, TSEnd: evEnd, Description: desc,
	})
}

// attackStuffing sprays failed console logins against many accounts from one
// fresh IP; half the time the last victim is breached (a success from the
// attacker IP), which legitimately also reads as an identity anomaly.
func (g *generator) attackStuffing(id string, day int) {
	attacker := g.freshIP()
	nVictims := 18 + g.r.Intn(23)
	nFails := nVictims + 7 + g.r.Intn(20)
	perm := g.r.Perm(len(g.users))
	startHour := g.r.Intn(24)
	base := g.p.Start.AddDate(0, 0, day).Add(time.Duration(startHour)*time.Hour + time.Duration(g.r.Intn(60))*time.Minute)
	dur := time.Duration(150+g.r.Intn(180)) * time.Second

	var last time.Time
	for i := 0; i < nFails; i++ {
		v := &g.users[perm[i%nVictims]]
		ts := base.Add(time.Duration(float64(dur) * float64(i) / float64(nFails)))
		e := g.consoleLogin(v, ts, attacker, false)
		g.emit(e, id, model.TypeCredentialStuffing)
		last = ts
	}
	desc := fmt.Sprintf("credential stuffing: %d failed logins across %d accounts from %s", nFails, nVictims, attacker)
	if g.r.Float64() < 0.5 { // breakthrough
		v := &g.users[perm[0]]
		ts := last.Add(time.Duration(10+g.r.Intn(40)) * time.Second)
		g.emit(g.consoleLogin(v, ts, attacker, true), id, model.TypeCredentialStuffing)
		for j := 0; j < 2+g.r.Intn(3); j++ {
			ts = ts.Add(time.Duration(30+g.r.Intn(120)) * time.Second)
			g.emit(g.apiCall(v, ts, attacker), id, model.TypeCredentialStuffing)
		}
		last = ts
		desc += "; account " + v.name + " breached"
	}
	g.manifest(id, model.TypeCredentialStuffing, attacker, desc, base, last)
}

// attackPrivEsc: a user grants themselves admin, sometimes after a denied try.
func (g *generator) attackPrivEsc(id string, day int, u *user) {
	ts := g.localTS(u, day, u.workStart+g.r.Intn(6), g.r.Intn(60), g.r.Intn(60))
	ip := g.userIP(u)
	first := ts
	if g.r.Float64() < 0.4 {
		g.emit(g.permissionChange(u.name, u.name, "admin", ts, ip, model.StatusDenied), id, model.TypePrivilegeEscalation)
		ts = ts.Add(time.Duration(20+g.r.Intn(90)) * time.Second)
	}
	g.emit(g.permissionChange(u.name, u.name, "admin", ts, ip, model.StatusSuccess), id, model.TypePrivilegeEscalation)
	g.manifest(id, model.TypePrivilegeEscalation, u.name,
		fmt.Sprintf("privilege escalation: %s self-granted admin", u.name), first, ts)
}

// attackSecretLeak drops real-looking secrets into app logs.
func (g *generator) attackSecretLeak(id string, day int, u *user) {
	ts := g.localTS(u, day, u.workStart+g.r.Intn(7), g.r.Intn(60), g.r.Intn(60))
	secrets := []string{
		"ERROR credential rotation failed, key material in payload: aws_access_key_id=" + g.randKey("AKIA", 16),
		fmt.Sprintf("DEBUG dsn=postgres://svc_billing:p%dssw0rd!x@db-01:5432/prod", 4+g.r.Intn(5)),
		"WARN raw config dump: stripe_secret=sk_live_" + g.randKey("", 24),
	}
	n := 1 + g.r.Intn(3)
	first, last := ts, ts
	for i := 0; i < n; i++ {
		e := model.LogEvent{TS: ts, Source: "app", EventType: model.EvAppLog,
			Username: u.name, Status: model.StatusInfo, Message: secrets[i%len(secrets)]}
		g.emit(e, id, model.TypeSensitiveDataExposure)
		last = ts
		ts = ts.Add(time.Duration(30+g.r.Intn(300)) * time.Second)
	}
	g.manifest(id, model.TypeSensitiveDataExposure, u.name,
		fmt.Sprintf("sensitive data exposure: live credentials logged by %s", u.name), first, last)
}

func (g *generator) randKey(prefix string, n int) string {
	const chars = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
	b := []byte(prefix)
	for i := 0; i < n; i++ {
		b = append(b, chars[g.r.Intn(len(chars))])
	}
	return string(b)
}

// attackNewLocation: a successful login plus follow-on API calls from an IP
// the user has never used, during their normal working hours.
func (g *generator) attackNewLocation(id string, day int, u *user) {
	ip := g.freshIP()
	ts := g.localTS(u, day, u.workStart+1+g.r.Intn(5), g.r.Intn(60), g.r.Intn(60))
	first := ts
	g.emit(g.consoleLogin(u, ts, ip, true), id, model.TypeIdentityAnomaly)
	for j := 0; j < 2+g.r.Intn(3); j++ {
		ts = ts.Add(time.Duration(40+g.r.Intn(200)) * time.Second)
		g.emit(g.apiCall(u, ts, ip), id, model.TypeIdentityAnomaly)
	}
	g.manifest(id, model.TypeIdentityAnomaly, u.name,
		fmt.Sprintf("identity anomaly: %s authenticated from never-seen IP %s", u.name, ip), first, ts)
}

// attackLateral: a fan-out to far more hosts than the user's own set, from
// the user's usual IP (a compromised workstation), in working hours.
func (g *generator) attackLateral(id string, day int, u *user) {
	nHosts := 8 + g.r.Intn(7)
	perm := g.r.Perm(len(g.hosts))
	ip := g.userIP(u)
	ts := g.localTS(u, day, u.workStart+1+g.r.Intn(5), g.r.Intn(60), g.r.Intn(60))
	first := ts
	for i := 0; i < nHosts; i++ {
		host := g.hosts[perm[i]]
		g.emit(g.sshLogin(u, ts, ip, host, true), id, model.TypeLateralMovement)
		ts = ts.Add(time.Duration(20+g.r.Intn(80)) * time.Second)
	}
	g.manifest(id, model.TypeLateralMovement, u.name,
		fmt.Sprintf("lateral movement: %s reached %d distinct hosts in a burst", u.name, nHosts), first, ts)
}

// attackOffHours: successful access at the user's local deep night (02:00 to
// 03:55) from their home IP, so only the hour is anomalous.
func (g *generator) attackOffHours(id string, day int, u *user) {
	start := g.localTS(u, day, 2, g.r.Intn(50), g.r.Intn(60))
	ts := start
	g.emit(g.consoleLogin(u, ts, u.homeIP, true), id, model.TypeOffHoursAccess)
	for j := 0; j < 3+g.r.Intn(5); j++ {
		ts = ts.Add(time.Duration(60+g.r.Intn(500)) * time.Second)
		g.emit(g.apiCall(u, ts, u.homeIP), id, model.TypeOffHoursAccess)
	}
	g.manifest(id, model.TypeOffHoursAccess, u.name,
		fmt.Sprintf("off-hours access: %s active at local deep night", u.name), start, ts)
}

// attackExfil: a burst of large outbound transfers far above any benign sum.
func (g *generator) attackExfil(id string, day int, u *user) {
	n := 8 + g.r.Intn(17)
	total := int64(400_000_000 + g.r.Intn(2_600_000_000))
	ip := g.userIP(u)
	ts := g.localTS(u, day, u.workStart+g.r.Intn(6), g.r.Intn(60), g.r.Intn(60))
	first := ts
	for i := 0; i < n; i++ {
		chunk := total / int64(n)
		g.emit(g.dataTransfer(u, ts, ip, chunk, "cdn-mirror.ext"), id, model.TypeDataExfiltration)
		ts = ts.Add(time.Duration(15+g.r.Intn(60)) * time.Second)
	}
	g.manifest(id, model.TypeDataExfiltration, u.name,
		fmt.Sprintf("data exfiltration: %s moved %d MB outbound in a burst", u.name, total/1_000_000), first, ts)
}
