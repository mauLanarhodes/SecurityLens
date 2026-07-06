// Package gen produces the labelled synthetic dataset: multi-source benign
// activity for a fleet of users plus injected, ground-truth-labelled attacks
// of all seven types.
//
// Realism rules that detection accuracy depends on (see NOTES.md):
//   - Benign logins come only from a user's home or office IP, and both are
//     present in the user's first days, so identity baselines always contain
//     every benign origin before attacks begin.
//   - Benign SSH is scoped to a small per-user host set; API calls carry no
//     destination host. Lateral fan-out is therefore attack-only.
//   - Benign activity sits in a contiguous local-hour band [workStart,
//     workEnd+2], with the working hours fully covered on days 0-1, so a
//     zero-baseline deep-night hour is attack-only.
//   - Benign transfers are individually small and per-window sums stay far
//     below the exfiltration threshold.
//   - Attacks begin on day 3, after baselines have matured.
package gen

import (
	"fmt"
	"math/rand"
	"sort"
	"time"

	"securitylens/internal/model"
	"securitylens/internal/store"
)

type Params struct {
	Logs  int       // approximate total events
	Days  int       // dataset span in days (minimum 5)
	Seed  int64     // RNG seed; same seed = same dataset shape
	Start time.Time // UTC midnight of day 0; zero value = Days ago from now
}

type Dataset struct {
	Events  []store.LabeledEvent
	Attacks []store.Attack
}

type user struct {
	name      string
	tzOffMin  int // minutes east of UTC
	homeIP    string
	officeIP  string // empty for remote-only users
	hosts     []string
	workStart int // local hour
	workEnd   int
	admin     bool
	weight    float64
}

var firstNames = []string{
	"aisha", "ben", "carla", "deepak", "elena", "farid", "grace", "hiro",
	"ines", "jonas", "kavya", "liam", "mara", "nikolai", "oona", "priya",
	"quentin", "rosa", "sam", "tariq", "uma", "viktor", "wren", "ximena",
	"yusuf", "zoe", "arjun", "bella", "cheng", "diana", "emil", "fatima",
	"gustav", "hana", "ivan", "julia", "kenji", "leila", "marco", "nadia",
}

var tzChoices = []int{-480, -420, -300, -240, -180, 0, 60, 120, 330, 480, 540}

var apiActions = []string{
	"s3:GetObject", "s3:ListBucket", "ec2:DescribeInstances", "iam:ListUsers",
	"lambda:InvokeFunction", "dynamodb:Query", "sts:GetCallerIdentity",
	"cloudwatch:GetMetricData", "kms:Decrypt", "sqs:ReceiveMessage",
}

var httpPaths = []string{
	"/", "/login", "/api/v1/orders", "/api/v1/users/me", "/static/app.js",
	"/health", "/api/v1/search?q=invoices", "/api/v1/reports/monthly",
	"/docs", "/api/v1/items/1042",
}

var benignAppLogs = []string{
	"request completed in %dms",
	"cache refresh finished, %d entries",
	"scheduled job billing-rollup finished ok",
	"connection pool resized to %d",
	"retrying upstream call, attempt %d",
	"user preferences saved",
	"report generation queued",
}

// Placeholder-secret confusers: the sensitive-data classifier must NOT flag these.
var placeholderLogs = []string{
	"docs example: aws_access_key_id=AKIAIOSFODNN7EXAMPLE",
	"config template loaded, api_key=XXXX-XXXX-PLACEHOLDER",
	"sanitized connection string: password=<redacted>",
	"sample payload uses card 4111 1111 1111 1111 (test number)",
	"tutorial snippet: export STRIPE_KEY=sk_test_EXAMPLEEXAMPLEEXAMPLE",
	"masked secret: token=************",
}

type generator struct {
	r      *rand.Rand
	p      Params
	users  []user
	hosts  []string
	events []store.LabeledEvent
	atks   []store.Attack
	usedIP map[string]bool
}

// Generate builds the dataset deterministically from p.Seed.
func Generate(p Params) Dataset {
	if p.Days < 5 {
		p.Days = 5
	}
	if p.Start.IsZero() {
		// Anchor the dataset end near "now" so the live feed has fresh events
		// arriving right after seeding (late-timezone activity extends a few
		// hours past now and streams in as wall-clock time advances).
		p.Start = time.Now().UTC().Add(-time.Duration(p.Days) * 24 * time.Hour).Truncate(time.Minute)
	}
	g := &generator{r: rand.New(rand.NewSource(p.Seed)), p: p, usedIP: map[string]bool{}}
	g.makeFleet()
	g.makeAttacks()
	attackEvents := len(g.events)
	forced := g.forcedBaseline()
	organic := p.Logs - attackEvents - forced
	if organic < 0 {
		organic = 0
	}
	g.benign(organic)
	sort.Slice(g.events, func(i, j int) bool { return g.events[i].TS.Before(g.events[j].TS) })
	sort.Slice(g.atks, func(i, j int) bool { return g.atks[i].TSStart.Before(g.atks[j].TSStart) })
	return Dataset{Events: g.events, Attacks: g.atks}
}

func (g *generator) makeFleet() {
	for _, role := range []string{"web", "db", "app", "cache"} {
		n := 6
		if role == "cache" {
			n = 4
		}
		for i := 1; i <= n; i++ {
			g.hosts = append(g.hosts, fmt.Sprintf("%s-%02d", role, i))
		}
	}
	officeIPs := []string{g.freshIP(), g.freshIP()}
	for i, name := range firstNames {
		u := user{
			name:      name,
			tzOffMin:  tzChoices[g.r.Intn(len(tzChoices))],
			homeIP:    g.freshIP(),
			workStart: 7 + g.r.Intn(3),
			admin:     i < 8,
			weight:    0.5 + g.r.Float64()*2.5,
		}
		u.workEnd = 17 + g.r.Intn(4)
		if g.r.Float64() < 0.8 {
			u.officeIP = officeIPs[g.r.Intn(2)]
		}
		for _, hi := range g.r.Perm(len(g.hosts))[:2+g.r.Intn(3)] {
			u.hosts = append(u.hosts, g.hosts[hi])
		}
		g.users = append(g.users, u)
	}
}

func (g *generator) freshIP() string {
	for {
		ip := fmt.Sprintf("%d.%d.%d.%d", 20+g.r.Intn(200), g.r.Intn(256), g.r.Intn(256), 1+g.r.Intn(254))
		if !g.usedIP[ip] {
			g.usedIP[ip] = true
			return ip
		}
	}
}

// localTS converts (day, local hour, minute, second) in a user's timezone to UTC.
func (g *generator) localTS(u *user, day int, hour, min, sec int) time.Time {
	return g.p.Start.AddDate(0, 0, day).
		Add(time.Duration(hour)*time.Hour + time.Duration(min)*time.Minute + time.Duration(sec)*time.Second).
		Add(-time.Duration(u.tzOffMin) * time.Minute)
}

func (g *generator) emit(e model.LogEvent, attackID, attackType string) {
	g.events = append(g.events, store.LabeledEvent{LogEvent: e, AttackID: attackID, AttackType: attackType})
}

// userIP picks the user's location for a benign action: home or office only,
// so every benign origin is a baseline origin.
func (g *generator) userIP(u *user) string {
	if u.officeIP != "" && g.r.Float64() < 0.45 {
		return u.officeIP
	}
	return u.homeIP
}

// forcedBaseline emits the deterministic warm-up: on days 0-1 every user logs
// in from home and office and touches every working hour, so identity and
// hour baselines are complete before any attack begins. Returns event count.
func (g *generator) forcedBaseline() int {
	before := len(g.events)
	for ui := range g.users {
		u := &g.users[ui]
		for day := 0; day < 2; day++ {
			g.emit(g.consoleLogin(u, g.localTS(u, day, u.workStart, g.r.Intn(30), g.r.Intn(60)), u.homeIP, true), "", "")
			if u.officeIP != "" {
				g.emit(g.consoleLogin(u, g.localTS(u, day, u.workStart+1, g.r.Intn(30), g.r.Intn(60)), u.officeIP, true), "", "")
			} else {
				g.emit(g.consoleLogin(u, g.localTS(u, day, u.workStart+1, g.r.Intn(30), g.r.Intn(60)), u.homeIP, true), "", "")
			}
			for h := u.workStart; h <= u.workEnd; h++ {
				g.emit(g.apiCall(u, g.localTS(u, day, h, g.r.Intn(60), g.r.Intn(60)), g.userIP(u)), "", "")
			}
			for _, h := range u.hosts {
				g.emit(g.sshLogin(u, g.localTS(u, day, u.workStart+2+g.r.Intn(3), g.r.Intn(60), g.r.Intn(60)), g.userIP(u), h, true), "", "")
			}
		}
		// one more home+office login on day 2 to clear login-maturity gates
		g.emit(g.consoleLogin(u, g.localTS(u, 2, u.workStart, g.r.Intn(45), g.r.Intn(60)), u.homeIP, true), "", "")
		if u.officeIP != "" {
			g.emit(g.consoleLogin(u, g.localTS(u, 2, u.workStart+2, g.r.Intn(45), g.r.Intn(60)), u.officeIP, true), "", "")
		}
	}
	return len(g.events) - before
}

// benign emits n organic benign events across the fleet.
func (g *generator) benign(n int) {
	totalW := 0.0
	for _, u := range g.users {
		totalW += u.weight
	}
	for i := 0; i < n; i++ {
		// weighted user pick
		x := g.r.Float64() * totalW
		var u *user
		for ui := range g.users {
			x -= g.users[ui].weight
			if x <= 0 {
				u = &g.users[ui]
				break
			}
		}
		if u == nil {
			u = &g.users[len(g.users)-1]
		}

		// day with weekend damping
		day := g.r.Intn(g.p.Days)
		wd := g.p.Start.AddDate(0, 0, day).Weekday()
		if (wd == time.Saturday || wd == time.Sunday) && g.r.Float64() > 0.3 {
			day = (day + 2) % g.p.Days
		}

		// local hour: work band, with a 12% evening-shoulder tail
		var hour int
		if g.r.Float64() < 0.12 {
			hour = u.workEnd + 1 + g.r.Intn(2)
			if hour > 23 {
				hour = 23
			}
		} else {
			hour = u.workStart + g.r.Intn(u.workEnd-u.workStart+1)
		}
		ts := g.localTS(u, day, hour, g.r.Intn(60), g.r.Intn(60))
		ip := g.userIP(u)

		switch p := g.r.Float64(); {
		case p < 0.06: // console login, occasionally fat-fingered
			ok := g.r.Float64() > 0.03
			g.emit(g.consoleLogin(u, ts, ip, ok), "", "")
			if !ok { // a typo is followed by a success moments later
				g.emit(g.consoleLogin(u, ts.Add(time.Duration(5+g.r.Intn(20))*time.Second), ip, true), "", "")
			}
		case p < 0.28: // cloudtrail api call (no destination host)
			g.emit(g.apiCall(u, ts, ip), "", "")
		case p < 0.36: // ssh to one of the user's own hosts
			g.emit(g.sshLogin(u, ts, ip, u.hosts[g.r.Intn(len(u.hosts))], g.r.Float64() > 0.02), "", "")
		case p < 0.76: // nginx traffic, 60% anonymous
			username, srcIP := "", fmt.Sprintf("%d.%d.%d.%d", 1+g.r.Intn(223), g.r.Intn(256), g.r.Intn(256), 1+g.r.Intn(254))
			if g.r.Float64() < 0.4 {
				username, srcIP = u.name, ip
			}
			g.emit(g.httpRequest(username, ts, srcIP), "", "")
		case p < 0.92: // app log line
			g.emit(g.appLog(u, ts), "", "")
		case p < 0.98: // small outbound transfer
			g.emit(g.dataTransfer(u, ts, ip, int64(100_000+g.r.Intn(20_000_000)), ""), "", "")
		default: // benign permission change: an admin grants someone ELSE a right
			admin := &g.users[g.r.Intn(8)]
			target := g.users[g.r.Intn(len(g.users))].name
			if target == admin.name {
				target = g.users[(g.r.Intn(len(g.users))+9)%len(g.users)].name
			}
			perm := []string{"s3_read", "deploy", "vpn_access", "dashboard_view"}[g.r.Intn(4)]
			g.emit(g.permissionChange(admin.name, target, perm, ts, g.userIP(admin), model.StatusSuccess), "", "")
		}
	}
}

// --- event constructors ---

func (g *generator) consoleLogin(u *user, ts time.Time, ip string, ok bool) model.LogEvent {
	st, msg := model.StatusSuccess, "Console login for "+u.name+": success"
	if !ok {
		st, msg = model.StatusFailure, "Console login for "+u.name+": FAILED (invalid credentials)"
	}
	return model.LogEvent{TS: ts, Source: "cloudtrail", EventType: model.EvConsoleLogin,
		Username: u.name, SrcIP: ip, Status: st, Message: msg}
}

func (g *generator) apiCall(u *user, ts time.Time, ip string) model.LogEvent {
	action := apiActions[g.r.Intn(len(apiActions))]
	st := model.StatusSuccess
	if g.r.Float64() < 0.02 {
		st = model.StatusDenied
	}
	return model.LogEvent{TS: ts, Source: "cloudtrail", EventType: model.EvAPICall,
		Username: u.name, SrcIP: ip, Status: st, Message: action,
		Extra: map[string]string{"action": action}}
}

func (g *generator) sshLogin(u *user, ts time.Time, ip, host string, ok bool) model.LogEvent {
	st := model.StatusSuccess
	msg := fmt.Sprintf("Accepted publickey for %s from %s port %d", u.name, ip, 40000+g.r.Intn(20000))
	if !ok {
		st = model.StatusFailure
		msg = fmt.Sprintf("Failed password for %s from %s", u.name, ip)
	}
	return model.LogEvent{TS: ts, Source: "ssh", EventType: model.EvSSHLogin,
		Username: u.name, SrcIP: ip, DstHost: host, Status: st, Message: msg}
}

func (g *generator) httpRequest(username string, ts time.Time, ip string) model.LogEvent {
	path := httpPaths[g.r.Intn(len(httpPaths))]
	code := []string{"200", "200", "200", "200", "301", "404"}[g.r.Intn(6)]
	method := []string{"GET", "GET", "GET", "POST"}[g.r.Intn(4)]
	return model.LogEvent{TS: ts, Source: "nginx", EventType: model.EvHTTPRequest,
		Username: username, SrcIP: ip, DstHost: g.hosts[g.r.Intn(8)], Status: model.StatusInfo,
		BytesOut: int64(200 + g.r.Intn(50000)),
		Message:  fmt.Sprintf("%s %s %s", method, path, code),
		Extra:    map[string]string{"method": method, "path": path, "code": code}}
}

func (g *generator) appLog(u *user, ts time.Time) model.LogEvent {
	var msg string
	if g.r.Float64() < 0.04 {
		msg = placeholderLogs[g.r.Intn(len(placeholderLogs))]
	} else {
		t := benignAppLogs[g.r.Intn(len(benignAppLogs))]
		msg = t
		for i := 0; i < 2; i++ {
			if containsPct(t) {
				msg = fmt.Sprintf(t, 1+g.r.Intn(500))
				break
			}
		}
	}
	return model.LogEvent{TS: ts, Source: "app", EventType: model.EvAppLog,
		Username: u.name, Status: model.StatusInfo, Message: msg}
}

func containsPct(s string) bool {
	for i := 0; i+1 < len(s); i++ {
		if s[i] == '%' && s[i+1] == 'd' {
			return true
		}
	}
	return false
}

func (g *generator) dataTransfer(u *user, ts time.Time, ip string, bytes int64, dst string) model.LogEvent {
	return model.LogEvent{TS: ts, Source: "app", EventType: model.EvDataTransfer,
		Username: u.name, SrcIP: ip, DstHost: dst, Status: model.StatusSuccess, BytesOut: bytes,
		Message: fmt.Sprintf("outbound transfer %d bytes", bytes),
		Extra:   map[string]string{"direction": "outbound"}}
}

func (g *generator) permissionChange(actor, target, perm string, ts time.Time, ip, status string) model.LogEvent {
	return model.LogEvent{TS: ts, Source: "cloudtrail", EventType: model.EvPermissionChange,
		Username: actor, SrcIP: ip, Status: status,
		Message: fmt.Sprintf("PutUserPolicy: %s granted %q to %s", actor, perm, target),
		Extra:   map[string]string{"target_user": target, "permission": perm}}
}
