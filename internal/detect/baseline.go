package detect

import (
	"context"
	"fmt"
	"strconv"
	"sync"

	"github.com/redis/go-redis/v9"

	"securitylens/internal/model"
)

// UserBaseline is what SecurityLens knows about one identity's normal
// behaviour: the origins it has authenticated from and the hours it is active.
type UserBaseline struct {
	IPs    map[string]bool
	Hours  [24]int64 // successful-access count per UTC hour of day
	Logins int64     // successful logins observed
	Events int64     // successful access events observed
	Days   map[string]bool
}

// Baselines keeps per-user baselines in memory with write-through to Redis,
// so a restarted process reloads state instead of re-learning from scratch.
// Only successful events feed a baseline: learning from failures would let a
// credential-stuffing burst whitelist the attacker's IP before breakthrough.
type Baselines struct {
	rdb   *redis.Client
	mu    sync.RWMutex
	users map[string]*UserBaseline
}

func NewBaselines(rdb *redis.Client) *Baselines {
	return &Baselines{rdb: rdb, users: map[string]*UserBaseline{}}
}

// Load rebuilds the in-memory mirror from Redis (process start).
func (b *Baselines) Load(ctx context.Context) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.users = map[string]*UserBaseline{}
	iter := b.rdb.Scan(ctx, 0, "bl:ips:*", 500).Iterator()
	var names []string
	for iter.Next(ctx) {
		names = append(names, iter.Val()[len("bl:ips:"):])
	}
	if err := iter.Err(); err != nil {
		return err
	}
	for _, u := range names {
		ub := &UserBaseline{IPs: map[string]bool{}, Days: map[string]bool{}}
		ips, err := b.rdb.SMembers(ctx, "bl:ips:"+u).Result()
		if err != nil {
			return err
		}
		for _, ip := range ips {
			ub.IPs[ip] = true
		}
		hrs, err := b.rdb.HGetAll(ctx, "bl:hrs:"+u).Result()
		if err != nil {
			return err
		}
		for h, n := range hrs {
			hi, _ := strconv.Atoi(h)
			ni, _ := strconv.ParseInt(n, 10, 64)
			if hi >= 0 && hi < 24 {
				ub.Hours[hi] = ni
			}
		}
		days, err := b.rdb.SMembers(ctx, "bl:days:"+u).Result()
		if err != nil {
			return err
		}
		for _, d := range days {
			ub.Days[d] = true
		}
		ub.Logins, _ = b.rdb.Get(ctx, "bl:logins:"+u).Int64()
		ub.Events, _ = b.rdb.Get(ctx, "bl:events:"+u).Int64()
		b.users[u] = ub
	}
	return nil
}

// Reset wipes all baseline state (fresh eval drain).
func (b *Baselines) Reset(ctx context.Context) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.users = map[string]*UserBaseline{}
	iter := b.rdb.Scan(ctx, 0, "bl:*", 500).Iterator()
	var keys []string
	for iter.Next(ctx) {
		keys = append(keys, iter.Val())
	}
	if err := iter.Err(); err != nil {
		return err
	}
	if len(keys) > 0 {
		return b.rdb.Del(ctx, keys...).Err()
	}
	return nil
}

// View returns the read handle detectors use. The pipeline is single-writer
// and updates only after detection, so the view is stable within a window.
func (b *Baselines) View() *BaselineView {
	return &BaselineView{b: b}
}

// Update merges a batch of events into the baselines and write-through to
// Redis. The pipeline calls this with each sweep window's leading step only,
// so every event is merged exactly once, after detection has seen the window.
func (b *Baselines) Update(ctx context.Context, events []model.LogEvent) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	pipe := b.rdb.Pipeline()
	for _, e := range events {
		if e.Username == "" || !isSuccessfulAccess(e) {
			continue
		}
		u := e.Username
		ub := b.users[u]
		if ub == nil {
			ub = &UserBaseline{IPs: map[string]bool{}, Days: map[string]bool{}}
			b.users[u] = ub
		}
		if e.SrcIP != "" && !ub.IPs[e.SrcIP] {
			ub.IPs[e.SrcIP] = true
			pipe.SAdd(ctx, "bl:ips:"+u, e.SrcIP)
		}
		h := e.TS.UTC().Hour()
		ub.Hours[h]++
		pipe.HIncrBy(ctx, "bl:hrs:"+u, strconv.Itoa(h), 1)
		ub.Events++
		pipe.Incr(ctx, "bl:events:"+u)
		day := e.TS.UTC().Format("20060102")
		if !ub.Days[day] {
			ub.Days[day] = true
			pipe.SAdd(ctx, "bl:days:"+u, day)
		}
		if e.EventType == model.EvConsoleLogin {
			ub.Logins++
			pipe.Incr(ctx, "bl:logins:"+u)
		}
	}
	_, err := pipe.Exec(ctx)
	return err
}

// BaselineView is the detectors' read-only handle.
type BaselineView struct{ b *Baselines }

// User returns the baseline for a username, or nil if none exists yet.
func (v *BaselineView) User(u string) *UserBaseline {
	if v == nil || v.b == nil {
		return nil
	}
	v.b.mu.RLock()
	defer v.b.mu.RUnlock()
	return v.b.users[u]
}

// String summarizes a baseline for debugging.
func (ub *UserBaseline) String() string {
	return fmt.Sprintf("ips=%d logins=%d events=%d days=%d", len(ub.IPs), ub.Logins, ub.Events, len(ub.Days))
}
