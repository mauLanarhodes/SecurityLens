// Command seed generates the labelled synthetic dataset and loads it into
// Postgres, replacing whatever was there.
package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"strconv"
	"time"

	"github.com/redis/go-redis/v9"

	"securitylens/internal/config"
	"securitylens/internal/gen"
	"securitylens/internal/store"
)

func main() {
	cfg := config.Load()
	ctx := context.Background()

	st, err := store.New(ctx, cfg.DatabaseURL)
	if err != nil {
		log.Fatalf("connect: %v", err)
	}
	defer st.Close()
	if err := st.Migrate(ctx); err != nil {
		log.Fatalf("migrate: %v", err)
	}

	t0 := time.Now()
	// SEED_ANCHOR_NOW=true ends the dataset near "now" for a fresh live feed;
	// the default fixed anchor keeps eval seeding reproducible.
	anchorNow, _ := strconv.ParseBool(os.Getenv("SEED_ANCHOR_NOW"))
	ds := gen.Generate(gen.Params{Logs: cfg.SeedLogs, Days: cfg.SeedDays, Seed: cfg.SeedSeed, AnchorNow: anchorNow})
	fmt.Printf("generated %d events, %d labelled attacks (seed=%d, days=%d) in %s\n",
		len(ds.Events), len(ds.Attacks), cfg.SeedSeed, cfg.SeedDays, time.Since(t0).Round(time.Millisecond))

	if err := st.ResetAll(ctx); err != nil {
		log.Fatalf("reset: %v", err)
	}
	// Redis holds only state derived from the dataset (baselines, LLM cache);
	// a reseed must clear it or the old dataset's baselines poison detection.
	rdb := redis.NewClient(&redis.Options{Addr: cfg.RedisAddr})
	if err := rdb.FlushDB(ctx).Err(); err != nil {
		log.Printf("warning: could not flush redis (%v); restart the backend after seeding", err)
	}
	rdb.Close()
	t1 := time.Now()
	const chunk = 20000
	var loaded int64
	for i := 0; i < len(ds.Events); i += chunk {
		j := min(i+chunk, len(ds.Events))
		n, err := st.InsertLogEvents(ctx, ds.Events[i:j])
		if err != nil {
			log.Fatalf("insert logs: %v", err)
		}
		loaded += n
	}
	if err := st.InsertAttacks(ctx, ds.Attacks); err != nil {
		log.Fatalf("insert attacks: %v", err)
	}
	el := time.Since(t1)
	fmt.Printf("loaded %d logs in %s (%.0f logs/sec)\n", loaded, el.Round(time.Millisecond),
		float64(loaded)/el.Seconds())

	byType := map[string]int{}
	for _, a := range ds.Attacks {
		byType[a.AttackType]++
	}
	fmt.Printf("attack mix: %v\n", byType)
	_ = os.Stdout.Sync()
}
