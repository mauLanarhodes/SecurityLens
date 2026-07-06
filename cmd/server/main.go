// Command server runs the SecurityLens backend: migrations, optional first-
// boot seeding, the live detection pipeline, and the HTTP API + dashboard.
package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/redis/go-redis/v9"

	"securitylens/internal/api"
	"securitylens/internal/config"
	"securitylens/internal/detect"
	"securitylens/internal/gen"
	"securitylens/internal/llm"
	"securitylens/internal/pipeline"
	"securitylens/internal/store"
)

func main() {
	cfg := config.Load()
	ctx := context.Background()

	st, err := store.New(ctx, cfg.DatabaseURL)
	if err != nil {
		log.Fatalf("postgres: %v", err)
	}
	defer st.Close()
	if err := st.Migrate(ctx); err != nil {
		log.Fatalf("migrate: %v", err)
	}
	rdb := redis.NewClient(&redis.Options{Addr: cfg.RedisAddr})
	if err := rdb.Ping(ctx).Err(); err != nil {
		log.Fatalf("redis: %v", err)
	}

	// First-boot seeding: only when enabled and the logs table is empty.
	if cfg.SeedOnStart {
		if n, err := st.CountLogs(ctx); err == nil && n == 0 {
			log.Printf("seeding synthetic dataset: %d logs / %d days / seed %d", cfg.SeedLogs, cfg.SeedDays, cfg.SeedSeed)
			// AnchorNow so the live feed has fresh events streaming right after
			// boot; the evaluator seeds without it for reproducibility.
			ds := gen.Generate(gen.Params{Logs: cfg.SeedLogs, Days: cfg.SeedDays, Seed: cfg.SeedSeed, AnchorNow: true})
			const chunk = 20000
			for i := 0; i < len(ds.Events); i += chunk {
				j := min(i+chunk, len(ds.Events))
				if _, err := st.InsertLogEvents(ctx, ds.Events[i:j]); err != nil {
					log.Fatalf("seed: %v", err)
				}
			}
			if err := st.InsertAttacks(ctx, ds.Attacks); err != nil {
				log.Fatalf("seed attacks: %v", err)
			}
			log.Printf("seeded %d logs, %d labelled attacks", len(ds.Events), len(ds.Attacks))
		}
	}

	var client llm.Client
	if cfg.LLMLive() {
		client = llm.NewAnthropic(cfg.AnthropicAPIKey, os.Getenv("LLM_MODEL"))
		log.Printf("llm: live (%s)", client.ModelName())
	} else {
		client = &llm.Mock{}
		log.Printf("llm: mock (no API key or LLM_MODE=mock)")
	}
	svc := llm.NewService(client, rdb, st)

	srv := api.New(st, rdb, svc, cfg)

	bl := detect.NewBaselines(rdb)
	p := pipeline.New(st, bl, cfg.SweepStep, detect.Defaults())
	p.OnAlert = srv.PublishAlert
	go p.RunLive(ctx, cfg.SweepInterval, cfg.DetectLag)
	log.Printf("pipeline: live sweep every %s (lag %s, step %s)", cfg.SweepInterval, cfg.DetectLag, cfg.SweepStep)

	r := srv.Router()

	addr := ":" + cfg.Port
	log.Printf("listening on %s", addr)
	if err := http.ListenAndServe(addr, withStatic(r)); err != nil {
		log.Fatal(err)
	}
}

// withStatic serves web/dist for non-API paths when the build exists.
func withStatic(next http.Handler) http.Handler {
	dist := "web/dist"
	fi, err := os.Stat(dist)
	if err != nil || !fi.IsDir() {
		return next
	}
	fs := http.FileServer(http.Dir(dist))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/api/") {
			next.ServeHTTP(w, r)
			return
		}
		if _, err := os.Stat(dist + r.URL.Path); err != nil && r.URL.Path != "/" {
			r.URL.Path = "/" // SPA fallback
		}
		fs.ServeHTTP(w, r)
	})
}
