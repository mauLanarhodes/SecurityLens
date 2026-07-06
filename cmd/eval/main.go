// Command eval drains the detection pipeline over the labelled dataset and
// scores every alert against the ground-truth attack manifest. This is the
// only binary besides the tests that reads the attack labels.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/redis/go-redis/v9"

	"securitylens/internal/config"
	"securitylens/internal/detect"
	"securitylens/internal/eval"
	"securitylens/internal/pipeline"
	"securitylens/internal/store"
)

func main() {
	name := flag.String("dataset", "", "dataset label for the report (default: derived from row count and SEED_SEED)")
	jsonDir := flag.String("json-dir", "docs", "directory to write the eval JSON into")
	flag.Parse()

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
	rdb := redis.NewClient(&redis.Options{Addr: cfg.RedisAddr})
	defer rdb.Close()

	nLogs, err := st.CountLogs(ctx)
	if err != nil {
		log.Fatalf("count: %v", err)
	}
	if nLogs == 0 {
		log.Fatal("no logs in database; run `make seed` first")
	}
	if *name == "" {
		*name = fmt.Sprintf("%dk_seed%d", (nLogs+500)/1000, cfg.SeedSeed)
	}

	if err := st.ResetDetections(ctx); err != nil {
		log.Fatalf("reset: %v", err)
	}
	bl := detect.NewBaselines(rdb)
	p := pipeline.New(st, bl, cfg.SweepStep, detect.Defaults())

	t0 := time.Now()
	windows, _, _, err := p.Drain(ctx)
	if err != nil {
		log.Fatalf("drain: %v", err)
	}
	drainDur := time.Since(t0)

	attacks, err := st.ListAttacks(ctx)
	if err != nil {
		log.Fatalf("attacks: %v", err)
	}
	alerts, err := st.ListAlerts(ctx, store.AlertFilter{Limit: 500})
	if err != nil {
		log.Fatalf("alerts: %v", err)
	}

	r := eval.Score(attacks, alerts, 10*time.Minute)
	r.Dataset = *name
	r.Logs = nLogs
	r.Windows = windows
	r.DrainSeconds = drainDur.Seconds()

	printReport(r, drainDur)

	if err := st.InsertEvalRun(ctx, *name, r); err != nil {
		log.Fatalf("record eval run: %v", err)
	}
	if *jsonDir != "" {
		_ = os.MkdirAll(*jsonDir, 0o755)
		path := filepath.Join(*jsonDir, "eval_"+*name+".json")
		b, _ := json.MarshalIndent(r, "", "  ")
		if err := os.WriteFile(path, b, 0o644); err != nil {
			log.Fatalf("write json: %v", err)
		}
		abs, _ := filepath.Abs(path)
		fmt.Printf("\nwrote eval JSON to %s\n", abs)
	}
	if r.Overall.Recall < 1 || r.BenignFP > 0 {
		os.Exit(1)
	}
}

func printReport(r eval.Result, drain time.Duration) {
	fmt.Printf("SecurityLens evaluation  (drain %.3fs, %d alerts vs %d labeled attacks)\n",
		drain.Seconds(), r.Overall.Alerts, r.Overall.Attacks)
	fmt.Printf("%-26s %7s %8s %7s %7s %6s %6s %7s\n",
		"alert_type", "attacks", "detect", "recall", "alerts", "TP", "FP", "prec")
	line := "------------------------------------------------------------------------------------"
	fmt.Println(line)
	types := make([]string, 0, len(r.PerType))
	for t := range r.PerType {
		types = append(types, t)
	}
	sort.Strings(types)
	row := func(name string, s eval.TypeScore) {
		prec := "-"
		if s.Alerts > 0 {
			prec = fmt.Sprintf("%.0f%%", 100*float64(s.TP)/float64(s.Alerts))
		}
		rec := "-"
		if s.Attacks > 0 {
			rec = fmt.Sprintf("%.0f%%", 100*float64(s.Detected)/float64(s.Attacks))
		}
		fmt.Printf("%-26s %7d %8d %7s %7d %6d %6d %7s\n",
			name, s.Attacks, s.Detected, rec, s.Alerts, s.TP, s.FP, prec)
	}
	for _, t := range types {
		row(t, r.PerType[t])
	}
	fmt.Println(line)
	row("OVERALL", r.Overall)

	fmt.Printf("\nrecall %.0f%%", 100*r.Overall.Recall)
	if r.Overall.Recall == 1 {
		fmt.Printf(" (all attack types detected)")
	}
	fmt.Printf("   type-exact precision %.0f%%   operational precision %.0f%%\n",
		100*r.TypeExactPrecision, 100*r.OperationalPrecision)
	fmt.Println(`FP column = alerts on benign activity. type-exact precision penalizes an alert whose
detector label differs from the ground-truth label even when it flags real attack activity
(e.g. a credential-stuffing breakthrough also tripping identity-anomaly); operational
precision credits any alert that overlaps a real attack on the same entity.`)
}
