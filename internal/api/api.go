// Package api is the HTTP surface: REST endpoints for the dashboard plus the
// SSE stream for the live feed.
package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5"
	"github.com/redis/go-redis/v9"

	"securitylens/internal/config"
	"securitylens/internal/llm"
	"securitylens/internal/model"
	"securitylens/internal/rulegen"
	"securitylens/internal/runbook"
	"securitylens/internal/store"
)

// EventsChannel is the Redis pub/sub channel carrying alert/incident events.
const EventsChannel = "securitylens:events"

type Server struct {
	St    *store.Store
	Redis *redis.Client
	LLM   *llm.Service
	Cfg   config.Config
}

func New(st *store.Store, rdb *redis.Client, svc *llm.Service, cfg config.Config) *Server {
	return &Server{St: st, Redis: rdb, LLM: svc, Cfg: cfg}
}

// PublishAlert pushes an alert event to the SSE stream via Redis pub/sub.
func (s *Server) PublishAlert(a model.Alert, created bool) {
	kind := "alert_updated"
	if created {
		kind = "alert_created"
	}
	b, _ := json.Marshal(gin.H{"kind": kind, "alert": a})
	s.Redis.Publish(context.Background(), EventsChannel, b)
}

func (s *Server) Router() *gin.Engine {
	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	r.Use(gin.Recovery())

	api := r.Group("/api")
	api.GET("/health", s.health)
	api.GET("/logs", s.logs)
	api.GET("/stream", s.stream)
	api.GET("/timeline", s.timeline)
	api.GET("/alerts", s.alerts)
	api.GET("/alerts/:id", s.alert)
	api.POST("/alerts/:id/triage", s.triage)
	api.POST("/alerts/:id/investigate", s.investigate)
	api.POST("/alerts/:id/status", s.alertStatus)
	api.GET("/incidents", s.incidents)
	api.GET("/incidents/:id", s.incident)
	api.GET("/runbooks", func(c *gin.Context) { c.JSON(200, runbook.All()) })
	api.POST("/rules/generate", s.generateRule)
	api.GET("/metrics", s.metrics)
	api.GET("/eval", s.evalRuns)
	api.GET("/oncall", s.oncall)
	return r
}

func (s *Server) health(c *gin.Context) {
	ctx := c.Request.Context()
	dbOK := s.St.Health(ctx) == nil
	redisOK := s.Redis.Ping(ctx).Err() == nil
	nLogs, _ := s.St.CountLogs(ctx)
	status := http.StatusOK
	if !dbOK || !redisOK {
		status = http.StatusServiceUnavailable
	}
	llmMode := "mock"
	if s.LLM.Client.Live() {
		llmMode = "live"
	}
	c.JSON(status, gin.H{
		"ok": dbOK && redisOK, "db": dbOK, "redis": redisOK,
		"llm_mode": llmMode, "llm_model": s.LLM.Client.ModelName(), "logs": nLogs,
	})
}

func (s *Server) logs(c *gin.Context) {
	limit := intQuery(c, "limit", 100, 500)
	evs, err := s.St.RecentLogs(c.Request.Context(), limit, c.Query("source"))
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	c.JSON(200, gin.H{"logs": evs})
}

// stream is the SSE endpoint: it pushes alert events from Redis pub/sub and
// tails the logs table by event time as wall-clock time advances.
func (s *Server) stream(c *gin.Context) {
	h := c.Writer.Header()
	h.Set("Content-Type", "text/event-stream")
	h.Set("Cache-Control", "no-cache")
	h.Set("Connection", "keep-alive")
	h.Set("X-Accel-Buffering", "no") // nginx: do not buffer this response
	c.Writer.Flush()

	ctx := c.Request.Context()
	sub := s.Redis.Subscribe(ctx, EventsChannel)
	defer sub.Close()
	events := sub.Channel()

	lastTS := time.Now().UTC().Add(-30 * time.Second)
	tick := time.NewTicker(2 * time.Second)
	defer tick.Stop()
	heartbeat := time.NewTicker(15 * time.Second)
	defer heartbeat.Stop()

	send := func(event string, data any) bool {
		b, _ := json.Marshal(data)
		_, err := fmt.Fprintf(c.Writer, "event: %s\ndata: %s\n\n", event, b)
		c.Writer.Flush()
		return err == nil
	}

	for {
		select {
		case <-ctx.Done():
			return
		case msg := <-events:
			var payload json.RawMessage = []byte(msg.Payload)
			if !send("alert", payload) {
				return
			}
		case <-tick.C:
			now := time.Now().UTC()
			evs, err := s.St.WindowEvents(ctx, lastTS, now)
			if err != nil {
				continue
			}
			const maxBatch = 50
			if len(evs) > maxBatch {
				evs = evs[len(evs)-maxBatch:]
			}
			for _, e := range evs {
				if !send("log", e) {
					return
				}
			}
			lastTS = now
		case <-heartbeat.C:
			if _, err := fmt.Fprint(c.Writer, ": ping\n\n"); err != nil {
				return
			}
			c.Writer.Flush()
		}
	}
}

func (s *Server) timeline(c *gin.Context) {
	points, err := s.St.Timeline(c.Request.Context())
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	c.JSON(200, gin.H{"points": points})
}

func (s *Server) alerts(c *gin.Context) {
	list, err := s.St.ListAlerts(c.Request.Context(), store.AlertFilter{
		Status:    c.Query("status"),
		AlertType: c.Query("type"),
		Limit:     intQuery(c, "limit", 200, 500),
	})
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	c.JSON(200, gin.H{"alerts": list})
}

func (s *Server) alert(c *gin.Context) {
	a, err := s.St.GetAlert(c.Request.Context(), c.Param("id"))
	if err == pgx.ErrNoRows {
		c.JSON(404, gin.H{"error": "alert not found"})
		return
	}
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	rb, _ := runbook.For(a.AlertType)
	c.JSON(200, gin.H{"alert": a, "runbook": rb})
}

func (s *Server) triage(c *gin.Context) {
	a, err := s.St.GetAlert(c.Request.Context(), c.Param("id"))
	if err != nil {
		c.JSON(404, gin.H{"error": "alert not found"})
		return
	}
	t, err := s.LLM.Triage(c.Request.Context(), a)
	if err != nil {
		c.JSON(502, gin.H{"error": err.Error()})
		return
	}
	if err := s.St.SetTriage(c.Request.Context(), a.ID, t); err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	c.JSON(200, gin.H{"triage": t})
}

func (s *Server) investigate(c *gin.Context) {
	a, err := s.St.GetAlert(c.Request.Context(), c.Param("id"))
	if err != nil {
		c.JSON(404, gin.H{"error": "alert not found"})
		return
	}
	inv, err := s.LLM.Investigate(c.Request.Context(), a)
	if err != nil {
		c.JSON(502, gin.H{"error": err.Error()})
		return
	}
	c.JSON(200, gin.H{"investigation": inv})
}

func (s *Server) alertStatus(c *gin.Context) {
	var body struct {
		Status string `json:"status"`
	}
	if err := c.BindJSON(&body); err != nil {
		return
	}
	valid := map[string]bool{"open": true, "acknowledged": true, "resolved": true, "dismissed": true}
	if !valid[body.Status] {
		c.JSON(400, gin.H{"error": "status must be one of open|acknowledged|resolved|dismissed"})
		return
	}
	err := s.St.SetAlertStatus(c.Request.Context(), c.Param("id"), body.Status)
	if err == pgx.ErrNoRows {
		c.JSON(404, gin.H{"error": "alert not found"})
		return
	}
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	c.JSON(200, gin.H{"ok": true, "status": body.Status})
}

func (s *Server) incidents(c *gin.Context) {
	list, err := s.St.ListIncidents(c.Request.Context(), intQuery(c, "limit", 100, 500))
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	c.JSON(200, gin.H{"incidents": list})
}

func (s *Server) incident(c *gin.Context) {
	inc, err := s.St.GetIncident(c.Request.Context(), c.Param("id"))
	if err == pgx.ErrNoRows {
		c.JSON(404, gin.H{"error": "incident not found"})
		return
	}
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	c.JSON(200, gin.H{"incident": inc})
}

func (s *Server) generateRule(c *gin.Context) {
	var body struct {
		Description string `json:"description"`
	}
	if err := c.BindJSON(&body); err != nil || body.Description == "" {
		c.JSON(400, gin.H{"error": "description is required"})
		return
	}
	code, err := s.LLM.GenerateRule(c.Request.Context(), body.Description)
	if err != nil {
		c.JSON(502, gin.H{"error": err.Error()})
		return
	}
	res, err := rulegen.Validate(c.Request.Context(), code)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	c.JSON(200, gin.H{
		"code": res.Code, "compile_ok": res.CompileOK, "compiler_output": res.CompilerOutput,
		"mock": !s.LLM.Client.Live(), "model": s.LLM.Client.ModelName(),
	})
}

func (s *Server) metrics(c *gin.Context) {
	ctx := c.Request.Context()
	alerts, err := s.St.AlertStats(ctx)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	usage, err := s.St.LLMUsageSummary(ctx)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	nLogs, _ := s.St.CountLogs(ctx)

	// Analyst-feedback FP rate: dismissed / total.
	var fpRate float64
	if t, ok := alerts["total"].(int64); ok && t > 0 {
		if d, ok := alerts["dismissed"].(int64); ok {
			fpRate = float64(d) / float64(t)
		}
	}
	c.JSON(200, gin.H{
		"alerts":  alerts,
		"llm":     usage,
		"logs":    nLogs,
		"fp_rate": fpRate,
		"detection_latency_bound_seconds": (s.Cfg.SweepInterval + s.Cfg.DetectLag).Seconds(),
	})
}

func (s *Server) evalRuns(c *gin.Context) {
	runs, err := s.St.LatestEvalRuns(c.Request.Context(), 10)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	c.JSON(200, gin.H{"runs": runs})
}

// oncall renders the payload a paging integration would receive: open
// critical/high alerts grouped by incident.
func (s *Server) oncall(c *gin.Context) {
	list, err := s.St.ListAlerts(c.Request.Context(), store.AlertFilter{Status: "open", Limit: 500})
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	var page []gin.H
	for _, a := range list {
		if a.Severity != model.SevCritical && a.Severity != model.SevHigh {
			continue
		}
		page = append(page, gin.H{
			"alert_id": a.ID, "incident_id": a.IncidentID,
			"severity": a.Severity, "type": a.AlertType, "title": a.Title,
			"entity": a.Entity, "window_start": a.WindowStart, "window_end": a.WindowEnd,
		})
	}
	c.JSON(200, gin.H{"service": "securitylens", "generated_at": time.Now().UTC(), "page": page})
}

func intQuery(c *gin.Context, name string, def, max int) int {
	v := def
	if q := c.Query(name); q != "" {
		fmt.Sscanf(q, "%d", &v)
	}
	if v <= 0 {
		v = def
	}
	if v > max {
		v = max
	}
	return v
}
