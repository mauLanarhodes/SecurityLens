package api

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"io"
	"mime"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"securitylens/internal/config"
)

const (
	sessionCookie   = "securitylens_session"
	sessionLifetime = 8 * time.Hour
	maxSessions     = 1024
	maxLoginPeers   = 1024
	roleOperator    = "operator"
	roleViewer      = "viewer"
)

type authSession struct {
	role    string
	expires time.Time
	ctx     context.Context
	cancel  context.CancelFunc
}

type loginAttempts struct {
	start time.Time
	count int
}

type authManager struct {
	enabled   bool
	secure    bool
	operator  [32]byte
	viewer    [32]byte
	hasViewer bool
	mu        sync.Mutex
	sessions  map[[32]byte]*authSession
	peers     map[string]loginAttempts
	global    loginAttempts
}

func newAuth(cfg config.Config) *authManager {
	a := &authManager{
		enabled: cfg.ValidateAuth() == nil, secure: cfg.AuthCookieSecure,
		sessions: make(map[[32]byte]*authSession), peers: make(map[string]loginAttempts),
	}
	a.operator = tokenHash(cfg.AuthOperatorToken)
	a.viewer = tokenHash(cfg.AuthViewerToken)
	a.hasViewer = cfg.AuthViewerToken != ""
	return a
}

// Hash fixed-length decoded tokens before constant-time comparisons, including
// malformed inputs. Configuration validation prevents empty credential fallback.
func tokenHash(token string) [32]byte {
	decoded, err := hex.DecodeString(token)
	if err != nil || len(decoded) != 32 {
		return sha256.Sum256(nil)
	}
	return sha256.Sum256(decoded)
}

func (a *authManager) role(token string) string {
	if !a.enabled {
		return ""
	}
	h := tokenHash(token)
	operator := subtle.ConstantTimeCompare(h[:], a.operator[:])
	viewer := subtle.ConstantTimeCompare(h[:], a.viewer[:])
	if operator == 1 {
		return roleOperator
	}
	if viewer == 1 && a.hasViewer {
		return roleViewer
	}
	return ""
}

func isAPI(path string) bool { return path == "/api" || strings.HasPrefix(path, "/api/") }
func isMutation(method string) bool {
	return method != http.MethodGet && method != http.MethodHead && method != http.MethodOptions
}

func deny(c *gin.Context, status int, message string) {
	c.AbortWithStatusJSON(status, gin.H{"error": message})
}

// guard covers the entire API namespace, including unknown and future routes.
// Only login may precede authentication. No credential is accepted from a URL.
func (a *authManager) guard(c *gin.Context) {
	if !isAPI(c.Request.URL.Path) {
		c.Next()
		return
	}
	c.Header("Cache-Control", "no-store")
	if !a.enabled {
		deny(c, http.StatusServiceUnavailable, "authentication is not configured")
		return
	}
	if c.GetHeader("Sec-Fetch-Site") == "cross-site" {
		deny(c, http.StatusForbidden, "cross-site requests are not allowed")
		return
	}
	if c.Request.URL.Path == "/api/session" && c.Request.Method == http.MethodPost {
		if !browserWriteAllowed(c) {
			return
		}
		c.Next()
		return
	}
	var role string
	var session *authSession
	if authorization := c.GetHeader("Authorization"); authorization != "" {
		parts := strings.Fields(authorization)
		if len(parts) == 2 && strings.EqualFold(parts[0], "Bearer") {
			role = a.role(parts[1])
		}
	} else if cookie, err := c.Cookie(sessionCookie); err == nil {
		a.mu.Lock()
		a.prune(time.Now())
		session = a.sessions[sha256.Sum256([]byte(cookie))]
		a.mu.Unlock()
		if session != nil {
			role = session.role
		}
	}
	if role == "" {
		deny(c, http.StatusUnauthorized, "authentication required")
		return
	}
	if session != nil {
		if isMutation(c.Request.Method) && !browserWriteAllowed(c) {
			return
		}
		// Revocation immediately cancels in-flight handlers and streams; the deadline
		// also limits idle streams even when no new requests arrive to prune sessions.
		ctx, cancel := context.WithDeadline(c.Request.Context(), session.expires)
		stop := context.AfterFunc(session.ctx, cancel)
		defer stop()
		defer cancel()
		if session.ctx.Err() != nil {
			deny(c, http.StatusUnauthorized, "session expired")
			return
		}
		c.Request = c.Request.WithContext(ctx)
		c.Set("auth.session", session)
	}
	c.Set("auth.role", role)
	// All non-read data operations require the operator role. Logout is available
	// to both roles; new mutation endpoints inherit the safe default.
	if isMutation(c.Request.Method) && c.Request.URL.Path != "/api/session" && role != roleOperator {
		deny(c, http.StatusForbidden, "operator access required")
		return
	}
	c.Next()
}

func browserWriteAllowed(c *gin.Context) bool {
	if c.GetHeader("X-SecurityLens-Request") != "1" {
		deny(c, http.StatusForbidden, "X-SecurityLens-Request header is required")
		return false
	}
	return true
}

// Called with the mutex held. State is bounded even under unauthenticated traffic.
func (a *authManager) prune(now time.Time) {
	for key, session := range a.sessions {
		if !now.Before(session.expires) || session.ctx.Err() != nil {
			session.cancel()
			delete(a.sessions, key)
		}
	}
	for peer, attempts := range a.peers {
		if now.Sub(attempts.start) >= time.Minute {
			delete(a.peers, peer)
		}
	}
}

func (a *authManager) allowLogin(remoteAddr string) bool {
	peer, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		peer = remoteAddr
	}
	now := time.Now()
	a.mu.Lock()
	defer a.mu.Unlock()
	a.prune(now)
	if now.Sub(a.global.start) >= time.Minute {
		a.global = loginAttempts{start: now}
	}
	if a.global.count >= 120 {
		return false
	}
	a.global.count++
	attempts, exists := a.peers[peer]
	if !exists {
		if len(a.peers) >= maxLoginPeers {
			return false
		}
		attempts.start = now
	}
	if attempts.count >= 10 {
		return false
	}
	attempts.count++
	a.peers[peer] = attempts
	return true
}

func (a *authManager) login(c *gin.Context) {
	if !a.allowLogin(c.Request.RemoteAddr) {
		c.Header("Retry-After", "60")
		deny(c, http.StatusTooManyRequests, "too many sign-in attempts; try again in one minute")
		return
	}
	mediaType, _, err := mime.ParseMediaType(c.GetHeader("Content-Type"))
	if err != nil || mediaType != "application/json" {
		deny(c, http.StatusUnsupportedMediaType, "application/json is required")
		return
	}
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, 1024)
	decoder := json.NewDecoder(c.Request.Body)
	decoder.DisallowUnknownFields()
	var body struct {
		Token string `json:"token"`
	}
	if err := decoder.Decode(&body); err != nil {
		deny(c, http.StatusBadRequest, "invalid sign-in request")
		return
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		deny(c, http.StatusBadRequest, "invalid sign-in request")
		return
	}
	role := a.role(body.Token)
	if role == "" {
		deny(c, http.StatusUnauthorized, "invalid credentials")
		return
	}
	var random [32]byte
	if _, err := rand.Read(random[:]); err != nil {
		deny(c, http.StatusInternalServerError, "unable to create session")
		return
	}
	id := hex.EncodeToString(random[:])
	expires := time.Now().Add(sessionLifetime)
	ctx, cancel := context.WithDeadline(context.Background(), expires)
	session := &authSession{role: role, expires: expires, ctx: ctx, cancel: cancel}
	a.mu.Lock()
	a.prune(time.Now())
	// Replace a prior browser session rather than accumulating it on sign-in.
	if previous, err := c.Cookie(sessionCookie); err == nil {
		a.revoke(sha256.Sum256([]byte(previous)))
	}
	if len(a.sessions) >= maxSessions {
		a.mu.Unlock()
		cancel()
		deny(c, http.StatusServiceUnavailable, "session capacity reached")
		return
	}
	a.sessions[sha256.Sum256([]byte(id))] = session
	a.mu.Unlock()
	http.SetCookie(c.Writer, &http.Cookie{
		Name: sessionCookie, Value: id, Path: "/", HttpOnly: true,
		Secure: a.secure, SameSite: http.SameSiteStrictMode,
		MaxAge: int(sessionLifetime.Seconds()), Expires: expires,
	})
	c.JSON(http.StatusOK, gin.H{"role": role})
}

// Called with the mutex held.
func (a *authManager) revoke(key [32]byte) {
	if session := a.sessions[key]; session != nil {
		session.cancel()
		delete(a.sessions, key)
	}
}

func (a *authManager) logout(c *gin.Context) {
	if cookie, err := c.Cookie(sessionCookie); err == nil {
		a.mu.Lock()
		a.revoke(sha256.Sum256([]byte(cookie)))
		a.mu.Unlock()
	}
	http.SetCookie(c.Writer, &http.Cookie{
		Name: sessionCookie, Value: "", Path: "/", HttpOnly: true,
		Secure: a.secure, SameSite: http.SameSiteStrictMode,
		MaxAge: -1, Expires: time.Unix(1, 0),
	})
	c.Status(http.StatusNoContent)
}

func (a *authManager) session(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"role": c.GetString("auth.role")})
}
