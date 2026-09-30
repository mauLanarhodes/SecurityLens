package api

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"securitylens/internal/config"
)

var operatorToken = strings.Repeat("a", 64)
var viewerToken = strings.Repeat("b", 64)

func testServer(t *testing.T) (*Server, *gin.Engine) {
	t.Helper()
	s := New(nil, nil, nil, config.Config{AuthOperatorToken: operatorToken, AuthViewerToken: viewerToken, AuthCookieSecure: true})
	t.Cleanup(func() {
		s.auth.mu.Lock()
		defer s.auth.mu.Unlock()
		for _, session := range s.auth.sessions {
			session.cancel()
		}
	})
	return s, s.Router()
}

func request(r http.Handler, method, path, body, token string, cookie *http.Cookie, browserHeader bool) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if cookie != nil {
		req.AddCookie(cookie)
	}
	if browserHeader {
		req.Header.Set("X-SecurityLens-Request", "1")
	}
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

func signIn(t *testing.T, r http.Handler, token string) *http.Cookie {
	t.Helper()
	w := request(r, http.MethodPost, "/api/session", `{"token":"`+token+`"}`, "", nil, true)
	if w.Code != http.StatusOK {
		t.Fatalf("sign-in status %d: %s", w.Code, w.Body.String())
	}
	cookies := w.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("expected one session cookie, got %d", len(cookies))
	}
	return cookies[0]
}

func TestAllDataRoutesRejectUnauthenticatedRequestsBeforeDependencies(t *testing.T) {
	_, r := testServer(t)
	for _, route := range r.Routes() {
		if !isAPI(route.Path) || (route.Path == "/api/session" && route.Method == http.MethodPost) {
			continue
		}
		path := strings.ReplaceAll(route.Path, ":id", "example")
		for _, token := range []string{"", strings.Repeat("c", 64), "malformed"} {
			t.Run(route.Method+" "+path+" token="+fmt.Sprint(len(token)), func(t *testing.T) {
				w := request(r, route.Method, path, `{}`, token, nil, true)
				if w.Code != http.StatusUnauthorized {
					t.Fatalf("status %d; want 401", w.Code)
				}
				if w.Header().Get("Cache-Control") != "no-store" {
					t.Fatal("API response may be cached")
				}
			})
		}
	}
	for _, path := range []string{"/api", "/api/not-registered", "/api/logs?token=" + operatorToken, "/api/stream?access_token=" + operatorToken} {
		if w := request(r, http.MethodGet, path, "", "", nil, false); w.Code != http.StatusUnauthorized {
			t.Fatalf("%s returned %d", path, w.Code)
		}
	}
}

func TestInvalidConfigurationFailsClosed(t *testing.T) {
	for _, cfg := range []config.Config{
		{}, {AuthOperatorToken: "short"}, {AuthViewerToken: viewerToken},
		{AuthOperatorToken: operatorToken, AuthViewerToken: "invalid"},
		{AuthOperatorToken: operatorToken, AuthViewerToken: strings.ToUpper(operatorToken)},
	} {
		s := New(nil, nil, nil, cfg)
		r := s.Router()
		for _, path := range []string{"/api/logs", "/api/health", "/api/session"} {
			w := request(r, http.MethodGet, path, "", operatorToken, nil, true)
			if w.Code != http.StatusServiceUnavailable {
				t.Fatalf("invalid auth config returned %d", w.Code)
			}
		}
		w := request(r, http.MethodPost, "/api/session", `{"token":"`+operatorToken+`"}`, "", nil, true)
		if w.Code != http.StatusServiceUnavailable {
			t.Fatalf("login with invalid config returned %d", w.Code)
		}
	}
	// An embedded Server constructed without New must also fail closed.
	r := (&Server{}).Router()
	if w := request(r, http.MethodGet, "/api/logs", "", "", nil, false); w.Code != http.StatusServiceUnavailable {
		t.Fatalf("zero Server returned %d", w.Code)
	}
}

func TestViewerReadsButCannotMutateOrInvokeModel(t *testing.T) {
	_, r := testServer(t)
	for _, route := range r.Routes() {
		if !isAPI(route.Path) || route.Path == "/api/session" || !isMutation(route.Method) {
			continue
		}
		path := strings.ReplaceAll(route.Path, ":id", "example")
		w := request(r, route.Method, path, `{}`, viewerToken, nil, false)
		if w.Code != http.StatusForbidden {
			t.Fatalf("viewer %s %s returned %d", route.Method, path, w.Code)
		}
	}
	viewerCookie := signIn(t, r, viewerToken)
	if w := request(r, http.MethodPost, "/api/rules/generate", `{}`, "", viewerCookie, true); w.Code != http.StatusForbidden {
		t.Fatalf("cookie viewer model request returned %d", w.Code)
	}
	for _, token := range []string{viewerToken, operatorToken} {
		w := request(r, http.MethodGet, "/api/runbooks", "", token, nil, false)
		if w.Code != http.StatusOK {
			t.Fatalf("authenticated runbooks returned %d", w.Code)
		}
	}
	for _, path := range []string{"/api/alerts/example/status", "/api/rules/generate"} {
		w := request(r, http.MethodPost, path, `{}`, operatorToken, nil, false)
		if w.Code != http.StatusBadRequest {
			t.Fatalf("operator should reach body validation: %s returned %d", path, w.Code)
		}
	}
}

func TestCookieSessionAttributesRolesAndRevocation(t *testing.T) {
	_, r := testServer(t)
	for _, token := range []string{operatorToken, viewerToken} {
		cookie := signIn(t, r, token)
		if cookie.Name != sessionCookie || !cookie.HttpOnly || !cookie.Secure || cookie.SameSite != http.SameSiteStrictMode || cookie.Path != "/" || cookie.Domain != "" || cookie.MaxAge != int(sessionLifetime.Seconds()) {
			t.Fatalf("unexpected cookie attributes: %+v", cookie)
		}
		if cookie.Value == token || len(cookie.Value) != 64 {
			t.Fatal("session ID must be opaque and separate from the credential")
		}
		if remaining := time.Until(cookie.Expires); remaining < sessionLifetime-time.Minute || remaining > sessionLifetime {
			t.Fatalf("unexpected session expiry: %s", remaining)
		}
		w := request(r, http.MethodGet, "/api/session", "", "", cookie, false)
		var body struct {
			Role string `json:"role"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
			t.Fatal(err)
		}
		wantRole := roleOperator
		if token == viewerToken {
			wantRole = roleViewer
		}
		if w.Code != http.StatusOK || body.Role != wantRole {
			t.Fatalf("session status/role %d/%s", w.Code, body.Role)
		}
		if strings.Contains(w.Body.String(), token) || strings.Contains(w.Body.String(), cookie.Value) {
			t.Fatal("session response exposes credentials")
		}
		w = request(r, http.MethodDelete, "/api/session", "", "", cookie, true)
		if w.Code != http.StatusNoContent || w.Result().Cookies()[0].MaxAge != -1 {
			t.Fatalf("logout failed: %d", w.Code)
		}
		if w = request(r, http.MethodGet, "/api/runbooks", "", "", cookie, false); w.Code != http.StatusUnauthorized {
			t.Fatalf("revoked session returned %d", w.Code)
		}
	}
}

func TestCookieMutationsRequireRequestHeader(t *testing.T) {
	_, r := testServer(t)
	cookie := signIn(t, r, operatorToken)
	for _, path := range []string{"/api/alerts/example/triage", "/api/alerts/example/investigate", "/api/alerts/example/status", "/api/rules/generate"} {
		if w := request(r, http.MethodPost, path, `{}`, "", cookie, false); w.Code != http.StatusForbidden {
			t.Fatalf("cookie mutation without CSRF header %s returned %d", path, w.Code)
		}
	}
	if w := request(r, http.MethodDelete, "/api/session", "", "", cookie, false); w.Code != http.StatusForbidden {
		t.Fatalf("logout without CSRF header returned %d", w.Code)
	}
	if w := request(r, http.MethodPost, "/api/rules/generate", `{}`, "", cookie, true); w.Code != http.StatusBadRequest {
		t.Fatalf("cookie operator with header did not reach validation: %d", w.Code)
	}
	// An invalid explicit Bearer credential must not fall back to a valid cookie.
	if w := request(r, http.MethodGet, "/api/runbooks", "", "bad", cookie, false); w.Code != http.StatusUnauthorized {
		t.Fatalf("invalid Bearer fell back to cookie: %d", w.Code)
	}
}

func TestLoginRejectsCSRFAndMalformedRequests(t *testing.T) {
	tests := []struct {
		name, body, contentType, site, header string
		want                                  int
	}{
		{"missing header", `{"token":"` + operatorToken + `"}`, "application/json", "", "", 403},
		{"cross site", `{"token":"` + operatorToken + `"}`, "application/json", "cross-site", "1", 403},
		{"form", "token=" + operatorToken, "application/x-www-form-urlencoded", "", "1", 415},
		{"invalid credential", `{"token":"invalid"}`, "application/json", "", "1", 401},
		{"unknown field", `{"token":"` + operatorToken + `","other":true}`, "application/json", "", "1", 400},
		{"trailing body", `{"token":"` + operatorToken + `"} {}`, "application/json", "", "1", 400},
		{"oversize", `{"token":"` + strings.Repeat("a", 1025) + `"}`, "application/json", "", "1", 400},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, r := testServer(t)
			req := httptest.NewRequest(http.MethodPost, "/api/session", strings.NewReader(tt.body))
			req.Header.Set("Content-Type", tt.contentType)
			req.Header.Set("X-SecurityLens-Request", tt.header)
			req.Header.Set("Sec-Fetch-Site", tt.site)
			w := httptest.NewRecorder()
			r.ServeHTTP(w, req)
			if w.Code != tt.want {
				t.Fatalf("got %d; want %d", w.Code, tt.want)
			}
			if len(w.Result().Cookies()) != 0 {
				t.Fatal("rejected sign-in set a session")
			}
		})
	}
	_, r := testServer(t)
	req := httptest.NewRequest(http.MethodGet, "/api/runbooks", nil)
	req.Header.Set("Authorization", "Bearer "+operatorToken)
	req.Header.Set("Sec-Fetch-Site", "cross-site")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusForbidden {
		t.Fatalf("cross-site authenticated read returned %d", w.Code)
	}
}

func TestLoginThrottleUsesPeerAddressNotForwardedHeader(t *testing.T) {
	_, r := testServer(t)
	for i := 0; i < 11; i++ {
		req := httptest.NewRequest(http.MethodPost, "/api/session", strings.NewReader(`{"token":"wrong"}`))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-SecurityLens-Request", "1")
		req.Header.Set("X-Forwarded-For", fmt.Sprintf("192.0.2.%d", i))
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		want := http.StatusUnauthorized
		if i == 10 {
			want = http.StatusTooManyRequests
		}
		if w.Code != want {
			t.Fatalf("attempt %d got %d; want %d", i, w.Code, want)
		}
	}
}

func TestSessionExpiryAndReplacement(t *testing.T) {
	s, r := testServer(t)
	first := signIn(t, r, operatorToken)
	w := request(r, http.MethodPost, "/api/session", `{"token":"`+operatorToken+`"}`, "", first, true)
	if w.Code != http.StatusOK {
		t.Fatalf("replacement login returned %d", w.Code)
	}
	second := w.Result().Cookies()[0]
	if first.Value == second.Value {
		t.Fatal("session ID was reused")
	}
	if w = request(r, http.MethodGet, "/api/session", "", "", first, false); w.Code != http.StatusUnauthorized {
		t.Fatal("replaced session remains valid")
	}
	s.auth.mu.Lock()
	session := s.auth.sessions[sha256.Sum256([]byte(second.Value))]
	session.expires = time.Now().Add(-time.Second)
	s.auth.mu.Unlock()
	if w = request(r, http.MethodGet, "/api/session", "", "", second, false); w.Code != http.StatusUnauthorized {
		t.Fatalf("expired cookie returned %d", w.Code)
	}
	if session.ctx.Err() == nil {
		t.Fatal("pruning did not cancel expired session context")
	}
}

// Exercise a real streaming HTTP request through the same guard used by SSE.
// Expiry and logout must end its context even while the connection remains open.
func TestSessionExpiryAndLogoutCancelActiveStreams(t *testing.T) {
	for _, mode := range []string{"expiry", "logout"} {
		t.Run(mode, func(t *testing.T) {
			s, r := testServer(t)
			cookie := signIn(t, r, operatorToken)
			s.auth.mu.Lock()
			session := s.auth.sessions[sha256.Sum256([]byte(cookie.Value))]
			if mode == "expiry" {
				session.expires = time.Now().Add(100 * time.Millisecond)
			}
			s.auth.mu.Unlock()
			stopped := make(chan struct{})
			r.GET("/api/test-stream", func(c *gin.Context) {
				c.Header("Content-Type", "text/event-stream")
				c.Writer.Flush()
				<-c.Request.Context().Done()
				close(stopped)
			})
			server := httptest.NewServer(r)
			defer server.Close()
			req, err := http.NewRequest(http.MethodGet, server.URL+"/api/test-stream", nil)
			if err != nil {
				t.Fatal(err)
			}
			req.AddCookie(cookie)
			response, err := (&http.Client{Timeout: 2 * time.Second}).Do(req)
			if err != nil {
				t.Fatal(err)
			}
			defer response.Body.Close()
			if response.StatusCode != http.StatusOK {
				t.Fatalf("stream status %d", response.StatusCode)
			}
			if mode == "logout" {
				if w := request(r, http.MethodDelete, "/api/session", "", "", cookie, true); w.Code != http.StatusNoContent {
					t.Fatal("logout failed")
				}
			}
			select {
			case <-stopped:
			case <-time.After(time.Second):
				t.Fatal("stream survived session expiry/revocation")
			}
			if _, err := io.ReadAll(response.Body); err != nil {
				t.Fatalf("stream did not end cleanly: %v", err)
			}
		})
	}
}

func TestSessionCapacityIsBoundedAndExpiredSessionsArePruned(t *testing.T) {
	s, r := testServer(t)
	for i := 0; i < maxSessions; i++ {
		key := sha256.Sum256([]byte(fmt.Sprint(i)))
		s.auth.sessions[key] = &authSession{role: roleViewer, expires: time.Now().Add(time.Hour), ctx: context.Background(), cancel: func() {}}
	}
	if w := request(r, http.MethodPost, "/api/session", `{"token":"`+operatorToken+`"}`, "", nil, true); w.Code != http.StatusServiceUnavailable {
		t.Fatalf("full session store returned %d", w.Code)
	}
	for _, session := range s.auth.sessions {
		session.expires = time.Now().Add(-time.Second)
	}
	signIn(t, r, operatorToken)
	if len(s.auth.sessions) != 1 {
		t.Fatalf("expired sessions retained: %d", len(s.auth.sessions))
	}
}

func TestReadinessDoesNotExposeAPIHealth(t *testing.T) {
	_, r := testServer(t)
	w := request(r, http.MethodGet, "/readyz", "", "", nil, false)
	if w.Code != http.StatusServiceUnavailable || w.Body.String() != `{"ok":false}` {
		t.Fatalf("unexpected readiness output: %d %s", w.Code, w.Body.String())
	}
	if w := request(r, http.MethodGet, "/api/health", "", "", nil, false); w.Code != http.StatusUnauthorized {
		t.Fatal("detailed health is public")
	}
}

func TestExplicitLocalCookieMode(t *testing.T) {
	s, _ := testServer(t)
	s.Cfg.AuthCookieSecure = false
	s.auth = newAuth(s.Cfg)
	if cookie := signIn(t, s.Router(), operatorToken); cookie.Secure || !cookie.HttpOnly || cookie.SameSite != http.SameSiteStrictMode {
		t.Fatal("local HTTP override must change only the Secure attribute")
	}
}
