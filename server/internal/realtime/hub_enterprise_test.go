package realtime

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/gorilla/websocket"
	"github.com/multica-ai/multica/server/internal/auth"
)

// enterpriseToken signs a JWT carrying the enterprise session epoch.
func enterpriseToken(t *testing.T, userID, sid string, ver int64) string {
	t.Helper()
	claims := jwt.MapClaims{"sub": userID, auth.EnterpriseSessionClaim: sid, auth.EnterpriseVersionClaim: ver}
	signed, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(auth.JWTSecret())
	if err != nil {
		t.Fatalf("sign enterprise token: %v", err)
	}
	return signed
}

// staticEnterprisePATResolver resolves tokens to (user, enterprise subject).
type staticEnterprisePATResolver map[string]struct {
	User    string
	Subject string
}

func (s staticEnterprisePATResolver) ResolveToken(ctx context.Context, token string) (string, bool) {
	id, ok := s[token]
	return id.User, ok
}

func (s staticEnterprisePATResolver) ResolveTokenEnterprise(ctx context.Context, token string) (string, string, bool) {
	id, ok := s[token]
	return id.User, id.Subject, ok
}

func dialEnterpriseWS(t *testing.T, server *httptest.Server, token string) *websocket.Conn {
	t.Helper()
	wsURL := "ws" + strings.TrimPrefix(server.URL, "http") + "/ws?workspace_id=" + testWorkspaceID
	conn, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	authMsg, _ := json.Marshal(map[string]any{
		"type":    "auth",
		"payload": map[string]string{"token": token},
	})
	if err := conn.WriteMessage(websocket.TextMessage, authMsg); err != nil {
		t.Fatalf("send auth: %v", err)
	}
	return conn
}

func TestHandleWebSocketEnterpriseRevokedClosesConnection(t *testing.T) {
	hub := NewHub()
	go hub.Run()
	mc := &mockMembershipChecker{}
	hub.SetMembershipChecker(mc)

	checkerCalls := 0
	checker := func(ctx context.Context, userID string, ent EnterpriseTokenInfo) bool {
		checkerCalls++
		if ent.SessionID != "sess-1" || ent.Version != 7 {
			t.Errorf("checker saw ent = %+v", ent)
		}
		return false // entitlement revoked
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/ws", func(w http.ResponseWriter, r *http.Request) {
		HandleWebSocketWithEnterprise(hub, mc, nil, nil, checker, w, r)
	})
	server := httptest.NewServer(mux)
	defer server.Close()

	conn := dialEnterpriseWS(t, server, enterpriseToken(t, testUserID, "sess-1", 7))
	defer conn.Close()

	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	// Auth succeeds first — the entitlement check runs after the auth frame.
	_, ack, err := conn.ReadMessage()
	if err != nil {
		t.Fatalf("read auth_ack: %v", err)
	}
	if !strings.Contains(string(ack), "auth_ack") {
		t.Fatalf("expected auth_ack, got %s", ack)
	}
	_, frame, err := conn.ReadMessage()
	if err != nil {
		t.Fatalf("read revoked frame: %v", err)
	}
	if string(frame) != `{"type":"enterprise_revoked"}` {
		t.Fatalf("frame = %s", frame)
	}
	// The server closes the connection after the frame.
	if _, _, err := conn.ReadMessage(); err == nil {
		t.Fatal("expected close after enterprise_revoked")
	}
	if checkerCalls != 1 {
		t.Fatalf("checker called %d times", checkerCalls)
	}
	if n := len(hub.clients); n != 0 {
		t.Fatalf("revoked connection registered %d clients", n)
	}
}

func TestHandleWebSocketEnterpriseValidEpochRegisters(t *testing.T) {
	hub := NewHub()
	go hub.Run()
	mc := &mockMembershipChecker{}
	hub.SetMembershipChecker(mc)

	mux := http.NewServeMux()
	mux.HandleFunc("/ws", func(w http.ResponseWriter, r *http.Request) {
		HandleWebSocketWithEnterprise(hub, mc, nil, nil,
			func(ctx context.Context, userID string, ent EnterpriseTokenInfo) bool { return true }, w, r)
	})
	server := httptest.NewServer(mux)
	defer server.Close()

	conn := dialEnterpriseWS(t, server, enterpriseToken(t, testUserID, "sess-1", 7))
	defer conn.Close()

	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, ack, err := conn.ReadMessage()
	if err != nil {
		t.Fatalf("read auth_ack: %v", err)
	}
	if !strings.Contains(string(ack), "auth_ack") {
		t.Fatalf("expected auth_ack, got %s", ack)
	}
}

func TestHandleWebSocketPersonalConnectionIgnoresChecker(t *testing.T) {
	hub := NewHub()
	go hub.Run()
	mc := &mockMembershipChecker{}
	hub.SetMembershipChecker(mc)

	checkerCalls := 0
	mux := http.NewServeMux()
	mux.HandleFunc("/ws", func(w http.ResponseWriter, r *http.Request) {
		HandleWebSocketWithEnterprise(hub, mc, nil, nil,
			func(ctx context.Context, userID string, ent EnterpriseTokenInfo) bool {
				checkerCalls++
				return false
			}, w, r)
	})
	server := httptest.NewServer(mux)
	defer server.Close()

	// Personal JWT: no ent_sid claim → checker must not run.
	conn := dialEnterpriseWS(t, server, makeTestToken(t))
	defer conn.Close()
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, _, err := conn.ReadMessage(); err != nil {
		t.Fatalf("read auth_ack: %v", err)
	}
	if checkerCalls != 0 {
		t.Fatalf("personal connection ran the enterprise checker %d times", checkerCalls)
	}
}

func TestAuthenticateTokenFullEnterprisePATSubject(t *testing.T) {
	resolver := staticEnterprisePATResolver{
		"mul_ent": {User: "user-1", Subject: "sub-1"},
	}
	uid, ent, errMsg := authenticateTokenFull("mul_ent", resolver, context.Background())
	if errMsg != "" || uid != "user-1" {
		t.Fatalf("uid=%q errMsg=%q", uid, errMsg)
	}
	if ent.PATSubject != "sub-1" {
		t.Fatalf("PATSubject = %q", ent.PATSubject)
	}

	uid, ent, errMsg = authenticateTokenFull("mul_plain", staticPATResolver{"mul_plain": "user-2"}, context.Background())
	if errMsg != "" || uid != "user-2" || !ent.Empty() {
		t.Fatalf("plain PAT uid=%q ent=%+v errMsg=%q", uid, ent, errMsg)
	}
}

// TestCloseEnterpriseUserConnectionsClosesOnlyEnterprise pins the C-4c push
// path: the platform invalidate call closes exactly the user's
// enterprise-managed connections — enterprise_revoked frame first, then a
// close — while the same user's personal connections stay up.
func TestCloseEnterpriseUserConnectionsClosesOnlyEnterprise(t *testing.T) {
	hub := NewHub()
	go hub.Run()
	mc := &mockMembershipChecker{}
	hub.SetMembershipChecker(mc)

	mux := http.NewServeMux()
	mux.HandleFunc("/ws", func(w http.ResponseWriter, r *http.Request) {
		HandleWebSocketWithEnterprise(hub, mc, nil, nil,
			func(ctx context.Context, userID string, ent EnterpriseTokenInfo) bool { return true }, w, r)
	})
	server := httptest.NewServer(mux)
	defer server.Close()

	entConn := dialEnterpriseWS(t, server, enterpriseToken(t, testUserID, "sess-1", 7))
	defer entConn.Close()
	personalConn := dialEnterpriseWS(t, server, makeTestToken(t))
	defer personalConn.Close()
	// Both connections read their auth_ack before registration completes.
	for _, c := range []*websocket.Conn{entConn, personalConn} {
		c.SetReadDeadline(time.Now().Add(2 * time.Second))
		if _, _, err := c.ReadMessage(); err != nil {
			t.Fatalf("read auth_ack: %v", err)
		}
	}

	closed := hub.CloseEnterpriseUserConnections(testUserID)
	if closed != 1 {
		t.Fatalf("closed %d connections, want 1 (only the enterprise one)", closed)
	}

	// The enterprise connection receives the frame, then the socket closes.
	entConn.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, frame, err := entConn.ReadMessage()
	if err != nil {
		t.Fatalf("read enterprise_revoked: %v", err)
	}
	if string(frame) != `{"type":"enterprise_revoked"}` {
		t.Fatalf("frame = %s", frame)
	}
	if _, _, err := entConn.ReadMessage(); err == nil {
		t.Fatal("enterprise connection stayed open after enterprise_revoked")
	}

	// The personal connection gets nothing and stays registered.
	personalConn.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
	if _, _, err := personalConn.ReadMessage(); err == nil {
		t.Fatal("personal connection received an enterprise frame")
	}
	if n := len(hub.clients); n != 1 {
		t.Fatalf("hub holds %d clients, want the personal one only", n)
	}
}

// TestEnterpriseRecheckClosesDriftedConnection pins C-4d: connect-time
// validation alone cannot catch a revocation that lands while the socket is
// up. The periodic recheck re-runs the epoch check and closes the connection
// with the enterprise_revoked frame once the epoch drifts.
func TestEnterpriseRecheckClosesDriftedConnection(t *testing.T) {
	prev := enterpriseRecheckInterval
	enterpriseRecheckInterval = 20 * time.Millisecond
	t.Cleanup(func() { enterpriseRecheckInterval = prev })

	hub := NewHub()
	go hub.Run()
	mc := &mockMembershipChecker{}
	hub.SetMembershipChecker(mc)

	var calls atomic.Int32
	mux := http.NewServeMux()
	mux.HandleFunc("/ws", func(w http.ResponseWriter, r *http.Request) {
		HandleWebSocketWithEnterprise(hub, mc, nil, nil,
			func(ctx context.Context, userID string, ent EnterpriseTokenInfo) bool {
				// First call is the connect-time check (passes); later calls
				// are the recheck and report the entitlement gone.
				return calls.Add(1) == 1
			}, w, r)
	})
	server := httptest.NewServer(mux)
	defer server.Close()

	conn := dialEnterpriseWS(t, server, enterpriseToken(t, testUserID, "sess-1", 7))
	defer conn.Close()
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, _, err := conn.ReadMessage(); err != nil {
		t.Fatalf("read auth_ack: %v", err)
	}

	for {
		_, frame, err := conn.ReadMessage()
		if err != nil {
			t.Fatalf("connection closed without the revoked frame: %v", err)
		}
		if string(frame) == `{"type":"enterprise_revoked"}` {
			break
		}
	}
	// The server closes after the frame.
	if _, _, err := conn.ReadMessage(); err == nil {
		t.Fatal("connection stayed open after enterprise_revoked")
	}
	if calls.Load() < 2 {
		t.Fatalf("checker ran %d times, want connect + at least one recheck", calls.Load())
	}
}
