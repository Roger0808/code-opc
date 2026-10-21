package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/multica-ai/multica/server/internal/auth"
	"github.com/multica-ai/multica/server/internal/platform"
	"github.com/multica-ai/multica/server/internal/testutil"
)

// platformStub serves the INT-101g contract for exchange tests.
type platformStub struct {
	t        *testing.T
	status   int
	body     map[string]any
	requests int
	token    string
	verifier string
}

func (ps *platformStub) handler() *httptest.Server {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ps.requests++
		ps.token = r.Header.Get("Authorization")
		var reqBody struct {
			CodeVerifier string `json:"code_verifier"`
		}
		_ = json.NewDecoder(r.Body).Decode(&reqBody)
		ps.verifier = reqBody.CodeVerifier
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(ps.status)
		_ = json.NewEncoder(w).Encode(ps.body)
	}))
	ps.t.Cleanup(server.Close)
	return server
}

func exchangeRequest(body string) *http.Request {
	req := httptest.NewRequest("POST", "/api/enterprise/exchange", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	return req
}

func exchangeSuccessBody(subject string, version int64) map[string]any {
	return map[string]any{
		"subject":           subject,
		"identity_link_id":  "ilink-" + subject,
		"knowledge_user_id": "ku-" + subject,
		"code_user_id":      "cu-" + subject,
		"authz_version":     version,
		"spaces":            []map[string]any{{"id": "pw-" + subject, "tenant": "acme"}},
	}
}

func decodeLoginToken(t *testing.T, tokenString string) jwt.MapClaims {
	t.Helper()
	token, err := jwt.Parse(tokenString, func(t *jwt.Token) (any, error) {
		return auth.JWTSecret(), nil
	})
	if err != nil || !token.Valid {
		t.Fatalf("parse login token: %v", err)
	}
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		t.Fatal("claims are not MapClaims")
	}
	return claims
}

func TestEnterpriseExchangeSuccess(t *testing.T) {
	if testHandler == nil || testPool == nil {
		t.Skip("database not available")
	}
	stub := &platformStub{t: t, status: http.StatusOK, body: exchangeSuccessBody("sub-x", 42)}
	server := stub.handler()
	previous := testHandler.Platform
	testHandler.Platform = mustPlatformClient(t, server.URL)
	t.Cleanup(func() { testHandler.Platform = previous })

	rec := testutil.Call(t, testHandler.EnterpriseExchange, exchangeRequest(`{"exchange_token":"xtok","code_verifier":"verifier-1"}`))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d (%s)", rec.Code, rec.Body.String())
	}
	if stub.token != "Bearer svc" {
		t.Fatalf("service token not presented: %q", stub.token)
	}
	if stub.verifier != "verifier-1" {
		t.Fatalf("code_verifier not forwarded to the platform: %q", stub.verifier)
	}

	var resp LoginResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode login response: %v", err)
	}
	claims := decodeLoginToken(t, resp.Token)
	if claims[auth.EnterpriseSessionClaim] == "" {
		t.Fatalf("login token missing ent_sid: %v", claims)
	}
	if claims[auth.EnterpriseVersionClaim] != float64(42) {
		t.Fatalf("ent_ver = %v, want 42", claims[auth.EnterpriseVersionClaim])
	}

	// The user row carries the epoch the token was signed against.
	var userID, subject, sessionID string
	var version int64
	dbfx.QueryRow(t, `
		SELECT id, enterprise_subject, enterprise_session_id, enterprise_authz_version
		FROM "user" WHERE id = $1
	`, resp.User.ID).Scan(&userID, &subject, &sessionID, &version)
	if subject != "sub-x" || version != 42 || sessionID != claims[auth.EnterpriseSessionClaim] {
		t.Fatalf("user row epoch mismatch: subject=%q version=%d sid=%q", subject, version, sessionID)
	}
	if !strings.HasPrefix(resp.User.Email, "enterprise-sub-x@") {
		t.Fatalf("placeholder email = %q", resp.User.Email)
	}

	// The space became an enterprise workspace linked to the user.
	var linkCount int
	dbfx.QueryRow(t, `
		SELECT count(*) FROM enterprise_workspace_link
		WHERE user_id = $1 AND platform_workspace_id = 'pw-sub-x'
	`, userID).Scan(&linkCount)
	if linkCount != 1 {
		t.Fatalf("workspace links = %d", linkCount)
	}
	var wsID, wsName string
	dbfx.QueryRow(t, `
		SELECT w.id, w.name FROM workspace w
		JOIN enterprise_workspace_link l ON l.workspace_id = w.id
		WHERE l.user_id = $1
	`, userID).Scan(&wsID, &wsName)
	if wsName != "enterprise-acme" {
		t.Fatalf("workspace name = %q, want enterprise-acme", wsName)
	}
	t.Cleanup(func() {
		ctx := context.Background()
		testPool.Exec(ctx, `DELETE FROM enterprise_workspace_link WHERE user_id = $1`, userID)
		testPool.Exec(ctx, `DELETE FROM member WHERE user_id = $1`, userID)
		testPool.Exec(ctx, `DELETE FROM workspace WHERE id = $1`, wsID)
		testPool.Exec(ctx, `DELETE FROM "user" WHERE id = $1`, userID)
	})
}

// TestEnterpriseExchangeMirrorsSpaceRoles pins the role mapping: the
// platform's per-space role (viewer/contributor/admin/owner) decides the
// mirrored member row — viewer/contributor collapse to member, missing or
// unknown values default to member, and nothing is silently owner.
func TestEnterpriseExchangeMirrorsSpaceRoles(t *testing.T) {
	if testHandler == nil || testPool == nil {
		t.Skip("database not available")
	}
	body := exchangeSuccessBody("sub-roles", 1)
	body["spaces"] = []map[string]any{
		{"id": "pw-viewer", "tenant": "acme", "role": "viewer"},
		{"id": "pw-contributor", "tenant": "acme", "role": "contributor"},
		{"id": "pw-admin", "tenant": "acme", "role": "admin"},
		{"id": "pw-owner", "tenant": "acme", "role": "owner"},
		{"id": "pw-bare", "tenant": "acme"},
	}
	stub := &platformStub{t: t, status: http.StatusOK, body: body}
	server := stub.handler()
	previous := testHandler.Platform
	testHandler.Platform = mustPlatformClient(t, server.URL)
	t.Cleanup(func() { testHandler.Platform = previous })

	rec := testutil.Call(t, testHandler.EnterpriseExchange,
		exchangeRequest(`{"exchange_token":"xtok","code_verifier":"v-roles"}`))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d (%s)", rec.Code, rec.Body.String())
	}

	want := map[string]string{
		"pw-viewer":      "member",
		"pw-contributor": "member",
		"pw-admin":       "admin",
		"pw-owner":       "owner",
		"pw-bare":        "member",
	}
	var userID string
	dbfx.QueryRow(t, `SELECT id FROM "user" WHERE enterprise_subject = 'sub-roles'`).Scan(&userID)
	for platformWS, wantRole := range want {
		var role string
		dbfx.QueryRow(t, `
			SELECT m.role FROM member m
			JOIN enterprise_workspace_link l ON l.workspace_id = m.workspace_id AND l.user_id = m.user_id
			WHERE l.user_id = $1 AND l.platform_workspace_id = $2
		`, userID, platformWS).Scan(&role)
		if role != wantRole {
			t.Fatalf("space %s: role = %q, want %q", platformWS, role, wantRole)
		}
	}
	t.Cleanup(func() {
		ctx := context.Background()
		testPool.Exec(ctx, `DELETE FROM member WHERE user_id = $1`, userID)
		testPool.Exec(ctx, `DELETE FROM workspace WHERE id IN (
			SELECT workspace_id FROM enterprise_workspace_link WHERE user_id = $1
		)`, userID)
		testPool.Exec(ctx, `DELETE FROM enterprise_workspace_link WHERE user_id = $1`, userID)
		testPool.Exec(ctx, `DELETE FROM "user" WHERE id = $1`, userID)
	})
}

func TestEnterpriseExchangeIdempotentUser(t *testing.T) {
	if testHandler == nil || testPool == nil {
		t.Skip("database not available")
	}
	stub := &platformStub{t: t, status: http.StatusOK, body: exchangeSuccessBody("sub-replay", 1)}
	server := stub.handler()
	previous := testHandler.Platform
	testHandler.Platform = mustPlatformClient(t, server.URL)
	t.Cleanup(func() { testHandler.Platform = previous })

	first := testutil.Call(t, testHandler.EnterpriseExchange, exchangeRequest(`{"exchange_token":"a","code_verifier":"v-a"}`))
	if first.Code != http.StatusOK {
		t.Fatalf("first exchange: %d (%s)", first.Code, first.Body.String())
	}
	var userID string
	dbfx.QueryRow(t, `SELECT id FROM "user" WHERE enterprise_subject = 'sub-replay'`).Scan(&userID)
	var firstSID string
	dbfx.QueryRow(t, `SELECT enterprise_session_id FROM "user" WHERE id = $1`, userID).Scan(&firstSID)

	// Platform moves the version forward; re-exchange must reuse the user,
	// mint a fresh session epoch and update the version — never duplicate.
	stub.body = exchangeSuccessBody("sub-replay", 2)
	second := testutil.Call(t, testHandler.EnterpriseExchange, exchangeRequest(`{"exchange_token":"b","code_verifier":"v-b"}`))
	if second.Code != http.StatusOK {
		t.Fatalf("second exchange: %d (%s)", second.Code, second.Body.String())
	}
	var secondUserID, secondSID string
	var secondVersion int64
	dbfx.QueryRow(t, `
		SELECT id, enterprise_session_id, enterprise_authz_version
		FROM "user" WHERE enterprise_subject = 'sub-replay'
	`).Scan(&secondUserID, &secondSID, &secondVersion)
	if secondUserID != userID {
		t.Fatal("re-exchange created a duplicate user")
	}
	if secondSID == firstSID {
		t.Fatal("re-exchange did not rotate the session epoch")
	}
	if secondVersion != 2 {
		t.Fatalf("version = %d, want 2", secondVersion)
	}
	var userCount int
	dbfx.QueryRow(t, `SELECT count(*) FROM "user" WHERE enterprise_subject = 'sub-replay'`).Scan(&userCount)
	if userCount != 1 {
		t.Fatalf("users for subject = %d", userCount)
	}
	t.Cleanup(func() {
		ctx := context.Background()
		testPool.Exec(ctx, `DELETE FROM workspace WHERE id IN (
			SELECT workspace_id FROM enterprise_workspace_link WHERE user_id = $1
		)`, userID)
		testPool.Exec(ctx, `DELETE FROM enterprise_workspace_link WHERE user_id = $1`, userID)
		testPool.Exec(ctx, `DELETE FROM member WHERE user_id = $1`, userID)
		testPool.Exec(ctx, `DELETE FROM "user" WHERE id = $1`, userID)
	})
}

func TestEnterpriseExchangePlatformErrors(t *testing.T) {
	if testHandler == nil || testPool == nil {
		t.Skip("database not available")
	}
	previous := testHandler.Platform
	t.Cleanup(func() { testHandler.Platform = previous })

	cases := []struct {
		name       string
		status     int
		body       map[string]any
		wantStatus int
		wantCode   string
	}{
		{
			name:       "replay rejected by platform",
			status:     http.StatusBadRequest,
			body:       map[string]any{"code": "EXCHANGE_TOKEN_REUSED", "message": "token already used"},
			wantStatus: http.StatusBadRequest,
			wantCode:   "EXCHANGE_TOKEN_REUSED",
		},
		{
			name:       "expired token",
			status:     http.StatusBadRequest,
			body:       map[string]any{"code": "EXCHANGE_TOKEN_EXPIRED", "message": "token expired"},
			wantStatus: http.StatusBadRequest,
			wantCode:   "EXCHANGE_TOKEN_EXPIRED",
		},
		{
			name:       "platform outage",
			status:     http.StatusBadGateway,
			body:       map[string]any{"error": "upstream down"},
			wantStatus: http.StatusBadGateway,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			stub := &platformStub{t: t, status: tc.status, body: tc.body}
			server := stub.handler()
			testHandler.Platform = mustPlatformClient(t, server.URL)

			rec := testutil.Call(t, testHandler.EnterpriseExchange, exchangeRequest(`{"exchange_token":"x","code_verifier":"v-x"}`))
			if rec.Code != tc.wantStatus {
				t.Fatalf("status = %d, want %d (%s)", rec.Code, tc.wantStatus, rec.Body.String())
			}
			if tc.wantCode != "" {
				if got := errorCode(t, rec.Body.String()); got != tc.wantCode {
					t.Fatalf("code = %q, want %q", got, tc.wantCode)
				}
			}
		})
	}
}

func TestEnterpriseExchangeRequiresConfigurationAndBody(t *testing.T) {
	if testHandler == nil {
		t.Skip("database not available")
	}
	previous := testHandler.Platform
	testHandler.Platform = nil
	t.Cleanup(func() { testHandler.Platform = previous })

	rec := testutil.Call(t, testHandler.EnterpriseExchange, exchangeRequest(`{"exchange_token":"x","code_verifier":"v-x"}`))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rec.Code)
	}
	if got := errorCode(t, rec.Body.String()); got != "enterprise_not_configured" {
		t.Fatalf("code = %q", got)
	}

	testHandler.Platform = mustPlatformClient(t, "http://platform.invalid")
	rec = testutil.Call(t, testHandler.EnterpriseExchange, exchangeRequest(`{}`))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("missing token: status = %d", rec.Code)
	}

	// The PKCE verifier is mandatory: the platform re-checks it (S256) before
	// releasing the identity, so the proxy must refuse to forward without one.
	rec = testutil.Call(t, testHandler.EnterpriseExchange, exchangeRequest(`{"exchange_token":"x"}`))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("missing code_verifier: status = %d (%s)", rec.Code, rec.Body.String())
	}
}

func mustPlatformClient(t *testing.T, baseURL string) *platform.Client {
	t.Helper()
	client, err := platform.New(platform.Config{
		BaseURL:         baseURL,
		ServiceToken:    "svc",
		LeaseHMACSecret: "lease-secret",
		HTTPClient:      &http.Client{Timeout: 5 * time.Second},
	})
	if err != nil {
		t.Fatalf("platform.New: %v", err)
	}
	return client
}

func TestEnterprisePATIssuanceSnapshotsSubject(t *testing.T) {
	if testHandler == nil || testPool == nil {
		t.Skip("database not available")
	}
	userID := dbfx.Insert(t, "user", testutil.Cols{
		"name": "pat ent", "email": "pat-ent-" + t.Name() + "@platform.local",
		"enterprise_subject": "sub-pat", "enterprise_session_id": "s1", "enterprise_authz_version": 3,
	})
	req := httptest.NewRequest("POST", "/api/personal-access-tokens", strings.NewReader(`{"name":"cli"}`))
	req.Header.Set("X-User-ID", userID)
	rec := testutil.Call(t, testHandler.CreatePersonalAccessToken, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d (%s)", rec.Code, rec.Body.String())
	}
	var storedSubject *string
	dbfx.QueryRow(t, `SELECT enterprise_subject FROM personal_access_token WHERE user_id = $1`, userID).Scan(&storedSubject)
	if storedSubject == nil || *storedSubject != "sub-pat" {
		t.Fatalf("snapshot = %v", storedSubject)
	}

	// Personal user: NULL snapshot, PAT stays a plain personal token.
	personalID := dbfx.Insert(t, "user", testutil.Cols{"name": "pat plain", "email": "pat-plain-" + t.Name() + "@multica.ai"})
	req = httptest.NewRequest("POST", "/api/personal-access-tokens", strings.NewReader(`{"name":"cli"}`))
	req.Header.Set("X-User-ID", personalID)
	rec = testutil.Call(t, testHandler.CreatePersonalAccessToken, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d (%s)", rec.Code, rec.Body.String())
	}
	dbfx.QueryRow(t, `SELECT enterprise_subject FROM personal_access_token WHERE user_id = $1`, personalID).Scan(&storedSubject)
	if storedSubject != nil {
		t.Fatalf("personal PAT snapshot = %v", *storedSubject)
	}
}

func TestEnterpriseRefresherReadsCurrentEpoch(t *testing.T) {
	if testHandler == nil || testPool == nil {
		t.Skip("database not available")
	}
	userID := dbfx.Insert(t, "user", testutil.Cols{
		"name": "refresher", "email": "refresher-" + t.Name() + "@platform.local",
		"enterprise_subject": "sub-r", "enterprise_session_id": "sess-r", "enterprise_authz_version": 9,
	})
	refresh := testHandler.enterpriseRefresher()
	sid, ver, ok := refresh(userID)
	if !ok || sid != "sess-r" || ver != 9 {
		t.Fatalf("refresher = (%q,%d,%v)", sid, ver, ok)
	}

	// A platform push bumped the version: the refresher must serve the new
	// epoch so sliding renewal re-signs against it.
	dbfx.Exec(t, `UPDATE "user" SET enterprise_authz_version = 10 WHERE id = $1`, userID)
	sid, ver, ok = refresh(userID)
	if !ok || sid != "sess-r" || ver != 10 {
		t.Fatalf("refresher after bump = (%q,%d,%v)", sid, ver, ok)
	}

	// Personal users renew into plain sessions.
	personalID := dbfx.Insert(t, "user", testutil.Cols{"name": "refresher p", "email": "refresher-p-" + t.Name() + "@multica.ai"})
	if _, _, ok := refresh(personalID); ok {
		t.Fatal("personal user reported an enterprise epoch")
	}
}

func TestRefreshSessionRotatesEnterpriseVersion(t *testing.T) {
	if testHandler == nil || testPool == nil {
		t.Skip("database not available")
	}
	userID := dbfx.Insert(t, "user", testutil.Cols{
		"name": "renew", "email": "renew-" + t.Name() + "@platform.local",
		"enterprise_subject": "sub-renew", "enterprise_session_id": "sess-renew", "enterprise_authz_version": 5,
	})

	// A session token inside its renewal window, signed against the old version.
	ttl := auth.AuthTokenTTL()
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub":                       userID,
		"email":                     "renew-" + t.Name() + "@platform.local",
		auth.EnterpriseSessionClaim: "sess-renew",
		auth.EnterpriseVersionClaim: 5,
		"exp":                       time.Now().Add(ttl / 4).Unix(),
		"iat":                       time.Now().Add(-ttl).Unix(),
	})
	signed, err := token.SignedString(auth.JWTSecret())
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	// The platform moved the version after the token was minted.
	dbfx.Exec(t, `UPDATE "user" SET enterprise_authz_version = 6 WHERE id = $1`, userID)

	req := httptest.NewRequest("POST", "/api/auth/refresh", nil)
	req.Header.Set("X-User-ID", userID)
	req.Header.Set("Authorization", "Bearer "+signed)
	rec := testutil.Call(t, testHandler.RefreshSession, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d (%s)", rec.Code, rec.Body.String())
	}
	var resp struct {
		Token   string `json:"token"`
		Renewed bool   `json:"renewed"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !resp.Renewed {
		t.Fatalf("not renewed: %s", rec.Body.String())
	}
	claims := decodeLoginToken(t, resp.Token)
	if claims[auth.EnterpriseVersionClaim] != float64(6) {
		t.Fatalf("renewed ent_ver = %v, want 6 from the database", claims[auth.EnterpriseVersionClaim])
	}
	if claims[auth.EnterpriseSessionClaim] != "sess-renew" {
		t.Fatalf("renewed ent_sid = %v", claims[auth.EnterpriseSessionClaim])
	}
}

func TestEnterpriseWorkspaceDetection(t *testing.T) {
	if testHandler == nil || testPool == nil {
		t.Skip("database not available")
	}
	f := newEnterpriseFixture(t)
	if !testHandler.enterpriseWorkspace(t.Context(), parseUUID(f.workspaceID)) {
		t.Fatal("linked workspace not detected as enterprise")
	}
	if testHandler.enterpriseWorkspace(t.Context(), parseUUID(testWorkspaceID)) {
		t.Fatal("plain workspace detected as enterprise")
	}
}
