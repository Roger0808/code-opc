package handler

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/multica-ai/multica/server/internal/testutil"
)

// authorizeStub records the platform INT-101a request and serves a canned
// authorize response.
type authorizeStub struct {
	t          *testing.T
	status     int
	body       map[string]any
	method     string
	path       string
	auth       string
	clientID   string
	redirect   string
	state      string
	challenge  string
	methodBody string
}

func (s *authorizeStub) handler() *httptest.Server {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.method = r.Method
		s.path = r.URL.Path
		s.auth = r.Header.Get("Authorization")
		var body map[string]string
		_ = json.NewDecoder(r.Body).Decode(&body)
		s.clientID = body["client_id"]
		s.redirect = body["redirect_uri"]
		s.state = body["state"]
		s.challenge = body["code_challenge"]
		s.methodBody = body["code_challenge_method"]
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(s.status)
		_ = json.NewEncoder(w).Encode(s.body)
	}))
	s.t.Cleanup(server.Close)
	return server
}

func beginRequest(body string) *http.Request {
	req := httptest.NewRequest("POST", "/api/enterprise/begin", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	return req
}

func TestEnterpriseBeginProxiesPlatformAuthorize(t *testing.T) {
	if testHandler == nil {
		t.Skip("database not available")
	}
	stub := &authorizeStub{t: t, status: http.StatusOK, body: map[string]any{
		"login_txn_id":  "txn-9",
		"authorize_url": "https://platform.example.com/wecom/scan?txn=txn-9",
	}}
	server := stub.handler()
	previous := testHandler.Platform
	testHandler.Platform = mustPlatformClient(t, server.URL)
	t.Cleanup(func() { testHandler.Platform = previous })

	rec := testutil.Call(t, testHandler.EnterpriseBegin, beginRequest(`{
		"state": "state-1",
		"code_challenge": "challenge-1",
		"redirect_uri": "http://127.0.0.1:49152/callback"
	}`))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d (%s)", rec.Code, rec.Body.String())
	}

	// The platform contract is POST, not the GET the desktop used to build.
	if stub.method != http.MethodPost || stub.path != "/integration/v1/auth/authorize" {
		t.Fatalf("platform call = %s %s, want POST /integration/v1/auth/authorize", stub.method, stub.path)
	}
	if stub.auth != "" {
		t.Fatalf("public authorize endpoint got Authorization %q", stub.auth)
	}
	if stub.clientID != "code-desktop" {
		t.Fatalf("client_id = %q", stub.clientID)
	}
	if stub.redirect != "http://127.0.0.1:49152/callback" || stub.state != "state-1" ||
		stub.challenge != "challenge-1" || stub.methodBody != "S256" {
		t.Fatalf("platform body = (%q, %q, %q, %q)", stub.redirect, stub.state, stub.challenge, stub.methodBody)
	}

	var out struct {
		LoginTxnID   string `json:"login_txn_id"`
		AuthorizeURL string `json:"authorize_url"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if out.LoginTxnID != "txn-9" || out.AuthorizeURL == "" {
		t.Fatalf("response = %+v", out)
	}
}

func TestEnterpriseBeginRejectsNonLoopbackRedirectURI(t *testing.T) {
	if testHandler == nil {
		t.Skip("database not available")
	}
	previous := testHandler.Platform
	testHandler.Platform = mustPlatformClient(t, "http://platform.invalid")
	t.Cleanup(func() { testHandler.Platform = previous })

	cases := []struct {
		name string
		uri  string
	}{
		{"https scheme", "https://127.0.0.1:49152/callback"},
		{"non-loopback host", "http://example.com:49152/callback"},
		{"localhost name", "http://localhost:49152/callback"},
		{"missing port", "http://127.0.0.1/callback"},
		{"wrong path", "http://127.0.0.1:49152/elsewhere"},
		{"query smuggled", "http://127.0.0.1:49152/callback?next=http://evil.example"},
		{"fragment smuggled", "http://127.0.0.1:49152/callback#evil"},
		{"garbage", "not a url"},
		{"empty", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			body := `{"state":"s","code_challenge":"c","redirect_uri":"` + tc.uri + `"}`
			rec := testutil.Call(t, testHandler.EnterpriseBegin, beginRequest(body))
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400 (%s)", rec.Code, rec.Body.String())
			}
			if got := errorCode(t, rec.Body.String()); got != "enterprise_redirect_uri_not_allowed" {
				t.Fatalf("code = %q", got)
			}
		})
	}
}

func TestEnterpriseBeginRequiresFieldsAndConfiguration(t *testing.T) {
	if testHandler == nil {
		t.Skip("database not available")
	}
	previous := testHandler.Platform
	testHandler.Platform = nil
	t.Cleanup(func() { testHandler.Platform = previous })

	rec := testutil.Call(t, testHandler.EnterpriseBegin, beginRequest(`{"state":"s","code_challenge":"c","redirect_uri":"http://127.0.0.1:1/callback"}`))
	if rec.Code != http.StatusForbidden || errorCode(t, rec.Body.String()) != "enterprise_not_configured" {
		t.Fatalf("status = %d (%s)", rec.Code, rec.Body.String())
	}

	testHandler.Platform = mustPlatformClient(t, "http://platform.invalid")
	for _, body := range []string{
		`{"code_challenge":"c","redirect_uri":"http://127.0.0.1:1/callback"}`,
		`{"state":"s","redirect_uri":"http://127.0.0.1:1/callback"}`,
		`not json`,
	} {
		rec := testutil.Call(t, testHandler.EnterpriseBegin, beginRequest(body))
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("body %s: status = %d, want 400", body, rec.Code)
		}
	}
}

func TestEnterpriseBeginPlatformErrors(t *testing.T) {
	if testHandler == nil {
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
			name:       "bad challenge passes the platform code through",
			status:     http.StatusBadRequest,
			body:       map[string]any{"code": "INVALID_CODE_CHALLENGE", "message": "challenge must be S256"},
			wantStatus: http.StatusBadRequest,
			wantCode:   "INVALID_CODE_CHALLENGE",
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
			stub := &authorizeStub{t: t, status: tc.status, body: tc.body}
			server := stub.handler()
			testHandler.Platform = mustPlatformClient(t, server.URL)

			rec := testutil.Call(t, testHandler.EnterpriseBegin, beginRequest(`{
				"state": "s", "code_challenge": "c",
				"redirect_uri": "http://127.0.0.1:49152/callback"
			}`))
			if rec.Code != tc.wantStatus {
				t.Fatalf("status = %d, want %d (%s)", rec.Code, tc.wantStatus, rec.Body.String())
			}
			if tc.wantCode != "" && errorCode(t, rec.Body.String()) != tc.wantCode {
				t.Fatalf("code = %q, want %q", errorCode(t, rec.Body.String()), tc.wantCode)
			}
		})
	}
}
