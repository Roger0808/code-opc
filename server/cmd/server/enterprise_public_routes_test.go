package main

import (
	"io"
	"net/http"
	"strings"
	"testing"
)

// TestEnterpriseLoginRoutesArePublic_NoTokenNot401 pins the C-1 fix: the
// enterprise begin/exchange endpoints are PRE-SESSION by definition — the
// desktop holds no Multica session until the exchange completes — so they
// live outside middleware.Auth. Before the fix both sat in the
// session-gated group and a tokenless login attempt died with 401 before
// reaching the handler.
//
// The test environment has no PLATFORM_BASE_URL, so the handler's
// not-configured gate (403) fires before body validation — the assertions
// therefore pin: never 401, and a well-formed body provably reaches the
// handler (403 enterprise_not_configured rather than an auth or routing
// failure).
func TestEnterpriseLoginRoutesArePublic_NoTokenNot401(t *testing.T) {
	cases := []struct {
		name string
		path string
		body string
	}{
		{"begin well-formed", "/api/enterprise/begin", `{"state":"s","code_challenge":"c","redirect_uri":"http://127.0.0.1:49152/callback"}`},
		{"begin malformed", "/api/enterprise/begin", `{"state":"s"}`},
		{"exchange well-formed", "/api/enterprise/exchange", `{"exchange_token":"x","code_verifier":"v"}`},
		{"exchange malformed", "/api/enterprise/exchange", `{}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Deliberately NO Authorization header or session cookie: this is
			// the pre-login shape the desktop client actually sends.
			resp, err := http.Post(testServer.URL+tc.path, "application/json", strings.NewReader(tc.body))
			if err != nil {
				t.Fatalf("request failed: %v", err)
			}
			defer resp.Body.Close()
			body, _ := io.ReadAll(resp.Body)

			if resp.StatusCode == http.StatusUnauthorized {
				t.Fatalf("%s returned 401 without a session — it is still behind the Auth group. body=%s", tc.path, body)
			}
			// 403 (enterprise_not_configured) proves the request reached the
			// handler in this platform-less test env; 400 proves the body
			// validators ran. Anything else (404/405/5xx) means the route
			// registration itself is broken.
			if resp.StatusCode != http.StatusForbidden && resp.StatusCode != http.StatusBadRequest {
				t.Fatalf("%s: status = %d, want 400 or 403 (body=%s)", tc.path, resp.StatusCode, body)
			}
		})
	}
}
