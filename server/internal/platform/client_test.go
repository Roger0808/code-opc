package platform

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func newTestClient(t *testing.T, handler http.Handler) (*Client, *httptest.Server) {
	t.Helper()
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	client, err := New(Config{
		BaseURL:         server.URL,
		ServiceToken:    "svc-token",
		LeaseHMACSecret: "lease-secret",
		HTTPClient:      server.Client(),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return client, server
}

func TestCodeExchangeSuccess(t *testing.T) {
	client, server := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/integration/v1/auth/code-exchange" {
			t.Errorf("path = %q", r.URL.Path)
		}
		if auth := r.Header.Get("Authorization"); auth != "Bearer svc-token" {
			t.Errorf("Authorization = %q", auth)
		}
		var body map[string]string
		_ = json.NewDecoder(r.Body).Decode(&body)
		if body["exchange_token"] != "xtok" {
			t.Errorf("exchange_token = %q", body["exchange_token"])
		}
		// INT-101g requires the login transaction's PKCE verifier (S256
		// re-check on the platform side).
		if body["code_verifier"] != "verifier-1" {
			t.Errorf("code_verifier = %q", body["code_verifier"])
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"subject":           "sub-1",
			"identity_link_id":  "ilink-1",
			"knowledge_user_id": "ku-1",
			"code_user_id":      "cu-1",
			"authz_version":     42,
			"spaces":            []map[string]any{{"id": "pw-1", "tenant": "acme", "tenant_id": "ignored"}},
		})
	}))
	defer server.Close()

	out, err := client.CodeExchange(context.Background(), "xtok", "verifier-1")
	if err != nil {
		t.Fatalf("CodeExchange: %v", err)
	}
	if out.Subject != "sub-1" || out.IdentityLinkID != "ilink-1" || out.AuthzVersion != 42 {
		t.Fatalf("unexpected identity: %+v", out)
	}
	if len(out.Spaces) != 1 || out.Spaces[0].ID != "pw-1" || out.Spaces[0].Tenant != "acme" {
		t.Fatalf("unexpected spaces: %+v", out.Spaces)
	}
}

func TestCodeExchangeMissingSubjectFailsClosed(t *testing.T) {
	client, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"authz_version": 1})
	}))
	if _, err := client.CodeExchange(context.Background(), "xtok", "v"); err == nil {
		t.Fatal("expected error for subject-less exchange response")
	}
}

func TestCodeExchangePlatformErrorCarriesCode(t *testing.T) {
	client, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]string{"code": "EXCHANGE_TOKEN_REUSED", "message": "token already used"})
	}))
	_, err := client.CodeExchange(context.Background(), "xtok", "v")
	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("expected *APIError, got %T (%v)", err, err)
	}
	if apiErr.Code != "EXCHANGE_TOKEN_REUSED" || apiErr.StatusCode != http.StatusBadRequest {
		t.Fatalf("unexpected api error: %+v", apiErr)
	}
	if !IsCode(err, "EXCHANGE_TOKEN_REUSED") {
		t.Fatal("IsCode did not match")
	}
}

func TestCodeExchangeServerError(t *testing.T) {
	client, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
	}))
	_, err := client.CodeExchange(context.Background(), "xtok", "v")
	var apiErr *APIError
	if !errors.As(err, &apiErr) || apiErr.StatusCode != http.StatusBadGateway {
		t.Fatalf("expected 502 APIError, got %v", err)
	}
	if IsCode(err, CodeEntitlementRevoked) {
		t.Fatal("IsCode matched a code the error does not carry")
	}
}

func TestExchangeCodePostsTokenRequest(t *testing.T) {
	client, server := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("method = %q, want POST", r.Method)
		}
		if r.URL.Path != "/integration/v1/auth/token" {
			t.Errorf("path = %q", r.URL.Path)
		}
		// INT-101 token is public like authorize: no caller credential yet.
		if auth := r.Header.Get("Authorization"); auth != "" {
			t.Errorf("Authorization = %q, want none", auth)
		}
		var body map[string]string
		_ = json.NewDecoder(r.Body).Decode(&body)
		if body["grant_type"] != "authorization_code" || body["code"] != "code-1" ||
			body["code_verifier"] != "verifier-1" || body["client_id"] != "code-desktop" ||
			body["audience"] != "code-backend" || body["device"] != "dev-1" {
			t.Errorf("body = %v", body)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"exchange_token": "xtok-1"})
	}))
	defer server.Close()

	out, err := client.ExchangeCode(context.Background(), ExchangeCodeRequest{
		Code: "code-1", CodeVerifier: "verifier-1", Device: "dev-1",
	})
	if err != nil {
		t.Fatalf("ExchangeCode: %v", err)
	}
	if out.ExchangeToken != "xtok-1" {
		t.Fatalf("ExchangeToken = %q", out.ExchangeToken)
	}
}

func TestExchangeCodeValidatesCodeAndResponse(t *testing.T) {
	client, _ := newTestClient(t, http.NotFoundHandler())
	if _, err := client.ExchangeCode(context.Background(), ExchangeCodeRequest{Code: "  "}); err == nil {
		t.Fatal("empty code accepted")
	}

	broken, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "work-audience-shape"})
	}))
	if _, err := broken.ExchangeCode(context.Background(), ExchangeCodeRequest{Code: "c"}); err == nil ||
		!strings.Contains(err.Error(), "exchange_token") {
		t.Fatalf("expected exchange_token failure, got %v", err)
	}
}

func TestExchangeCodePlatformErrorCarriesCode(t *testing.T) {
	client, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]string{"code": "AUTH_CODE_REPLAYED", "message": "authorization code replayed or expired"})
	}))
	_, err := client.ExchangeCode(context.Background(), ExchangeCodeRequest{Code: "c", CodeVerifier: "v"})
	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("expected *APIError, got %T (%v)", err, err)
	}
	if apiErr.Code != "AUTH_CODE_REPLAYED" || apiErr.StatusCode != http.StatusBadRequest {
		t.Fatalf("unexpected api error: %+v", apiErr)
	}
	if !IsCode(err, "AUTH_CODE_REPLAYED") {
		t.Fatal("IsCode did not match")
	}
}

func TestNewRequiresConfiguration(t *testing.T) {
	if _, err := New(Config{}); !errors.Is(err, ErrNotConfigured) {
		t.Fatalf("expected ErrNotConfigured, got %v", err)
	}
	if _, err := New(Config{BaseURL: "http://x"}); err == nil || errors.Is(err, ErrNotConfigured) {
		t.Fatalf("expected service-token error, got %v", err)
	}
}

func signLease(t *testing.T, secret string, claims jwt.MapClaims) string {
	t.Helper()
	if claims == nil {
		claims = jwt.MapClaims{}
	}
	if _, ok := claims["exp"]; !ok {
		claims["exp"] = time.Now().Add(time.Minute).Unix()
	}
	signed, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString([]byte(secret))
	if err != nil {
		t.Fatalf("sign lease: %v", err)
	}
	return signed
}

func TestParseLeaseSuccess(t *testing.T) {
	client, _ := newTestClient(t, http.NotFoundHandler())
	lease := signLease(t, "lease-secret", jwt.MapClaims{
		"sub": "sub-1", "task_id": "t-1", "runtime_id": "r-1", "tenant_id": "ten-1", "grant_id": "g-1",
	})
	out, err := client.ParseLease(lease)
	if err != nil {
		t.Fatalf("ParseLease: %v", err)
	}
	if out.Subject != "sub-1" || out.TaskID != "t-1" || out.RuntimeID != "r-1" || out.TenantID != "ten-1" || out.GrantID != "g-1" {
		t.Fatalf("unexpected claims: %+v", out)
	}
	if out.ExpiresAt.Before(time.Now()) {
		t.Fatal("lease already expired")
	}
}

func TestParseLeaseExpired(t *testing.T) {
	client, _ := newTestClient(t, http.NotFoundHandler())
	lease := signLease(t, "lease-secret", jwt.MapClaims{
		"sub": "sub-1", "task_id": "t-1", "runtime_id": "r-1",
		"exp": time.Now().Add(-time.Minute).Unix(),
	})
	if _, err := client.ParseLease(lease); !errors.Is(err, jwt.ErrTokenExpired) {
		t.Fatalf("expected jwt.ErrTokenExpired, got %v", err)
	}
}

func TestParseLeaseWrongKeyAndMissingBindings(t *testing.T) {
	client, _ := newTestClient(t, http.NotFoundHandler())
	if _, err := client.ParseLease(signLease(t, "other-secret", nil)); err == nil {
		t.Fatal("expected signature failure with wrong key")
	}
	if _, err := client.ParseLease(signLease(t, "lease-secret", jwt.MapClaims{"sub": "s"})); err == nil {
		t.Fatal("expected failure for lease without task/runtime binding")
	}
	if _, err := client.ParseLease("not-a-jwt"); err == nil {
		t.Fatal("expected failure for garbage lease")
	}
}

func TestParseLeaseRequiresKey(t *testing.T) {
	client, err := New(Config{BaseURL: "http://localhost", ServiceToken: "t"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, err := client.ParseLease(signLease(t, "lease-secret", nil)); err == nil ||
		!strings.Contains(err.Error(), "not configured") {
		t.Fatalf("expected not-configured failure, got %v", err)
	}
}

func TestIssuerDefaultsAndOverride(t *testing.T) {
	client, _ := newTestClient(t, http.NotFoundHandler())
	if got := client.Issuer(); got != DefaultIssuer {
		t.Fatalf("Issuer() = %q, want DefaultIssuer %q", got, DefaultIssuer)
	}
	override, err := New(Config{BaseURL: "http://localhost", ServiceToken: "t", Issuer: " issuer-b "})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if got := override.Issuer(); got != "issuer-b" {
		t.Fatalf("Issuer() = %q, want issuer-b", got)
	}
	var nilClient *Client
	if got := nilClient.Issuer(); got != DefaultIssuer {
		t.Fatalf("nil client Issuer() = %q, want DefaultIssuer", got)
	}
}

func TestDownloadSkillRoundTrip(t *testing.T) {
	body := []byte("zip-bytes")
	client, server := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/integration/v1/skills/pub-1/download" {
			t.Errorf("path = %q", r.URL.Path)
		}
		if got := r.URL.Query().Get("sha256"); got != "abc123" {
			t.Errorf("sha256 query = %q", got)
		}
		if auth := r.Header.Get("Authorization"); auth != "Bearer svc-token" {
			t.Errorf("Authorization = %q", auth)
		}
		w.Header().Set("X-SHA256", "attested-digest")
		_, _ = w.Write(body)
	}))
	defer server.Close()

	pkg, err := client.DownloadSkill(context.Background(), "pub-1", "abc123")
	if err != nil {
		t.Fatalf("DownloadSkill: %v", err)
	}
	if string(pkg.Body) != string(body) {
		t.Fatalf("body = %q", pkg.Body)
	}
	if pkg.SHA256Header != "attested-digest" {
		t.Fatalf("X-SHA256 = %q", pkg.SHA256Header)
	}
}

func TestDownloadSkillRequiresPinAndPublishID(t *testing.T) {
	client, _ := newTestClient(t, http.NotFoundHandler())
	if _, err := client.DownloadSkill(context.Background(), "", "abc"); err == nil {
		t.Fatal("empty publishID accepted")
	}
	if _, err := client.DownloadSkill(context.Background(), "pub-1", "  "); err == nil {
		t.Fatal("empty sha256 accepted")
	}
}

func TestDownloadSkillErrorCarriesCode(t *testing.T) {
	client, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_ = json.NewEncoder(w).Encode(map[string]string{"code": "REVISION_NOT_FOUND", "message": "gone"})
	}))
	_, err := client.DownloadSkill(context.Background(), "pub-1", "abc")
	if !IsCode(err, "REVISION_NOT_FOUND") {
		t.Fatalf("err = %v", err)
	}
	var apiErr *APIError
	if !errors.As(err, &apiErr) || apiErr.StatusCode != http.StatusNotFound {
		t.Fatalf("err = %v", err)
	}
}

func TestAuthorizePostsPublicLoginBegin(t *testing.T) {
	client, server := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("method = %q, want POST", r.Method)
		}
		if r.URL.Path != "/integration/v1/auth/authorize" {
			t.Errorf("path = %q", r.URL.Path)
		}
		// INT-101a is public: the server service token must not ride along.
		if auth := r.Header.Get("Authorization"); auth != "" {
			t.Errorf("Authorization = %q, want none", auth)
		}
		var body map[string]string
		_ = json.NewDecoder(r.Body).Decode(&body)
		if body["client_id"] != "code-desktop" || body["redirect_uri"] != "http://127.0.0.1:49152/callback" ||
			body["state"] != "state-1" || body["code_challenge"] != "challenge-1" ||
			body["code_challenge_method"] != "S256" {
			t.Errorf("body = %v", body)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"login_txn_id":  "txn-1",
			"authorize_url": "https://platform.example.com/wecom/scan?txn=txn-1",
		})
	}))
	defer server.Close()

	out, err := client.Authorize(context.Background(), AuthorizeRequest{
		ClientID:            "code-desktop",
		RedirectURI:         "http://127.0.0.1:49152/callback",
		State:               "state-1",
		CodeChallenge:       "challenge-1",
		CodeChallengeMethod: "S256",
	})
	if err != nil {
		t.Fatalf("Authorize: %v", err)
	}
	if out.LoginTxnID != "txn-1" || out.AuthorizeURL == "" {
		t.Fatalf("unexpected response: %+v", out)
	}
}

func TestAuthorizeValidatesRequestAndResponse(t *testing.T) {
	client, _ := newTestClient(t, http.NotFoundHandler())
	if _, err := client.Authorize(context.Background(), AuthorizeRequest{
		ClientID: "code-desktop", RedirectURI: "http://127.0.0.1:1/callback", State: "s",
	}); err == nil {
		t.Fatal("empty code_challenge accepted")
	}

	broken, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"authorize_url": "https://platform.example.com/x"})
	}))
	if _, err := broken.Authorize(context.Background(), AuthorizeRequest{
		ClientID: "code-desktop", RedirectURI: "http://127.0.0.1:1/callback",
		State: "s", CodeChallenge: "c",
	}); err == nil || !strings.Contains(err.Error(), "login_txn_id") {
		t.Fatalf("expected login_txn_id failure, got %v", err)
	}
}

func TestListInternalSkillsQueriesSubjectAndTenant(t *testing.T) {
	client, server := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/integration/v1/internal/skills" {
			t.Errorf("path = %q", r.URL.Path)
		}
		if auth := r.Header.Get("Authorization"); auth != "Bearer svc-token" {
			t.Errorf("Authorization = %q", auth)
		}
		if got := r.URL.Query().Get("subject"); got != "sub-1" {
			t.Errorf("subject = %q", got)
		}
		if got := r.URL.Query().Get("tenant"); got != "tenant-a" {
			t.Errorf("tenant = %q", got)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"skills": []map[string]any{{
				"publish_id": "pub-1",
				"name":       "Deploy Skill",
				"version":    "1.2.3",
				"manifest":   map[string]string{"sha256": "sha256:abc"},
			}},
		})
	}))
	defer server.Close()

	skills, err := client.ListInternalSkills(context.Background(), "sub-1", "tenant-a")
	if err != nil {
		t.Fatalf("ListInternalSkills: %v", err)
	}
	if len(skills) != 1 || skills[0].PublishID != "pub-1" || skills[0].Version != "1.2.3" {
		t.Fatalf("unexpected skills: %+v", skills)
	}
	if got := skills[0].Pin(); got != "sha256:abc" {
		t.Fatalf("Pin() = %q", got)
	}
}

func TestListInternalSkillsOmitsEmptyTenantAndToleratesFlatDigest(t *testing.T) {
	client, server := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, ok := r.URL.Query()["tenant"]; ok {
			t.Errorf("tenant must be omitted for an all-tenant listing, got %q", r.URL.Query().Get("tenant"))
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"skills": []map[string]any{{
				"publish_id": "pub-2",
				"skill_id":   "pub-2",
				"version":    "1.0.0",
				"sha256":     "def456",
			}},
		})
	}))
	defer server.Close()

	skills, err := client.ListInternalSkills(context.Background(), "sub-1", "")
	if err != nil {
		t.Fatalf("ListInternalSkills: %v", err)
	}
	if len(skills) != 1 || skills[0].Pin() != "def456" {
		t.Fatalf("unexpected skills: %+v", skills)
	}

	if _, err := client.ListInternalSkills(context.Background(), "  ", "tenant-a"); err == nil {
		t.Fatal("empty subject accepted")
	}
}

// TestGetAuthzParsesSubjectKeyedView locks the real INT-102b wire shape:
// the platform answers {<subject>: {authz_version, revoked, entitlements}}
// (both GET single and POST batch). A flat-shape misparse once made the
// refresher read entitled=false and force-bump local versions, locking
// every enterprise session out with 401s.
func TestGetAuthzParsesSubjectKeyedView(t *testing.T) {
	client, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/integration/v1/internal/authz" {
			t.Errorf("path = %q", r.URL.Path)
		}
		if r.URL.Query().Get("subject") != "sub-1" {
			t.Errorf("subject = %q", r.URL.Query().Get("subject"))
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"sub-1": map[string]any{
				"authz_version": 7,
				"revoked":       false,
				"entitlements":  []string{"member"},
			},
		})
	}))

	out, err := client.GetAuthz(context.Background(), "sub-1", "")
	if err != nil {
		t.Fatalf("GetAuthz: %v", err)
	}
	if out.Subject != "sub-1" || out.AuthzVersion != 7 || !out.Entitled {
		t.Fatalf("unexpected authz view: %+v", out)
	}
}

func TestGetAuthzRevokedOrEmptyEntitlementsNotEntitled(t *testing.T) {
	cases := []struct {
		name string
		view map[string]any
	}{
		{"revoked", map[string]any{"authz_version": 3, "revoked": true, "entitlements": []string{}}},
		{"no-entitlements", map[string]any{"authz_version": 3, "revoked": false, "entitlements": []string{}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			view := tc.view
			client, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_ = json.NewEncoder(w).Encode(map[string]any{"sub-1": view})
			}))
			out, err := client.GetAuthz(context.Background(), "sub-1", "")
			if err != nil {
				t.Fatalf("GetAuthz: %v", err)
			}
			if out.Entitled {
				t.Fatalf("expected not entitled: %+v", out)
			}
		})
	}
}

func TestGetAuthzMissingSubjectFailsClosed(t *testing.T) {
	client, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"someone-else": map[string]any{}})
	}))
	if _, err := client.GetAuthz(context.Background(), "sub-1", ""); err == nil {
		t.Fatal("expected error when the view omits the requested subject")
	}
}
