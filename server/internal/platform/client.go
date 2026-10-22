// Package platform is the client side of the OPC platform integration
// contract. The platform owns enterprise identity, authorization versions
// and task grants; this server calls into it (never the reverse) and keeps
// every platform boundary fail-closed: an unreachable or misconfigured
// platform must degrade enterprise flows to refusals, never to local
// fallbacks.
package platform

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// Platform error codes surfaced by the integration contract.
const (
	// CodeEntitlementRevoked means the subject's enterprise entitlement is
	// gone; sessions and leases carrying it must stop working immediately.
	CodeEntitlementRevoked = "ENTITLEMENT_REVOKED"
	// CodeLeaseExpired means a grant lease reached the end of its lifetime
	// and was not renewed in time.
	CodeLeaseExpired = "LEASE_EXPIRED"
)

// ErrNotConfigured marks a client with no platform base URL. Enterprise
// endpoints must fail closed on it.
var ErrNotConfigured = errors.New("platform integration not configured")

// APIError is a non-2xx platform response carrying the platform's stable
// machine-readable error code.
type APIError struct {
	StatusCode int
	Code       string
	Message    string
}

func (e *APIError) Error() string {
	if e.Code != "" {
		return fmt.Sprintf("platform request failed: status %d: %s: %s", e.StatusCode, e.Code, e.Message)
	}
	return fmt.Sprintf("platform request failed: status %d: %s", e.StatusCode, e.Message)
}

// IsCode reports whether err is an APIError carrying the given platform code.
func IsCode(err error, code string) bool {
	var apiErr *APIError
	if errors.As(err, &apiErr) {
		return apiErr.Code == code
	}
	return false
}

// Config wires a Client. LeaseHMACSecret verifies platform-issued lease
// JWTs (HS256, aud set by the platform); the platform-side grant endpoints
// authenticate this server with the service token instead.
type Config struct {
	BaseURL         string
	ServiceToken    string
	LeaseHMACSecret string
	HTTPClient      *http.Client
	// Issuer names the platform deployment serving BaseURL. It is the
	// issuer segment of the BND-142 enterprise skill cache key, so skill
	// packages cached against one platform issuer never satisfy a request
	// pinned by another. Empty keeps DefaultIssuer.
	Issuer string
}

// DefaultIssuer is the cache-key issuer segment used when Config.Issuer is
// empty.
const DefaultIssuer = "platform"

// DesktopClientID is the pre-registered INT-101 client id of the code
// desktop app; every desktop login call (authorize, token) is made under it.
const DesktopClientID = "code-desktop"

// AudienceCodeBackend selects the INT-101 token audience the code server
// needs: a one-time exchange token (JWT, aud=code-backend, 120s, single
// use) that code-exchange consumes, instead of a work-session token pair.
const AudienceCodeBackend = "code-backend"

// maxSkillPackageBytes bounds one INT-142 skill package download. Skill
// bundles are text payloads; anything past this is a misbehaving platform
// and must fail closed instead of filling the cache disk.
const maxSkillPackageBytes = 32 << 20

// Client calls the platform integration API. The zero value is unusable;
// New validates the minimum viable configuration.
func New(cfg Config) (*Client, error) {
	baseURL := strings.TrimRight(strings.TrimSpace(cfg.BaseURL), "/")
	if baseURL == "" {
		return nil, ErrNotConfigured
	}
	if strings.TrimSpace(cfg.ServiceToken) == "" {
		return nil, errors.New("platform service token is required")
	}
	httpClient := cfg.HTTPClient
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 15 * time.Second}
	}
	return &Client{
		baseURL:         baseURL,
		serviceToken:    cfg.ServiceToken,
		leaseHMACSecret: []byte(cfg.LeaseHMACSecret),
		issuer:          strings.TrimSpace(cfg.Issuer),
		httpClient:      httpClient,
	}, nil
}

// Client is safe for concurrent use.
type Client struct {
	baseURL         string
	serviceToken    string
	leaseHMACSecret []byte
	issuer          string
	httpClient      *http.Client
}

// Issuer returns the cache-key issuer segment configured for this client,
// falling back to DefaultIssuer when the deployment did not name one.
func (c *Client) Issuer() string {
	if c == nil || strings.TrimSpace(c.issuer) == "" {
		return DefaultIssuer
	}
	return c.issuer
}

// CodeExchangeResponse is the platform answer to INT-101g: the enterprise
// identity the one-time exchange token stood for, plus the spaces it may
// reach and the authorization version the session epoch starts at.
type CodeExchangeResponse struct {
	Subject         string  `json:"subject"`
	IdentityLinkID  string  `json:"identity_link_id"`
	KnowledgeUserID string  `json:"knowledge_user_id"`
	CodeUserID      string  `json:"code_user_id"`
	AuthzVersion    int64   `json:"authz_version"`
	Spaces          []Space `json:"spaces"`
}

// Space is one enterprise workspace the identity may use. The platform
// contract only guarantees id; name/tenant are optional hints the exchange
// flow falls back from when absent. Role is the identity's platform role in
// this space (viewer/contributor/admin/owner), mirrored onto the local
// workspace member at exchange time.
type Space struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	Tenant string `json:"tenant"`
	Role   string `json:"role"`
}

// UnmarshalJSON tolerates the platform evolving the space shape: id is the
// only field the local link depends on.
func (s *Space) UnmarshalJSON(data []byte) error {
	var wire struct {
		ID     string `json:"id"`
		Name   string `json:"name"`
		Tenant string `json:"tenant"`
		Role   string `json:"role"`
		// Some platform versions key the tenant as tenant_id.
		TenantID string `json:"tenant_id"`
	}
	if err := json.Unmarshal(data, &wire); err != nil {
		return err
	}
	s.ID = wire.ID
	s.Name = wire.Name
	s.Tenant = wire.Tenant
	s.Role = wire.Role
	if s.Tenant == "" {
		s.Tenant = wire.TenantID
	}
	return nil
}

// ExchangeCodeRequest is the INT-101 token request for the desktop login:
// the loopback one-time authorization code plus the login transaction's
// PKCE verifier. Device is the desktop fingerprint the platform binds the
// exchange token to; empty is accepted.
type ExchangeCodeRequest struct {
	Code         string
	CodeVerifier string
	Device       string
}

// ExchangeCodeResponse is the platform answer for audience=code-backend:
// the one-time exchange token CodeExchange consumes.
type ExchangeCodeResponse struct {
	ExchangeToken string `json:"exchange_token"`
}

// ExchangeCode performs the INT-101 token step: trade the one-time loopback
// authorization code for the exchange token. Like Authorize this endpoint
// is public by contract — the login transaction is not complete yet, so no
// caller credential exists — hence no service token. The platform consumes
// the code atomically and rejects a PKCE S256 mismatch with 400
// AUTH_STATE_MISMATCH; a 4xx/5xx becomes *APIError so callers can map
// platform codes (replay, expiry) to local responses.
func (c *Client) ExchangeCode(ctx context.Context, req ExchangeCodeRequest) (ExchangeCodeResponse, error) {
	if strings.TrimSpace(req.Code) == "" {
		return ExchangeCodeResponse{}, errors.New("platform token exchange requires a code")
	}
	body, err := json.Marshal(map[string]string{
		"grant_type":    "authorization_code",
		"code":          req.Code,
		"code_verifier": req.CodeVerifier,
		"client_id":     DesktopClientID,
		"device":        req.Device,
		"audience":      AudienceCodeBackend,
	})
	if err != nil {
		return ExchangeCodeResponse{}, err
	}
	var out ExchangeCodeResponse
	if err := c.doNoAuth(ctx, http.MethodPost, "/integration/v1/auth/token", body, &out); err != nil {
		return ExchangeCodeResponse{}, err
	}
	if strings.TrimSpace(out.ExchangeToken) == "" {
		return ExchangeCodeResponse{}, errors.New("platform token response missing exchange_token")
	}
	return out, nil
}

// CodeExchange performs INT-101g: exchange a one-time desktop login token
// for the enterprise identity. The platform requires the login transaction's
// PKCE verifier and rejects an S256 mismatch with 400 AUTH_STATE_MISMATCH.
// A 4xx/5xx becomes *APIError so callers can map platform codes (replay,
// expiry) to local responses.
func (c *Client) CodeExchange(ctx context.Context, exchangeToken, codeVerifier string) (CodeExchangeResponse, error) {
	body, err := json.Marshal(map[string]string{
		"exchange_token": exchangeToken,
		"code_verifier":  codeVerifier,
	})
	if err != nil {
		return CodeExchangeResponse{}, err
	}
	var out CodeExchangeResponse
	if err := c.do(ctx, http.MethodPost, "/integration/v1/auth/code-exchange", body, &out); err != nil {
		return CodeExchangeResponse{}, err
	}
	if strings.TrimSpace(out.Subject) == "" {
		return CodeExchangeResponse{}, errors.New("platform code exchange response missing subject")
	}
	return out, nil
}

// AuthorizeRequest is the INT-101a login-begin payload. The code backend
// proxies the desktop's parameters so the platform never talks to the
// renderer directly; client_id names the pre-registered code desktop app.
type AuthorizeRequest struct {
	ClientID      string `json:"client_id"`
	RedirectURI   string `json:"redirect_uri"`
	State         string `json:"state"`
	CodeChallenge string `json:"code_challenge"`
	// CodeChallengeMethod is always "S256" for this integration; it is sent
	// explicitly so a platform default can never downgrade the method.
	CodeChallengeMethod string `json:"code_challenge_method"`
}

// AuthorizeResponse is the platform answer to INT-101a: the browser URL the
// desktop must open and the platform login transaction it belongs to.
type AuthorizeResponse struct {
	LoginTxnID   string `json:"login_txn_id"`
	AuthorizeURL string `json:"authorize_url"`
}

// Authorize performs INT-101a: create a platform login transaction and get
// the authorize URL for it. The endpoint is public by contract (it starts a
// login, so no caller credential exists yet), so unlike every other platform
// call this one sends no service token.
func (c *Client) Authorize(ctx context.Context, req AuthorizeRequest) (AuthorizeResponse, error) {
	if strings.TrimSpace(req.ClientID) == "" || strings.TrimSpace(req.RedirectURI) == "" ||
		strings.TrimSpace(req.State) == "" || strings.TrimSpace(req.CodeChallenge) == "" {
		return AuthorizeResponse{}, errors.New("platform authorize requires client_id, redirect_uri, state and code_challenge")
	}
	body, err := json.Marshal(req)
	if err != nil {
		return AuthorizeResponse{}, err
	}
	var out AuthorizeResponse
	if err := c.doNoAuth(ctx, http.MethodPost, "/integration/v1/auth/authorize", body, &out); err != nil {
		return AuthorizeResponse{}, err
	}
	if strings.TrimSpace(out.LoginTxnID) == "" || strings.TrimSpace(out.AuthorizeURL) == "" {
		return AuthorizeResponse{}, errors.New("platform authorize response missing login_txn_id or authorize_url")
	}
	return out, nil
}

// EnterpriseSkillListing is one entry of the internal skill listing the
// platform builds for claim-time SkillRef issuance. Manifest.SHA256 is the
// pinned skill manifest hash (the BND-142 pin vocabulary); SHA256 carries
// the same digest in the flat INT-142 listing spelling, so Pin accepts
// whichever shape this platform deployment returns.
type EnterpriseSkillListing struct {
	PublishID string `json:"publish_id"`
	SkillID   string `json:"skill_id"`
	Name      string `json:"name"`
	Version   string `json:"version"`
	SHA256    string `json:"sha256"`
	Manifest  struct {
		SHA256 string `json:"sha256"`
	} `json:"manifest"`
}

// Pin returns the pinned manifest digest in BND-142 vocabulary (bare or
// "sha256:"-prefixed hex), preferring the nested manifest spelling.
func (e EnterpriseSkillListing) Pin() string {
	if strings.TrimSpace(e.Manifest.SHA256) != "" {
		return e.Manifest.SHA256
	}
	return e.SHA256
}

// ListInternalSkills fetches the enterprise skills visible to one subject
// (GET /integration/v1/internal/skills, service token). tenant narrows the
// listing to one platform tenant; empty lists the subject's entitled skills
// across all tenants. The platform filters by entitlement, so an
// unreachable or denying platform fails closed upstream.
func (c *Client) ListInternalSkills(ctx context.Context, subject, tenant string) ([]EnterpriseSkillListing, error) {
	if strings.TrimSpace(subject) == "" {
		return nil, errors.New("platform internal skills listing requires a subject")
	}
	query := url.Values{}
	query.Set("subject", subject)
	if tenant != "" {
		query.Set("tenant", tenant)
	}
	var out struct {
		Skills []EnterpriseSkillListing `json:"skills"`
	}
	if err := c.do(ctx, http.MethodGet, "/integration/v1/internal/skills?"+query.Encode(), nil, &out); err != nil {
		return nil, err
	}
	return out.Skills, nil
}

// GrantRequest is the INT-102 grant minting payload.
type GrantRequest struct {
	Subject           string   `json:"subject"`
	TenantID          string   `json:"tenant_id"`
	WorkspaceID       string   `json:"workspace_id"`
	TaskID            string   `json:"task_id"`
	RuntimeID         string   `json:"runtime_id"`
	OriginatingUserID string   `json:"originating_user_id"`
	Capabilities      []string `json:"capabilities"`
}

// GrantResponse carries the lease the daemon must present when claiming the
// granted enterprise task.
type GrantResponse struct {
	GrantID        string `json:"grant_id"`
	LeaseToken     string `json:"lease_token"`
	LeaseExpiresAt string `json:"lease_expires_at"`
}

// CreateGrant mints an INT-102 grant for one enterprise task.
func (c *Client) CreateGrant(ctx context.Context, req GrantRequest) (GrantResponse, error) {
	body, err := json.Marshal(req)
	if err != nil {
		return GrantResponse{}, err
	}
	var out GrantResponse
	if err := c.do(ctx, http.MethodPost, "/integration/v1/internal/grants", body, &out); err != nil {
		return GrantResponse{}, err
	}
	return out, nil
}

// RenewGrant extends an INT-102 grant lease.
func (c *Client) RenewGrant(ctx context.Context, grantID string) (GrantResponse, error) {
	var out GrantResponse
	if err := c.do(ctx, http.MethodPost, "/integration/v1/internal/grants/"+grantID+"/renew", nil, &out); err != nil {
		return GrantResponse{}, err
	}
	return out, nil
}

// AuthzResponse is the platform authorization snapshot for a subject.
type AuthzResponse struct {
	Subject      string `json:"subject"`
	AuthzVersion int64  `json:"authz_version"`
	Entitled     bool   `json:"entitled"`
	Raw          json.RawMessage
}

// GetAuthz fetches the current authorization record for a subject (INT-102).
func (c *Client) GetAuthz(ctx context.Context, subject, tenantID string) (AuthzResponse, error) {
	query := url.Values{}
	query.Set("subject", subject)
	if tenantID != "" {
		query.Set("tenant", tenantID)
	}
	var out AuthzResponse
	if err := c.do(ctx, http.MethodGet, "/integration/v1/internal/authz?"+query.Encode(), nil, &out); err != nil {
		return AuthzResponse{}, err
	}
	return out, nil
}

// SkillPackage is one INT-142 enterprise skill download: the package bytes
// exactly as the platform served them plus the digest the platform attests
// in the X-SHA256 response header. Callers recompute the byte digest before
// trusting either value.
type SkillPackage struct {
	Body         []byte
	SHA256Header string
}

// DownloadSkill fetches the enterprise skill package pinned to publishID and
// sha256 (INT-142). The sha256 pin travels as a query parameter so a
// platform that no longer serves that exact revision answers 4xx instead of
// silently returning the current package; the caller validates the returned
// bytes against both the requested pin and the attested header before
// caching anything.
func (c *Client) DownloadSkill(ctx context.Context, publishID, sha256 string) (SkillPackage, error) {
	if strings.TrimSpace(publishID) == "" || strings.TrimSpace(sha256) == "" {
		return SkillPackage{}, errors.New("platform skill download requires publish_id and sha256")
	}
	path := "/integration/v1/skills/" + url.PathEscape(publishID) + "/download?sha256=" + url.QueryEscape(sha256)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+path, nil)
	if err != nil {
		return SkillPackage{}, err
	}
	req.Header.Set("Authorization", "Bearer "+c.serviceToken)
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return SkillPackage{}, fmt.Errorf("platform request: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		payload, readErr := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		apiErr := &APIError{StatusCode: resp.StatusCode, Message: strings.TrimSpace(string(payload))}
		if readErr != nil {
			apiErr.Message = readErr.Error()
		}
		var coded struct {
			Code    string `json:"code"`
			Message string `json:"message"`
			Error   string `json:"error"`
		}
		if json.Unmarshal(payload, &coded) == nil {
			apiErr.Code = coded.Code
			if coded.Message != "" {
				apiErr.Message = coded.Message
			} else {
				apiErr.Message = coded.Error
			}
		}
		return SkillPackage{}, apiErr
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxSkillPackageBytes+1))
	if err != nil {
		return SkillPackage{}, fmt.Errorf("platform response read: %w", err)
	}
	if len(body) > maxSkillPackageBytes {
		return SkillPackage{}, fmt.Errorf("platform skill package exceeds %d bytes", maxSkillPackageBytes)
	}
	return SkillPackage{Body: body, SHA256Header: strings.TrimSpace(resp.Header.Get("X-SHA256"))}, nil
}

func (c *Client) do(ctx context.Context, method, path string, body []byte, out any) error {
	return c.doAuth(ctx, method, path, body, out, true)
}

// doNoAuth is for platform endpoints that are public by contract (INT-101a
// authorize): there is no caller credential at login-begin time, and sending
// this server's service token there is unnecessary.
func (c *Client) doNoAuth(ctx context.Context, method, path string, body []byte, out any) error {
	return c.doAuth(ctx, method, path, body, out, false)
}

func (c *Client) doAuth(ctx context.Context, method, path string, body []byte, out any, withServiceToken bool) error {
	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, bytes.NewReader(body))
	if err != nil {
		return err
	}
	if withServiceToken {
		req.Header.Set("Authorization", "Bearer "+c.serviceToken)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("platform request: %w", err)
	}
	defer resp.Body.Close()
	payload, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return fmt.Errorf("platform response read: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		apiErr := &APIError{StatusCode: resp.StatusCode, Message: strings.TrimSpace(string(payload))}
		var coded struct {
			Code    string `json:"code"`
			Message string `json:"message"`
			Error   string `json:"error"`
		}
		if json.Unmarshal(payload, &coded) == nil {
			apiErr.Code = coded.Code
			if coded.Message != "" {
				apiErr.Message = coded.Message
			} else {
				apiErr.Message = coded.Error
			}
		}
		return apiErr
	}
	if out == nil || len(bytes.TrimSpace(payload)) == 0 {
		return nil
	}
	if err := json.Unmarshal(payload, out); err != nil {
		return fmt.Errorf("platform response decode: %w", err)
	}
	return nil
}

// LeaseClaims are the platform-signed assertions a daemon must present when
// claiming an enterprise task. task_id and runtime_id bind the lease to
// exactly one claim target; subject ties it back to the enterprise identity.
type LeaseClaims struct {
	Subject   string `json:"sub"`
	TenantID  string `json:"tenant_id"`
	TaskID    string `json:"task_id"`
	RuntimeID string `json:"runtime_id"`
	GrantID   string `json:"grant_id"`
	ExpiresAt time.Time
	Raw       jwt.MapClaims
}

// ParseLease verifies an X-Enterprise-Lease JWT (HS256 with the configured
// platform lease key) and validates its expiry. Caller must still compare
// TaskID/RuntimeID against the concrete claim target and re-check the
// subject's authorization — locally or via GetAuthz — before dispatching.
func (c *Client) ParseLease(tokenString string) (LeaseClaims, error) {
	if len(c.leaseHMACSecret) == 0 {
		return LeaseClaims{}, errors.New("platform lease key not configured")
	}
	token, err := jwt.Parse(tokenString, func(t *jwt.Token) (any, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, jwt.ErrSignatureInvalid
		}
		return c.leaseHMACSecret, nil
	})
	if err != nil || !token.Valid {
		return LeaseClaims{}, fmt.Errorf("invalid enterprise lease: %w", err)
	}
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return LeaseClaims{}, errors.New("invalid enterprise lease claims")
	}
	exp, err := claims.GetExpirationTime()
	if err != nil || exp == nil {
		return LeaseClaims{}, errors.New("enterprise lease missing expiry")
	}
	out := LeaseClaims{
		Subject:   strings.TrimSpace(claimsString(claims, "sub")),
		TenantID:  strings.TrimSpace(claimsString(claims, "tenant_id")),
		TaskID:    strings.TrimSpace(claimsString(claims, "task_id")),
		RuntimeID: strings.TrimSpace(claimsString(claims, "runtime_id")),
		GrantID:   strings.TrimSpace(claimsString(claims, "grant_id")),
		ExpiresAt: exp.Time,
		Raw:       claims,
	}
	if out.Subject == "" || out.TaskID == "" || out.RuntimeID == "" {
		return LeaseClaims{}, errors.New("enterprise lease missing subject/task/runtime binding")
	}
	return out, nil
}

func claimsString(claims jwt.MapClaims, key string) string {
	v, _ := claims[key].(string)
	return v
}
