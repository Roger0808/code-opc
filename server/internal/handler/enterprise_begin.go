package handler

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strings"

	"github.com/multica-ai/multica/server/internal/platform"
)

// Enterprise login begin proxy (OPC platform integration, INT-101a).
//
// The desktop renderer must not build the platform authorize URL itself: the
// platform contract is POST /integration/v1/auth/authorize, not a GET with
// query parameters. This endpoint takes the renderer's one-time flow
// parameters, forwards them to the platform under the pre-registered
// code-desktop client id, and hands the authorize URL back. The loopback
// redirect_uri restriction mirrors the platform rule — only
// http://127.0.0.1:<port>/callback is accepted — so a compromised renderer
// cannot redirect the enterprise login at an attacker-controlled host.
//
// The login flow is pre-session by definition, so this endpoint is registered
// OUTSIDE middleware.Auth and is rate-limited per client IP (5/min, like
// /auth/send-code). There is no actor to gate on at this point in the flow;
// the loopback redirect_uri restriction below is what keeps a compromised
// renderer from redirecting the enterprise login at an attacker-controlled
// host.

// enterpriseClientID is the pre-registered INT-101a client id of the code
// desktop app.
const enterpriseClientID = "code-desktop"

// EnterpriseBeginRequest is the body of POST /api/enterprise/begin.
type EnterpriseBeginRequest struct {
	State         string `json:"state"`
	CodeChallenge string `json:"code_challenge"`
	RedirectURI   string `json:"redirect_uri"`
}

// EnterpriseBeginResponse carries the platform login transaction the desktop
// must open in the system browser.
type EnterpriseBeginResponse struct {
	LoginTxnID   string `json:"login_txn_id"`
	AuthorizeURL string `json:"authorize_url"`
}

// EnterpriseBegin implements POST /api/enterprise/begin (INT-101a proxy).
// Registered outside middleware.Auth (pre-session) and rate-limited; see
// cmd/server/router.go.
func (h *Handler) EnterpriseBegin(w http.ResponseWriter, r *http.Request) {
	if h.Platform == nil {
		writeFeatureDisabled(w, "enterprise_not_configured", "enterprise integration is not configured")
		return
	}

	var req EnterpriseBeginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if strings.TrimSpace(req.State) == "" {
		writeError(w, http.StatusBadRequest, "state is required")
		return
	}
	if strings.TrimSpace(req.CodeChallenge) == "" {
		writeError(w, http.StatusBadRequest, "code_challenge is required")
		return
	}
	if !isEnterpriseLoopbackRedirectURI(req.RedirectURI) {
		writeErrorCode(w, http.StatusBadRequest, "enterprise_redirect_uri_not_allowed",
			"redirect_uri must be an http://127.0.0.1:<port>/callback loopback URL")
		return
	}

	out, err := h.Platform.Authorize(r.Context(), platform.AuthorizeRequest{
		ClientID:            enterpriseClientID,
		RedirectURI:         strings.TrimSpace(req.RedirectURI),
		State:               strings.TrimSpace(req.State),
		CodeChallenge:       strings.TrimSpace(req.CodeChallenge),
		CodeChallengeMethod: "S256",
	})
	if err != nil {
		h.writePlatformError(w, r, err)
		return
	}

	writeJSON(w, http.StatusOK, EnterpriseBeginResponse{
		LoginTxnID:   out.LoginTxnID,
		AuthorizeURL: out.AuthorizeURL,
	})
}

// isEnterpriseLoopbackRedirectURI reports whether raw is exactly an
// http://127.0.0.1:<port>/callback URL: loopback only, explicit port, the
// fixed callback path, and no query or fragment to smuggle a second target.
func isEnterpriseLoopbackRedirectURI(raw string) bool {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return false
	}
	if !strings.EqualFold(u.Scheme, "http") {
		return false
	}
	if u.Hostname() != "127.0.0.1" {
		return false
	}
	port := u.Port()
	if port == "" {
		return false
	}
	n := 0
	for _, c := range port {
		if c < '0' || c > '9' {
			return false
		}
		n = n*10 + int(c-'0')
	}
	if n < 1 || n > 65535 {
		return false
	}
	return u.Path == "/callback" && u.RawQuery == "" && u.Fragment == ""
}
