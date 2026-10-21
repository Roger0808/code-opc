package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/golang-jwt/jwt/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/multica-ai/multica/server/internal/platform"
	db "github.com/multica-ai/multica/server/pkg/db/generated"
	"github.com/multica-ai/multica/server/pkg/protocol"
)

// Enterprise daemon-claim gate (OPC integration, TASK-C02).
//
// An enterprise task is any task whose runtime workspace carries an
// enterprise_workspace_link row: the workspace is mirrored from the identity
// platform, so dispatch is only allowed against a platform lease the SERVER
// mints at claim time (INT-102 POST /internal/grants, service token). The
// daemon never obtains a lease on its own: it declares the
// enterprise-protocol-v1 capability, claims, receives the lease in the
// claim response (enterprise_lease), and renews it through the server while
// the task runs (POST .../enterprise-lease/renew, which re-validates the
// X-Enterprise-Lease header before proxying the platform renewal).
//
// Personal tasks never pass through this gate — their claim behavior is
// byte-for-byte what it was before the integration.

// Enterprise claim refusal codes, returned in the 403 body `code` field so
// the daemon (or its operator) can tell a missing capability apart from a
// lease issuance failure.
const (
	enterpriseCodeProtocolRequired = "enterprise_protocol_required"
	// enterpriseCodeLeaseUnauthorized means the platform refused to mint the
	// grant (entitlement revoked / identity disabled) — retrying without a
	// platform-side change is pointless.
	enterpriseCodeLeaseUnauthorized = "enterprise_lease_unauthorized"
	// enterpriseCodeLeaseUnavailable means the platform could not be reached
	// or answered 5xx — the refusal is transient and the task is requeued.
	enterpriseCodeLeaseUnavailable = "enterprise_lease_unavailable"
	// enterpriseCodeLeaseRequired/Invalid/Mismatch answer a bad
	// X-Enterprise-Lease header on the renew path.
	enterpriseCodeLeaseRequired = "enterprise_lease_required"
	enterpriseCodeLeaseInvalid  = "enterprise_lease_invalid"
	enterpriseCodeLeaseMismatch = "enterprise_lease_mismatch"
)

// EnterpriseLease is the platform grant the server issues into the claim
// response (enterprise_lease). The daemon presents lease_token back as the
// X-Enterprise-Lease header when it renews; grant_id selects the platform
// grant row to renew.
type EnterpriseLease struct {
	GrantID        string `json:"grant_id"`
	LeaseToken     string `json:"lease_token"`
	LeaseExpiresAt string `json:"lease_expires_at"`
}

// enterpriseClaimFailure is a refusal to dispatch one enterprise task. The
// claim handler requeues the task before answering so the refusal never
// strands work.
type enterpriseClaimFailure struct {
	code    string
	message string
}

// enterpriseClaimCheckpoint gates the dispatch of an enterprise task. It
// returns nil for personal tasks. For enterprise tasks it verifies the daemon
// declared the enterprise protocol (registered metadata or this request's
// X-Client-Capabilities) and then MINTS the task's platform lease: the server
// calls POST /integration/v1/internal/grants with the service token, binding
// subject (the task originator's enterprise_subject), tenant, workspace,
// task, runtime and originating user. The issued lease travels back in the
// claim response; the daemon renews it for the life of the task.
func (h *Handler) enterpriseClaimCheckpoint(r *http.Request, task *db.AgentTaskQueue, runtime db.AgentRuntime) (*EnterpriseLease, *enterpriseClaimFailure) {
	if h.Queries == nil || !h.enterpriseWorkspace(r.Context(), runtime.WorkspaceID) {
		return nil, nil
	}

	// Old-daemon refusal: the enterprise protocol must be declared either at
	// register time (persisted in the runtime metadata) or on this claim
	// request (X-Client-Capabilities). A daemon that never declared it would
	// ignore managed_mcp_status and silently run enterprise tasks with local
	// MCP — exactly what BND-161 forbids.
	if !requestHasClientCapability(r, protocol.DaemonCapabilityEnterpriseProtocolV1) &&
		!runtimeHasCapability(runtime.Metadata, protocol.DaemonCapabilityEnterpriseProtocolV1) {
		return nil, &enterpriseClaimFailure{
			code:    enterpriseCodeProtocolRequired,
			message: "daemon does not declare the enterprise protocol capability",
		}
	}

	if h.Platform == nil {
		return nil, &enterpriseClaimFailure{
			code:    enterpriseCodeLeaseUnavailable,
			message: "enterprise integration is not configured",
		}
	}

	lease, failure := h.issueEnterpriseLease(r, task, runtime)
	if failure != nil {
		return nil, failure
	}
	return lease, nil
}

// issueEnterpriseLease mints the INT-102 grant for one claimed enterprise
// task. The grant subject is the task originator's live enterprise subject
// (falling back to the workspace-linking user when the task carries no
// attributable originator); the tenant and platform workspace come from the
// link row, never from daemon input.
func (h *Handler) issueEnterpriseLease(r *http.Request, task *db.AgentTaskQueue, runtime db.AgentRuntime) (*EnterpriseLease, *enterpriseClaimFailure) {
	link, err := h.Queries.GetEnterpriseWorkspaceLinkByWorkspace(r.Context(), runtime.WorkspaceID)
	if err != nil {
		slog.Warn("enterprise claim: workspace link unavailable",
			"task_id", uuidToString(task.ID), "error", err)
		return nil, &enterpriseClaimFailure{
			code:    enterpriseCodeLeaseUnauthorized,
			message: "enterprise workspace link unavailable",
		}
	}

	subject, originatingUserID, err := h.enterpriseLeaseSubject(r.Context(), task, link)
	if err != nil {
		slog.Warn("enterprise claim: no attributable enterprise originator",
			"task_id", uuidToString(task.ID), "error", err)
		return nil, &enterpriseClaimFailure{
			code:    enterpriseCodeLeaseUnauthorized,
			message: "enterprise task has no attributable enterprise originator",
		}
	}

	grant, err := h.Platform.CreateGrant(r.Context(), platform.GrantRequest{
		Subject:           subject,
		TenantID:          link.PlatformTenant,
		WorkspaceID:       link.PlatformWorkspaceID,
		TaskID:            uuidToString(task.ID),
		RuntimeID:         uuidToString(task.RuntimeID),
		OriginatingUserID: originatingUserID,
		Capabilities:      requestClientCapabilities(r),
	})
	if err != nil {
		if platform.IsCode(err, platform.CodeEntitlementRevoked) {
			return nil, &enterpriseClaimFailure{
				code:    enterpriseCodeLeaseUnauthorized,
				message: "platform refused the enterprise grant: entitlement revoked",
			}
		}
		slog.Warn("enterprise claim: grant issuance failed",
			"task_id", uuidToString(task.ID), "error", err)
		return nil, &enterpriseClaimFailure{
			code:    enterpriseCodeLeaseUnavailable,
			message: "platform grant issuance unavailable",
		}
	}
	if strings.TrimSpace(grant.LeaseToken) == "" || strings.TrimSpace(grant.GrantID) == "" {
		slog.Warn("enterprise claim: grant response missing lease material",
			"task_id", uuidToString(task.ID))
		return nil, &enterpriseClaimFailure{
			code:    enterpriseCodeLeaseUnavailable,
			message: "platform grant issuance unavailable",
		}
	}
	return &EnterpriseLease{
		GrantID:        grant.GrantID,
		LeaseToken:     grant.LeaseToken,
		LeaseExpiresAt: grant.LeaseExpiresAt,
	}, nil
}

// enterpriseLeaseSubject resolves the platform subject the grant is minted
// for: the task's originating user first (that is who the work is
// attributable to), then the workspace-linking user as the structural
// fallback. The winner must carry a live enterprise identity.
func (h *Handler) enterpriseLeaseSubject(ctx context.Context, task *db.AgentTaskQueue, link db.EnterpriseWorkspaceLink) (subject, originatingUserID string, err error) {
	candidates := make([]pgtype.UUID, 0, 3)
	if task.OriginatorUserID.Valid {
		candidates = append(candidates, task.OriginatorUserID)
	}
	if task.AccountableUserID.Valid {
		candidates = append(candidates, task.AccountableUserID)
	}
	candidates = append(candidates, link.UserID)
	for _, candidate := range candidates {
		user, uerr := h.Queries.GetUser(ctx, candidate)
		if uerr != nil {
			continue
		}
		if user.EnterpriseSubject.Valid && strings.TrimSpace(user.EnterpriseSubject.String) != "" {
			return user.EnterpriseSubject.String, uuidToString(user.ID), nil
		}
	}
	return "", "", errors.New("no enterprise-linked originator for task")
}

// enterpriseClaimRejectHTTP answers a refused per-runtime enterprise claim:
// 403 with the machine-readable refusal code in the body.
func writeEnterpriseClaimError(w http.ResponseWriter, failure *enterpriseClaimFailure) {
	writeErrorCode(w, http.StatusForbidden, failure.code, failure.message)
}

// Enterprise daemon-claim headers.
const (
	// enterpriseLeaseHeader carries the platform grant lease (JWT) the daemon
	// presents when renewing a task's lease. The server verifies the signature
	// with the same key the issuer signed with (PLATFORM_LEASE_HMAC_SECRET)
	// and checks the claims bind this exact task and runtime.
	enterpriseLeaseHeader = "X-Enterprise-Lease"
)

// validatePresentedLease verifies the X-Enterprise-Lease header a daemon
// presents on daemon→server enterprise calls (currently the renew endpoint):
// signature via the shared platform lease key, expiry, and the task/runtime
// binding in the claims.
func (h *Handler) validatePresentedLease(r *http.Request, taskID, runtimeID string) (platform.LeaseClaims, string, *enterpriseClaimFailure) {
	header := strings.TrimSpace(r.Header.Get(enterpriseLeaseHeader))
	if header == "" {
		return platform.LeaseClaims{}, "", &enterpriseClaimFailure{
			code:    enterpriseCodeLeaseRequired,
			message: "enterprise task requires a platform lease token",
		}
	}
	lease, err := h.Platform.ParseLease(header)
	if err != nil {
		code := enterpriseCodeLeaseInvalid
		if errors.Is(err, jwt.ErrTokenExpired) {
			code = platform.CodeLeaseExpired
		}
		return platform.LeaseClaims{}, "", &enterpriseClaimFailure{code: code, message: "invalid enterprise lease"}
	}
	if lease.TaskID != taskID || lease.RuntimeID != runtimeID {
		return platform.LeaseClaims{}, "", &enterpriseClaimFailure{
			code:    enterpriseCodeLeaseMismatch,
			message: "enterprise lease does not match the claimed task or runtime",
		}
	}
	return lease, header, nil
}

// RenewEnterpriseLease implements POST
// /api/daemon/runtimes/{runtimeId}/tasks/{taskId}/enterprise-lease/renew. The
// daemon renews its claim-issued lease for the life of the task (the
// platform lease TTL is 30s with a 15s renewal grace window). The presented
// X-Enterprise-Lease is validated (signature, expiry, task/runtime binding)
// before the server proxies the renewal to the platform with its service
// token; a platform refusal (entitlement revoked, lease expired, unknown
// grant) is surfaced verbatim so the daemon stops cloud calls for the task.
func (h *Handler) RenewEnterpriseLease(w http.ResponseWriter, r *http.Request) {
	runtimeID := chi.URLParam(r, "runtimeId")
	taskID := chi.URLParam(r, "taskId")

	runtime, ok := h.requireDaemonRuntimeAccess(w, r, runtimeID)
	if !ok {
		return
	}
	task, _, ok := h.requireDaemonTaskAccessWithWorkspace(w, r, taskID)
	if !ok {
		return
	}
	if uuidToString(task.RuntimeID) != uuidToString(runtime.ID) {
		writeError(w, http.StatusNotFound, "task not found")
		return
	}
	if !h.enterpriseWorkspace(r.Context(), runtime.WorkspaceID) {
		writeError(w, http.StatusBadRequest, "not an enterprise task")
		return
	}
	if h.Platform == nil {
		writeFeatureDisabled(w, "enterprise_not_configured", "enterprise integration is not configured")
		return
	}

	lease, _, failure := h.validatePresentedLease(r, taskID, runtimeID)
	if failure != nil {
		writeEnterpriseClaimError(w, failure)
		return
	}
	if strings.TrimSpace(lease.GrantID) == "" {
		writeErrorCode(w, http.StatusForbidden, enterpriseCodeLeaseInvalid, "enterprise lease carries no grant id")
		return
	}

	renewed, err := h.Platform.RenewGrant(r.Context(), lease.GrantID)
	if err != nil {
		var apiErr *platform.APIError
		switch {
		case platform.IsCode(err, platform.CodeEntitlementRevoked):
			writeErrorCode(w, http.StatusForbidden, platform.CodeEntitlementRevoked, "enterprise entitlement revoked")
		case platform.IsCode(err, platform.CodeLeaseExpired):
			writeErrorCode(w, http.StatusUnauthorized, platform.CodeLeaseExpired, "enterprise lease expired")
		case errors.As(err, &apiErr) && apiErr.StatusCode == http.StatusNotFound:
			writeErrorCode(w, http.StatusNotFound, "GRANT_NOT_FOUND", "enterprise grant not found")
		default:
			slog.Warn("enterprise lease renew failed", "task_id", taskID, "error", err)
			writeError(w, http.StatusBadGateway, "failed to reach identity platform")
		}
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"grant_id":         renewed.GrantID,
		"lease_token":      renewed.LeaseToken,
		"lease_expires_at": renewed.LeaseExpiresAt,
	})
}

// enterpriseManagedMCPOutcome applies the BND-161 failed-closed semantics to
// the resolved workspace MCP configuration of an enterprise task. Any
// resolution failure (read, parse, authorization, network) zeroes the
// managed set to the legal empty object {} and marks the response
// failed_closed — the daemon must NOT fall back to local MCP. A successful
// resolution is empty when the managed set is literally {}, and a null
// config is a failure too: only personal tasks may run unconfigured.
func enterpriseManagedMCPOutcome(mcpConfig json.RawMessage, failed bool) (json.RawMessage, string) {
	if failed {
		return json.RawMessage(`{}`), enterpriseMCPStatusFailedClosed
	}
	trimmed := bytes.TrimSpace(mcpConfig)
	if len(trimmed) == 0 || bytes.Equal(trimmed, []byte("null")) {
		return json.RawMessage(`{}`), enterpriseMCPStatusFailedClosed
	}
	if bytes.Equal(trimmed, []byte("{}")) {
		return mcpConfig, enterpriseMCPStatusEmpty
	}
	return mcpConfig, enterpriseMCPStatusOK
}

// enterpriseMCPStatus values stamped on enterprise claim responses.
const (
	enterpriseMCPStatusOK           = "ok"
	enterpriseMCPStatusEmpty        = "empty"
	enterpriseMCPStatusFailedClosed = "failed_closed"
)
