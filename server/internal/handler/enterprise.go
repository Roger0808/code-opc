package handler

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/multica-ai/multica/server/internal/auth"
	"github.com/multica-ai/multica/server/internal/logger"
	"github.com/multica-ai/multica/server/internal/middleware"
	"github.com/multica-ai/multica/server/internal/platform"
	"github.com/multica-ai/multica/server/internal/util"
	db "github.com/multica-ai/multica/server/pkg/db/generated"
)

// Enterprise exchange + session-epoch endpoints (OPC platform integration).
//
// The exchange turns a one-time desktop login token (aud=code-backend,
// 120s, single use — replay detection lives on the platform) into a local
// session whose JWT carries the enterprise session epoch: ent_sid identifies
// the enterprise login, ent_ver is the platform authorization version it
// started at. middleware.EnterpriseVersion enforces the epoch on every
// enterprise-gated request, and sliding renewal re-reads both values from
// the user row so a revoked authorization cannot ride a renewed session.

// EnterpriseExchangeRequest is the body of POST /api/enterprise/exchange.
// CodeVerifier is the desktop's PKCE verifier for the login transaction: the
// platform requires it on code-exchange and rejects an S256 mismatch with
// 400 AUTH_STATE_MISMATCH.
type EnterpriseExchangeRequest struct {
	ExchangeToken string `json:"exchange_token"`
	CodeVerifier  string `json:"code_verifier"`
}

// enterpriseLocalEmail builds the placeholder mailbox for a platform-managed
// identity. It is an internal handle, not a deliverable address.
func enterpriseLocalEmail(subject string) string {
	return fmt.Sprintf("enterprise-%s@platform.local", subject)
}

// enterpriseWorkspaceName picks the display name for a workspace mirrored
// from a platform space, preferring the tenant hint the platform attached.
func enterpriseWorkspaceName(space platform.Space, subject string) string {
	if space.Tenant != "" {
		return "enterprise-" + space.Tenant
	}
	if space.Name != "" {
		return space.Name
	}
	return "enterprise-" + space.ID
}

// enterpriseWorkspaceSlug derives a unique, deterministic-ish slug for a
// mirrored workspace. Platform ids are not guaranteed slug-safe, so anything
// outside [a-z0-9-] is folded to '-'; a collision suffix keeps the insert
// retryable instead of failing the whole exchange.
func enterpriseWorkspaceSlug(spaceID string) string {
	var b strings.Builder
	b.WriteString("ent-")
	lastDash := false
	for _, r := range strings.ToLower(spaceID) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
			lastDash = false
		default:
			if !lastDash {
				b.WriteByte('-')
				lastDash = true
			}
		}
	}
	slug := strings.Trim(b.String(), "-")
	if len(slug) > 48 {
		slug = slug[:48]
	}
	return slug
}

// EnterpriseExchange implements POST /api/enterprise/exchange (INT-101g).
// Registered outside middleware.Auth (pre-session) and rate-limited; see
// cmd/server/router.go.
func (h *Handler) EnterpriseExchange(w http.ResponseWriter, r *http.Request) {
	if h.Platform == nil {
		writeFeatureDisabled(w, "enterprise_not_configured", "enterprise integration is not configured")
		return
	}

	var req EnterpriseExchangeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if strings.TrimSpace(req.ExchangeToken) == "" {
		writeError(w, http.StatusBadRequest, "exchange_token is required")
		return
	}
	if strings.TrimSpace(req.CodeVerifier) == "" {
		writeError(w, http.StatusBadRequest, "code_verifier is required")
		return
	}

	ident, err := h.Platform.CodeExchange(r.Context(), strings.TrimSpace(req.ExchangeToken), strings.TrimSpace(req.CodeVerifier))
	if err != nil {
		h.writePlatformError(w, r, err)
		return
	}

	user, err := h.upsertEnterpriseUser(r.Context(), ident)
	if err != nil {
		slog.Warn("enterprise exchange: user upsert failed", append(logger.RequestAttrs(r), "error", err)...)
		writeError(w, http.StatusInternalServerError, "failed to provision enterprise user")
		return
	}

	if err := h.syncEnterpriseWorkspaceLinks(r.Context(), user, ident); err != nil {
		slog.Warn("enterprise exchange: workspace link sync failed", append(logger.RequestAttrs(r), "error", err)...)
		writeError(w, http.StatusInternalServerError, "failed to provision enterprise workspace")
		return
	}

	tokenString, err := h.issueJWTWithEnterprise(user, user.EnterpriseSessionID.String, user.EnterpriseAuthzVersion.Int64)
	if err != nil {
		slog.Warn("enterprise exchange: token issuance failed", append(logger.RequestAttrs(r), "error", err)...)
		writeError(w, http.StatusInternalServerError, "failed to generate token")
		return
	}

	slog.Info("enterprise exchange completed",
		append(logger.RequestAttrs(r), "user_id", uuidToString(user.ID), "subject", ident.Subject)...)
	writeJSON(w, http.StatusOK, LoginResponse{
		Token: tokenString,
		User:  h.userToResponse(user),
	})
}

// writePlatformError maps a platform client failure onto the HTTP response.
// Platform 4xx responses (replay, expired or unknown exchange token) keep
// the platform's machine-readable code so the desktop client can render the
// right recovery; transport and 5xx failures are ours to report.
func (h *Handler) writePlatformError(w http.ResponseWriter, r *http.Request, err error) {
	var apiErr *platform.APIError
	if errors.As(err, &apiErr) && apiErr.StatusCode >= 400 && apiErr.StatusCode < 500 {
		if apiErr.Code != "" {
			writeErrorCode(w, apiErr.StatusCode, apiErr.Code, apiErr.Message)
			return
		}
		writeError(w, apiErr.StatusCode, apiErr.Message)
		return
	}
	slog.Warn("enterprise platform call failed", "error", err)
	writeError(w, http.StatusBadGateway, "failed to reach identity platform")
}

// upsertEnterpriseUser finds or creates the local user for a platform
// identity and re-anchors its session epoch: a fresh enterprise session id
// per exchange plus the authorization version the platform just reported.
// Finding the user by the unique enterprise_subject keeps re-exchange
// idempotent — no duplicate placeholder accounts.
func (h *Handler) upsertEnterpriseUser(ctx context.Context, ident platform.CodeExchangeResponse) (db.User, error) {
	sessionID, err := auth.NewSessionID()
	if err != nil {
		return db.User{}, err
	}
	linkID := ident.IdentityLinkID
	if linkID == "" {
		linkID = ident.KnowledgeUserID
	}
	if existing, err := h.Queries.GetUserByEnterpriseSubject(ctx, pgtype.Text{String: ident.Subject, Valid: true}); err == nil {
		return h.Queries.UpdateUserEnterpriseIdentity(ctx, db.UpdateUserEnterpriseIdentityParams{
			ID:                       existing.ID,
			EnterpriseSubject:        pgtype.Text{String: ident.Subject, Valid: true},
			EnterpriseIdentityLinkID: pgtype.Text{String: linkID, Valid: linkID != ""},
			EnterpriseAuthzVersion:   pgtype.Int8{Int64: ident.AuthzVersion, Valid: true},
			EnterpriseSessionID:      pgtype.Text{String: sessionID, Valid: true},
		})
	} else if !isNotFound(err) {
		return db.User{}, err
	}

	// New identity: placeholder email names the origin; the unique subject
	// index is what subsequent exchanges key on.
	user, err := h.Queries.CreateEnterpriseUser(ctx, db.CreateEnterpriseUserParams{
		Name:                     "enterprise-" + ident.Subject,
		Email:                    enterpriseLocalEmail(ident.Subject),
		EnterpriseSubject:        pgtype.Text{String: ident.Subject, Valid: true},
		EnterpriseIdentityLinkID: pgtype.Text{String: linkID, Valid: linkID != ""},
		EnterpriseAuthzVersion:   pgtype.Int8{Int64: ident.AuthzVersion, Valid: true},
		EnterpriseSessionID:      pgtype.Text{String: sessionID, Valid: true},
	})
	if err == nil {
		return user, nil
	}
	// The placeholder email can collide only if a row was created concurrently
	// for the same subject; re-read by subject and refresh it instead.
	if !isUniqueViolation(err) {
		return db.User{}, err
	}
	existing, err := h.Queries.GetUserByEnterpriseSubject(ctx, pgtype.Text{String: ident.Subject, Valid: true})
	if err != nil {
		return db.User{}, err
	}
	return h.Queries.UpdateUserEnterpriseIdentity(ctx, db.UpdateUserEnterpriseIdentityParams{
		ID:                       existing.ID,
		EnterpriseSubject:        pgtype.Text{String: ident.Subject, Valid: true},
		EnterpriseIdentityLinkID: pgtype.Text{String: linkID, Valid: linkID != ""},
		EnterpriseAuthzVersion:   pgtype.Int8{Int64: ident.AuthzVersion, Valid: true},
		EnterpriseSessionID:      pgtype.Text{String: sessionID, Valid: true},
	})
}

// syncEnterpriseWorkspaceLinks mirrors the platform space list into local
// workspaces. An existing (user, platform workspace) link keeps its local
// workspace; a new one creates an enterprise-<tenant> workspace and links
// it. Individual failures are logged and skipped — a single bad space must
// not fail the login — but the caller still reports an error when nothing
// could be synced at all, because a session with no reachable workspace is
// useless to the desktop client.
func (h *Handler) syncEnterpriseWorkspaceLinks(ctx context.Context, user db.User, ident platform.CodeExchangeResponse) error {
	synced := 0
	var lastErr error
	for _, space := range ident.Spaces {
		if strings.TrimSpace(space.ID) == "" {
			continue
		}
		if err := h.ensureEnterpriseWorkspaceLink(ctx, user, ident.Subject, space); err != nil {
			slog.Warn("enterprise exchange: space sync failed",
				"subject", ident.Subject, "space_id", space.ID, "error", err)
			lastErr = err
			continue
		}
		synced++
	}
	if synced == 0 && len(ident.Spaces) > 0 && lastErr != nil {
		return lastErr
	}
	return nil
}

// enterpriseMemberRole maps the platform space role onto the local workspace
// member role. Viewers and contributors are ordinary members; admin and owner
// keep their elevated role. An absent or unrecognized value mirrors as
// member: the mirror never widens a role the platform did not grant.
func enterpriseMemberRole(platformRole string) string {
	switch strings.ToLower(strings.TrimSpace(platformRole)) {
	case "admin":
		return "admin"
	case "owner":
		return "owner"
	default:
		return "member"
	}
}

// ensureEnterpriseWorkspaceLink binds one platform space to a local
// workspace, creating the workspace on first sight. Workspace + member +
// link are written in one transaction: a half-created enterprise workspace
// (created but unlinkable) would strand the desktop client on the next
// claim. No foreign keys by repository rule, so the member row references
// the workspace by plain UUID and cleanup is application-level.
//
// An existing link still re-mirrors the member role from the platform's
// current space role, so a promotion/demotion on the platform side lands on
// the next login instead of being frozen at first exchange.
func (h *Handler) ensureEnterpriseWorkspaceLink(ctx context.Context, user db.User, subject string, space platform.Space) error {
	memberRole := enterpriseMemberRole(space.Role)
	link, err := h.Queries.GetEnterpriseWorkspaceLinkByUserAndPlatform(ctx, db.GetEnterpriseWorkspaceLinkByUserAndPlatformParams{
		UserID:              user.ID,
		PlatformWorkspaceID: space.ID,
	})
	if err == nil {
		// Already linked: reconcile the mirrored role if it drifted.
		member, err := h.Queries.GetMemberByUserAndWorkspace(ctx, db.GetMemberByUserAndWorkspaceParams{
			UserID:      user.ID,
			WorkspaceID: link.WorkspaceID,
		})
		if err != nil {
			return err
		}
		if member.Role != memberRole {
			if _, err := h.Queries.UpdateMemberRole(ctx, db.UpdateMemberRoleParams{ID: member.ID, Role: memberRole}); err != nil {
				return err
			}
		}
		return nil
	} else if !isNotFound(err) {
		return err
	}

	tx, err := h.TxStarter.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	qtx := h.Queries.WithTx(tx)

	name := enterpriseWorkspaceName(space, subject)
	slug := enterpriseWorkspaceSlug(space.ID)
	var ws db.Workspace
	for attempt := 0; attempt < 5; attempt++ {
		candidate := slug
		if attempt > 0 {
			candidate = fmt.Sprintf("%s-%d", slug, attempt)
		}
		ws, err = qtx.CreateWorkspace(ctx, db.CreateWorkspaceParams{
			Name:        name,
			Slug:        candidate,
			Description: pgtype.Text{String: "Enterprise workspace mirrored from the identity platform", Valid: true},
			Context:     pgtype.Text{},
			IssuePrefix: defaultIssuePrefixFromSlug(candidate),
		})
		if err == nil {
			break
		}
		if !isUniqueViolation(err) {
			return err
		}
	}
	if err != nil {
		return err
	}

	if _, err := qtx.CreateMember(ctx, db.CreateMemberParams{
		WorkspaceID: ws.ID,
		UserID:      user.ID,
		Role:        memberRole,
	}); err != nil {
		return err
	}

	if _, err := qtx.UpsertEnterpriseWorkspaceLink(ctx, db.UpsertEnterpriseWorkspaceLinkParams{
		UserID:              user.ID,
		WorkspaceID:         ws.ID,
		PlatformWorkspaceID: space.ID,
		Source:              "enterprise_exchange",
		PlatformTenant:      space.Tenant,
	}); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// enterpriseRefresher re-reads the enterprise session epoch for RenewSession
// and the cookie renewal middleware. See auth.EnterpriseRefresher: returning
// ok=false drops the enterprise claims from the renewed token.
func (h *Handler) enterpriseRefresher() auth.EnterpriseRefresher {
	if h.Queries == nil {
		return nil
	}
	return func(userID string) (string, int64, bool) {
		userUUID, err := util.ParseUUID(userID)
		if err != nil {
			return "", 0, false
		}
		user, err := h.Queries.GetUser(context.Background(), userUUID)
		if err != nil || !user.EnterpriseSubject.Valid {
			return "", 0, false
		}
		return user.EnterpriseSessionID.String, user.EnterpriseAuthzVersion.Int64, true
	}
}

// enterpriseWorkspace reports whether the workspace is enterprise-managed.
// Presence of a link row is the marker: it is what makes daemon task claims
// require a platform lease and MCP resolution fail closed.
func (h *Handler) enterpriseWorkspace(ctx context.Context, workspaceID pgtype.UUID) bool {
	if h.Queries == nil {
		return false
	}
	_, err := h.Queries.GetEnterpriseWorkspaceLinkByWorkspace(ctx, workspaceID)
	return err == nil
}

// enterpriseInitiatorGate enforces the enterprise task-creation rule: in an
// enterprise workspace only a human actor holding a live enterprise identity
// may enqueue work. Machine credentials (task tokens, cloud PATs) and plain
// personal members get a refusal — enterprise runs must be attributable to
// an enterprise user the platform still recognizes.
func (h *Handler) enterpriseInitiatorGate(ctx context.Context, actorType, actorID string, workspaceID pgtype.UUID) error {
	if !h.enterpriseWorkspace(ctx, workspaceID) {
		return nil
	}
	if actorType != "member" {
		return errors.New("enterprise tasks require a human enterprise initiator")
	}
	userUUID, err := util.ParseUUID(actorID)
	if err != nil {
		return errors.New("enterprise tasks require a human enterprise initiator")
	}
	user, err := h.Queries.GetUser(ctx, userUUID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return errors.New("enterprise tasks require a human enterprise initiator")
		}
		return err
	}
	if !user.EnterpriseSubject.Valid {
		return errors.New("enterprise tasks require an enterprise-authenticated initiator")
	}
	return nil
}

// enterpriseInitiatorGateHTTP is the request-shaped wrapper used by HTTP
// handlers that can reject before any side effect.
func (h *Handler) enterpriseInitiatorGateHTTP(r *http.Request, actorType, actorID string, workspaceID pgtype.UUID) error {
	return h.enterpriseInitiatorGate(r.Context(), actorType, actorID, workspaceID)
}

// writeEnterpriseInitiatorRefusal answers a rejected enterprise initiator
// with the shared 403 code.
func writeEnterpriseInitiatorRefusal(w http.ResponseWriter) {
	writeErrorCode(w, http.StatusForbidden, "enterprise_initiator_required",
		"enterprise tasks require an enterprise-authenticated initiator")
}

// EnterpriseAuthzRefresher re-anchors a user's enterprise authorization
// version from the platform on version-cache miss (C-4): a platform
// revocation bumps the version there, and the middleware's ent_ver/PAT
// comparison fails on the very next uncached check. Platform errors fail
// closed in the middleware (401), so an unreachable platform can never hide
// a revocation behind a stale local row.
func (h *Handler) EnterpriseAuthzRefresher() middleware.EnterpriseAuthzRefresher {
	if h.Platform == nil || h.Queries == nil {
		return nil
	}
	return func(ctx context.Context, _ *db.Queries, userID string, current middleware.EnterpriseIdentity) (middleware.EnterpriseIdentity, error) {
		if current.Subject == "" {
			return current, errors.New("enterprise identity has no platform subject")
		}
		authz, err := h.Platform.GetAuthz(ctx, current.Subject, "")
		if err != nil {
			return current, err
		}
		version := authz.AuthzVersion
		if !authz.Entitled {
			// Entitlement gone: force a local bump so any outstanding ent_ver
			// stops matching even if the platform answered with an old value.
			version = current.Version + 1
		}
		if version > current.Version {
			userUUID, err := util.ParseUUID(userID)
			if err != nil {
				return current, err
			}
			// The update carries a monotonic guard, so a concurrent newer
			// write always wins; the refresher only ever moves the row forward.
			if _, err := h.Queries.UpdateUserEnterpriseAuthzVersion(ctx, db.UpdateUserEnterpriseAuthzVersionParams{
				ID:                     userUUID,
				EnterpriseAuthzVersion: pgtype.Int8{Int64: version, Valid: true},
			}); err != nil {
				return current, err
			}
			current.Version = version
		}
		// version <= current.Version: the local row is already at or ahead of
		// the platform's answer (a newer invalidate landed first) — keep it.
		return current, nil
	}
}
