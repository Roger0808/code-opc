package handler

import (
	"crypto/subtle"
	"encoding/json"
	"net/http"
	"strings"

	"github.com/multica-ai/multica/server/internal/middleware"
	"github.com/multica-ai/multica/server/internal/util"
	db "github.com/multica-ai/multica/server/pkg/db/generated"
	"github.com/jackc/pgx/v5/pgtype"
)

// EnterpriseInvalidate handles POST /api/internal/enterprise/invalidate: the
// platform's revocation notifier pushes authorization-version bumps here
// (BND-110 push path). The request is authenticated with the shared service
// token (constant-time compare), never a user credential.
//
// Body: {"user_id": "<uuid>"} or {"enterprise_subject": "<subject>"} plus
// {"version": n}. Effects: persist the new authorization version, drop the
// 30s version cache entry, and close the user's enterprise-managed WebSocket
// connections (enterprise_revoked frame first, so clients tear the session
// down and land on re-login). Any failure leaves the state more restrictive,
// never less.
func (h *Handler) EnterpriseInvalidate(w http.ResponseWriter, r *http.Request) {
	token := strings.TrimSpace(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "))
	if h.PlatformServiceToken == "" ||
		subtle.ConstantTimeCompare([]byte(token), []byte(h.PlatformServiceToken)) != 1 {
		writeErrorCode(w, http.StatusUnauthorized, middleware.EnterpriseRevokedCode, "invalid service token")
		return
	}

	var req struct {
		UserID     string `json:"user_id"`
		Subject    string `json:"enterprise_subject"`
		Version    int64  `json:"version"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid body")
		return
	}
	if strings.TrimSpace(req.UserID) == "" && strings.TrimSpace(req.Subject) == "" {
		writeError(w, http.StatusBadRequest, "user_id or enterprise_subject is required")
		return
	}

	userID := strings.TrimSpace(req.UserID)
	if userID == "" {
		user, err := h.Queries.GetUserByEnterpriseSubject(r.Context(), pgtype.Text{String: strings.TrimSpace(req.Subject), Valid: true})
		if err != nil {
			// Unknown subject: nothing local to invalidate — still idempotent 200.
			writeJSON(w, http.StatusOK, map[string]any{"applied": false, "reason": "unknown_subject"})
			return
		}
		userID = user.ID.String()
	}

	if req.Version > 0 {
		userUUID, err := util.ParseUUID(userID)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid user_id")
			return
		}
		// Monotonic guard in the query: a replayed or stale invalidate frame
		// carrying an older version is acknowledged but never rolls the row
		// back (rows affected = 0).
		if _, err := h.Queries.UpdateUserEnterpriseAuthzVersion(r.Context(), db.UpdateUserEnterpriseAuthzVersionParams{
			ID:                     userUUID,
			EnterpriseAuthzVersion: pgtype.Int8{Int64: req.Version, Valid: true},
		}); err != nil {
			writeError(w, http.StatusInternalServerError, "failed to persist authorization version")
			return
		}
	}
	if h.EnterpriseVersionCache != nil {
		h.EnterpriseVersionCache.InvalidateEnterpriseVersion(r.Context(), userID)
	}
	if h.Hub != nil {
		// Close the user's enterprise-managed connections, delivering the
		// enterprise_revoked frame first so the client tears the session down
		// and lands on re-login. Personal connections stay up.
		h.Hub.CloseEnterpriseUserConnections(userID)
	}
	writeJSON(w, http.StatusOK, map[string]any{"applied": true})
}
