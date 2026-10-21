package middleware

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/multica-ai/multica/server/internal/auth"
	"github.com/multica-ai/multica/server/internal/util"
	db "github.com/multica-ai/multica/server/pkg/db/generated"
	"github.com/redis/go-redis/v9"
)

// Enterprise entitlement codes surfaced to clients.
const (
	// EnterpriseRevokedCode answers any enterprise-gated request whose
	// session epoch or PAT subject snapshot no longer matches the user's
	// current enterprise identity.
	EnterpriseRevokedCode = "ENTITLEMENT_REVOKED"
)

// Server-set request headers carrying the enterprise identity snapshot of
// the credential that authenticated the request. Auth/DaemonAuth stamp them
// from signed JWT claims or the PAT row; clients cannot set them because
// both middlewares strip client-supplied values before authenticating.
const (
	enterpriseSubjectHeader = "X-Enterprise-Subject"
	enterpriseSessionHeader = "X-Enterprise-Session"
	enterpriseVersionHeader = "X-Enterprise-Version"
)

// stripEnterpriseHeaders drops client-supplied enterprise identity headers.
// Callers stamp authoritative values only after authenticating the token.
func stripEnterpriseHeaders(r *http.Request) {
	r.Header.Del(enterpriseSubjectHeader)
	r.Header.Del(enterpriseSessionHeader)
	r.Header.Del(enterpriseVersionHeader)
}

// stampEnterpriseFromClaims copies the enterprise session epoch out of
// signed JWT claims onto the request headers. No-op for personal sessions:
// a missing ent_sid claim means the connection is not enterprise-managed.
// The platform subject is deliberately not copied: session JWTs are checked
// by (ent_sid, ent_ver) against the database, and the subject reaches the
// headers only through the PAT snapshot path below.
func stampEnterpriseFromClaims(r *http.Request, claims map[string]any) {
	sid, _ := claims[auth.EnterpriseSessionClaim].(string)
	if sid == "" {
		return
	}
	r.Header.Set(enterpriseSessionHeader, sid)
	if ver, ok := claims[auth.EnterpriseVersionClaim].(float64); ok {
		r.Header.Set(enterpriseVersionHeader, strconv.FormatInt(int64(ver), 10))
	}
}

// stampEnterpriseSubject marks the request as carrying an enterprise PAT:
// the subject snapshot comes from the personal_access_token row (or the PAT
// cache entry that mirrored it), never from the client.
func stampEnterpriseSubject(r *http.Request, subject string) {
	if subject != "" {
		r.Header.Set(enterpriseSubjectHeader, subject)
	}
}

// stampEnterpriseVersion carries the PAT's authorization-version snapshot so
// the epoch middleware can reject enterprise PATs minted before a revocation.
func stampEnterpriseVersion(r *http.Request, version string) {
	if version != "" {
		r.Header.Set(enterpriseVersionHeader, version)
	}
}

// EnterpriseVersionTTL bounds how long an authorization-version lookup may
// be cached before the middleware re-reads the user row. Deleting the cache
// key (InvalidateEnterpriseVersion) is the push-channel invalidation path.
const EnterpriseVersionTTL = 30 * time.Second

const enterpriseVersionKeyPrefix = "ent:ver:"

func enterpriseVersionKey(userID string) string { return enterpriseVersionKeyPrefix + userID }

// EnterpriseIdentity is the point-in-time enterprise binding of a local
// user. Enterprise=false (NULL subject) must never be read as unlimited
// enterprise access — it means the user is not enterprise-managed at all.
type EnterpriseIdentity struct {
	Subject    string `json:"subject,omitempty"`
	SessionID  string `json:"session_id,omitempty"`
	Version    int64  `json:"version"`
	Enterprise bool   `json:"enterprise"`
}

// EnterpriseAuthzRefresher re-anchors a user's enterprise identity from the
// platform's authorization API on cache miss/expiry, persisting the fresh
// authorization version so revocations propagate into code without waiting
// for the next exchange. It must return an error when the platform is
// unreachable so enterprise-gated writes fail closed (BND-112).
type EnterpriseAuthzRefresher func(ctx context.Context, queries *db.Queries, userID string, current EnterpriseIdentity) (EnterpriseIdentity, error)

// EnterpriseVersionCache resolves users' enterprise identities with a short
// Redis cache in front of Postgres. A nil *EnterpriseVersionCache is safe:
// Current degrades to a direct database read on every call.
type EnterpriseVersionCache struct {
	rdb redis.UniversalClient
}

// NewEnterpriseVersionCache returns a cache backed by rdb. Pass nil to
// disable caching; the returned value stays usable and reads the database
// directly.
func NewEnterpriseVersionCache(rdb redis.UniversalClient) *EnterpriseVersionCache {
	if rdb == nil {
		return nil
	}
	return &EnterpriseVersionCache{rdb: rdb}
}

// InvalidateEnterpriseVersion drops the cached identity for userID so the
// next check re-reads Postgres. This is the hook the platform push channel
// calls when the authorization version moves or an entitlement is revoked.
func (c *EnterpriseVersionCache) InvalidateEnterpriseVersion(ctx context.Context, userID string) {
	if c == nil {
		return
	}
	if err := c.rdb.Del(ctx, enterpriseVersionKey(userID)).Err(); err != nil {
		slog.Warn("enterprise_version: invalidate failed; entry will expire on TTL", "error", err)
	}
}

// Current resolves the user's enterprise identity. Cache hits answer inside
// the TTL window; misses and Redis failures fall through to Postgres — a
// dead cache must never bypass the check, only make it more expensive.
func (c *EnterpriseVersionCache) Current(ctx context.Context, queries *db.Queries, userID string) (EnterpriseIdentity, error) {
	id, _, err := c.currentWithSource(ctx, queries, userID)
	return id, err
}

// currentWithSource additionally reports whether the identity came from the
// short-lived cache (fromCache=true) or was freshly read from Postgres. The
// middleware re-anchors from the platform only on fresh reads so the 30s
// TTL actually bounds lookup cost.
func (c *EnterpriseVersionCache) currentWithSource(ctx context.Context, queries *db.Queries, userID string) (EnterpriseIdentity, bool, error) {
	if c != nil {
		if raw, err := c.rdb.Get(ctx, enterpriseVersionKey(userID)).Result(); err == nil {
			var id EnterpriseIdentity
			if json.Unmarshal([]byte(raw), &id) == nil {
				return id, true, nil
			}
		} else if !errors.Is(err, redis.Nil) {
			slog.Warn("enterprise_version: get failed; falling back to DB", "error", err)
		}
	}
	if queries == nil {
		return EnterpriseIdentity{}, false, errors.New("enterprise version check unavailable")
	}
	userUUID, err := util.ParseUUID(userID)
	if err != nil {
		return EnterpriseIdentity{}, false, err
	}
	user, err := queries.GetUser(ctx, userUUID)
	if err != nil {
		return EnterpriseIdentity{}, false, err
	}
	id := EnterpriseIdentity{
		Subject:    user.EnterpriseSubject.String,
		SessionID:  user.EnterpriseSessionID.String,
		Enterprise: user.EnterpriseSubject.Valid,
	}
	if user.EnterpriseAuthzVersion.Valid {
		id.Version = user.EnterpriseAuthzVersion.Int64
	}
	if c != nil {
		if payload, err := json.Marshal(id); err == nil {
			if err := c.rdb.Set(ctx, enterpriseVersionKey(userID), payload, EnterpriseVersionTTL).Err(); err != nil {
				slog.Warn("enterprise_version: set failed", "error", err)
			}
		}
	}
	return id, false, nil
}

// EnterpriseVersion enforces the enterprise session epoch on the route
// groups that mutate enterprise workspaces and on the daemon enterprise
// task endpoints. It only acts when Auth (or DaemonAuth) stamped enterprise
// headers — personal requests pass through untouched — and fails closed:
// any resolution error or identity drift is a 401 ENTITLEMENT_REVOKED, so a
// platform revocation takes effect within at most EnterpriseVersionTTL
// (instantly when the push channel calls InvalidateEnterpriseVersion).
//
// Two credential shapes are checked:
//   - Enterprise session JWTs: the token's ent_sid/ent_ver must equal the
//     user row's current enterprise_session_id / enterprise_authz_version.
//   - Enterprise PATs: the subject snapshot taken at issuance must still
//     equal the user's current enterprise_subject. The 10-minute PAT cache
//     semantics are untouched for authentication; this check layers on top
//     and reads through the much shorter EnterpriseVersionTTL cache.
func EnterpriseVersion(cache *EnterpriseVersionCache, queries *db.Queries, refresher ...EnterpriseAuthzRefresher) func(http.Handler) http.Handler {
	var refresh EnterpriseAuthzRefresher
	if len(refresher) > 0 {
		refresh = refresher[0]
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			session := r.Header.Get(enterpriseSessionHeader)
			subject := r.Header.Get(enterpriseSubjectHeader)
			if session == "" && subject == "" {
				next.ServeHTTP(w, r)
				return
			}
			userID := r.Header.Get("X-User-ID")
			if userID == "" {
				writeEnterpriseRevoked(w)
				return
			}
			current, fromCache, err := cache.currentWithSource(r.Context(), queries, userID)
			if err != nil {
				slog.Warn("enterprise_version: identity resolution failed", "user_id", userID, "error", err)
				writeEnterpriseRevoked(w)
				return
			}
			if refresh != nil && current.Enterprise && !fromCache {
				fresh, ferr := refresh(r.Context(), queries, userID, current)
				if ferr != nil {
					// Platform unreachable or refused: fail closed so a
					// revocation can never be hidden by a stale local row.
					slog.Warn("enterprise_version: platform re-anchor failed", "user_id", userID, "error", ferr)
					writeEnterpriseRevoked(w)
					return
				}
				current = fresh
			}
			switch {
			case session != "":
				// Enterprise session token: the whole epoch (session id +
				// authorization version) must match the database.
				ver, err := strconv.ParseInt(r.Header.Get(enterpriseVersionHeader), 10, 64)
				if err != nil || !current.Enterprise || current.SessionID != session || current.Version != ver {
					writeEnterpriseRevoked(w)
					return
				}
			default:
				// Enterprise PAT: the issuance-time subject snapshot must
				// still be the user's live platform subject, and a PAT
				// carrying an authorization-version snapshot must still
				// match the user's current version (empty snapshot = PAT
				// minted before this check existed; subject-only compare).
				if !current.Enterprise || current.Subject != subject {
					writeEnterpriseRevoked(w)
					return
				}
				if patVer := r.Header.Get(enterpriseVersionHeader); patVer != "" {
					ver, err := strconv.ParseInt(patVer, 10, 64)
					if err != nil || current.Version != ver {
						writeEnterpriseRevoked(w)
						return
					}
				}
			}
			next.ServeHTTP(w, r)
		})
	}
}

func writeEnterpriseRevoked(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusUnauthorized)
	_, _ = w.Write([]byte(`{"error":"enterprise entitlement revoked","code":"` + EnterpriseRevokedCode + `"}` + "\n"))
}
