package middleware

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/multica-ai/multica/server/internal/util"
	db "github.com/multica-ai/multica/server/pkg/db/generated"
)

// enterpriseTestPool connects to DATABASE_URL when available; every test
// here skips without it, matching the other DB-backed suites.
func enterpriseTestPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		dbURL = "postgres://multica:multica@localhost:5432/multica?sslmode=disable"
	}
	pool, err := pgxpool.New(context.Background(), dbURL)
	if err != nil {
		t.Skipf("database not available: %v", err)
	}
	if err := pool.Ping(context.Background()); err != nil {
		pool.Close()
		t.Skipf("database not reachable: %v", err)
	}
	t.Cleanup(pool.Close)
	return pool
}

// seedEnterpriseUser inserts a user row and returns its id, cleaning up after
// the test.
func seedEnterpriseUser(t *testing.T, pool *pgxpool.Pool, enterprise bool) string {
	t.Helper()
	subject := ""
	if enterprise {
		subject = "sub-" + strings.ReplaceAll(t.Name(), "/", "-")
	}
	var id string
	if err := pool.QueryRow(context.Background(), `
		INSERT INTO "user" (name, email, enterprise_subject, enterprise_session_id, enterprise_authz_version)
		VALUES ($1, $2, NULLIF($3, ''), 'sess-1', 42)
		RETURNING id
	`, t.Name(), strings.ReplaceAll(t.Name(), "/", "-")+"-ent-test@multica.ai", subject).Scan(&id); err != nil {
		t.Fatalf("seed user: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM "user" WHERE id = $1`, id)
	})
	return id
}

func enterpriseNextHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
}

func TestEnterpriseVersionSkipsPersonalRequests(t *testing.T) {
	pool := enterpriseTestPool(t)
	queries := db.New(pool)
	cache := NewEnterpriseVersionCache(nil) // direct DB reads

	req := httptest.NewRequest(http.MethodPost, "/api/workspaces/x/issues", nil)
	req.Header.Set("X-User-ID", "anyone")
	rec := httptest.NewRecorder()
	EnterpriseVersion(cache, queries)(enterpriseNextHandler()).ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("personal request was blocked: %d", rec.Code)
	}
}

func TestEnterpriseVersionRejectsStaleSessionEpoch(t *testing.T) {
	pool := enterpriseTestPool(t)
	queries := db.New(pool)
	userID := seedEnterpriseUser(t, pool, true)

	cases := []struct {
		name    string
		session string
		version string
		want    int
	}{
		{name: "stale version", session: "sess-1", version: "1", want: http.StatusUnauthorized},
		{name: "stale session", session: "sess-old", version: "42", want: http.StatusUnauthorized},
		{name: "no version header", session: "sess-1", version: "", want: http.StatusUnauthorized},
		{name: "current epoch", session: "sess-1", version: "42", want: http.StatusNoContent},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cache := NewEnterpriseVersionCache(nil)
			req := httptest.NewRequest(http.MethodPost, "/api/workspaces/x/issues", nil)
			req.Header.Set("X-User-ID", userID)
			req.Header.Set(enterpriseSessionHeader, tc.session)
			if tc.version != "" {
				req.Header.Set(enterpriseVersionHeader, tc.version)
			}
			rec := httptest.NewRecorder()
			EnterpriseVersion(cache, queries)(enterpriseNextHandler()).ServeHTTP(rec, req)
			if rec.Code != tc.want {
				t.Fatalf("status = %d, want %d (body %s)", rec.Code, tc.want, rec.Body.String())
			}
			if tc.want == http.StatusUnauthorized {
				var body struct {
					Code string `json:"code"`
				}
				if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
					t.Fatalf("error body: %v", err)
				}
				if body.Code != EnterpriseRevokedCode {
					t.Fatalf("code = %q, want %q", body.Code, EnterpriseRevokedCode)
				}
			}
		})
	}
}

func TestEnterpriseVersionRejectsDriftedPATSubject(t *testing.T) {
	pool := enterpriseTestPool(t)
	queries := db.New(pool)
	userID := seedEnterpriseUser(t, pool, true)

	cache := NewEnterpriseVersionCache(nil)
	req := httptest.NewRequest(http.MethodPost, "/api/workspaces/x/issues", nil)
	req.Header.Set("X-User-ID", userID)
	req.Header.Set(enterpriseSubjectHeader, "sub-someone-else")
	rec := httptest.NewRecorder()
	EnterpriseVersion(cache, queries)(enterpriseNextHandler()).ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("drifted subject passed: %d", rec.Code)
	}

	// The snapshot taken at issuance still matches → allowed (PAT cache TTL
	// semantics stay the concern of the PAT branch, not this gate).
	req = httptest.NewRequest(http.MethodPost, "/api/workspaces/x/issues", nil)
	req.Header.Set("X-User-ID", userID)
	req.Header.Set(enterpriseSubjectHeader, "sub-"+strings.ReplaceAll(t.Name(), "/", "-"))
	rec = httptest.NewRecorder()
	EnterpriseVersion(cache, queries)(enterpriseNextHandler()).ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("matching subject blocked: %d (%s)", rec.Code, rec.Body.String())
	}
}

func TestEnterpriseVersionRejectsFormerEnterpriseUser(t *testing.T) {
	pool := enterpriseTestPool(t)
	queries := db.New(pool)
	// User once held a subject; the row has since been unlinked (NULL).
	userID := seedEnterpriseUser(t, pool, false)

	cache := NewEnterpriseVersionCache(nil)
	req := httptest.NewRequest(http.MethodPost, "/api/workspaces/x/issues", nil)
	req.Header.Set("X-User-ID", userID)
	req.Header.Set(enterpriseSessionHeader, "sess-1")
	req.Header.Set(enterpriseVersionHeader, "42")
	rec := httptest.NewRecorder()
	EnterpriseVersion(cache, queries)(enterpriseNextHandler()).ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("unlinked user passed the epoch check: %d", rec.Code)
	}
}

func TestEnterpriseVersionInvalidateForcesReRead(t *testing.T) {
	pool := enterpriseTestPool(t)
	queries := db.New(pool)
	userID := seedEnterpriseUser(t, pool, true)
	ctx := context.Background()

	// Without Redis the cache is DB-direct; assert the contract that matters:
	// a DB change is visible on the next check, and the invalidation call is
	// safe on a nil-backed cache.
	cache := NewEnterpriseVersionCache(nil)
	cache.InvalidateEnterpriseVersion(ctx, userID)

	if _, err := pool.Exec(ctx, `
		UPDATE "user" SET enterprise_authz_version = 43 WHERE id = $1
	`, userID); err != nil {
		t.Fatalf("bump version: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/workspaces/x/issues", nil)
	req.Header.Set("X-User-ID", userID)
	req.Header.Set(enterpriseSessionHeader, "sess-1")
	req.Header.Set(enterpriseVersionHeader, "43")
	rec := httptest.NewRecorder()
	EnterpriseVersion(cache, queries)(enterpriseNextHandler()).ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("fresh version rejected after invalidation: %d (%s)", rec.Code, rec.Body.String())
	}
}

func TestStripAndStampEnterpriseHeaders(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set(enterpriseSessionHeader, "forged")
	req.Header.Set(enterpriseSubjectHeader, "forged")
	req.Header.Set(enterpriseVersionHeader, "forged")
	stripEnterpriseHeaders(req)
	if req.Header.Get(enterpriseSessionHeader) != "" || req.Header.Get(enterpriseSubjectHeader) != "" ||
		req.Header.Get(enterpriseVersionHeader) != "" {
		t.Fatal("strip left client headers behind")
	}

	req = httptest.NewRequest(http.MethodGet, "/", nil)
	stampEnterpriseFromClaims(req, map[string]any{
		"ent_sid": "s-1",
		"ent_ver": float64(9),
	})
	if req.Header.Get(enterpriseSessionHeader) != "s-1" || req.Header.Get(enterpriseVersionHeader) != "9" {
		t.Fatalf("claims not stamped: %+v", req.Header)
	}
	stampEnterpriseSubject(req, "sub-1")
	if req.Header.Get(enterpriseSubjectHeader) != "sub-1" {
		t.Fatal("subject not stamped")
	}
	// Personal claims stamp nothing.
	req = httptest.NewRequest(http.MethodGet, "/", nil)
	stampEnterpriseFromClaims(req, map[string]any{"sub": "u"})
	if req.Header.Get(enterpriseSessionHeader) != "" {
		t.Fatal("personal claims stamped enterprise headers")
	}
}

func TestEnterpriseVersionRejectsStalePATVersion(t *testing.T) {
	pool := enterpriseTestPool(t)
	queries := db.New(pool)
	userID := seedEnterpriseUser(t, pool, true)
	subject := "sub-" + strings.ReplaceAll(t.Name(), "/", "-")

	// PAT snapshot matches the user's current version (42) → allowed.
	cache := NewEnterpriseVersionCache(nil)
	req := httptest.NewRequest(http.MethodPost, "/api/workspaces/x/issues", nil)
	req.Header.Set("X-User-ID", userID)
	req.Header.Set(enterpriseSubjectHeader, subject)
	req.Header.Set(enterpriseVersionHeader, "42")
	rec := httptest.NewRecorder()
	EnterpriseVersion(cache, queries)(enterpriseNextHandler()).ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("matching version blocked: %d (%s)", rec.Code, rec.Body.String())
	}

	// PAT minted before the revocation (stale snapshot 41) → rejected.
	req = httptest.NewRequest(http.MethodPost, "/api/workspaces/x/issues", nil)
	req.Header.Set("X-User-ID", userID)
	req.Header.Set(enterpriseSubjectHeader, subject)
	req.Header.Set(enterpriseVersionHeader, "41")
	rec = httptest.NewRecorder()
	EnterpriseVersion(cache, queries)(enterpriseNextHandler()).ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("stale PAT version passed: %d", rec.Code)
	}
}

func TestEnterpriseVersionRefresherReanchorAndFailClosed(t *testing.T) {
	pool := enterpriseTestPool(t)
	queries := db.New(pool)
	userID := seedEnterpriseUser(t, pool, true)

	// Refresher re-anchors version from the platform (99) and persists it.
	refresh := EnterpriseAuthzRefresher(func(ctx context.Context, q *db.Queries, uid string, current EnterpriseIdentity) (EnterpriseIdentity, error) {
		current.Version = 99
		u, uerr := util.ParseUUID(uid)
		if uerr != nil {
			return current, uerr
		}
		if _, err := q.UpdateUserEnterpriseAuthzVersion(ctx, db.UpdateUserEnterpriseAuthzVersionParams{
			ID:                     u,
			EnterpriseAuthzVersion: pgtype.Int8{Int64: 99, Valid: true},
		}); err != nil {
			return current, err
		}
		return current, nil
	})

	cache := NewEnterpriseVersionCache(nil)
	req := httptest.NewRequest(http.MethodPost, "/api/workspaces/x/issues", nil)
	req.Header.Set("X-User-ID", userID)
	req.Header.Set(enterpriseSessionHeader, "sess-1")
	req.Header.Set(enterpriseVersionHeader, "99")
	rec := httptest.NewRecorder()
	EnterpriseVersion(cache, queries, refresh)(enterpriseNextHandler()).ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("re-anchored epoch blocked: %d (%s)", rec.Code, rec.Body.String())
	}

	// Platform unreachable → fail closed, never serve the stale local row.
	broken := EnterpriseAuthzRefresher(func(ctx context.Context, q *db.Queries, uid string, current EnterpriseIdentity) (EnterpriseIdentity, error) {
		return current, errors.New("platform unreachable")
	})
	cache = NewEnterpriseVersionCache(nil)
	req = httptest.NewRequest(http.MethodPost, "/api/workspaces/x/issues", nil)
	req.Header.Set("X-User-ID", userID)
	req.Header.Set(enterpriseSessionHeader, "sess-1")
	req.Header.Set(enterpriseVersionHeader, "99")
	rec = httptest.NewRecorder()
	EnterpriseVersion(cache, queries, broken)(enterpriseNextHandler()).ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("unreachable platform must fail closed, got %d", rec.Code)
	}
}

// TestUpdateUserEnterpriseAuthzVersionMonotonic pins the N-4 guard: a stale
// platform read or a replayed invalidate frame carrying an older version must
// never roll the row back — the write only lands when it moves forward.
func TestUpdateUserEnterpriseAuthzVersionMonotonic(t *testing.T) {
	pool := enterpriseTestPool(t)
	q := db.New(pool)
	userID := seedEnterpriseUser(t, pool, true)
	ctx := context.Background()
	u := util.MustParseUUID(userID)

	// Forward write lands (the seed row starts at 42).
	n, err := q.UpdateUserEnterpriseAuthzVersion(ctx, db.UpdateUserEnterpriseAuthzVersionParams{
		ID: u, EnterpriseAuthzVersion: pgtype.Int8{Int64: 99, Valid: true},
	})
	if err != nil || n != 1 {
		t.Fatalf("forward write: rows=%d err=%v", n, err)
	}
	// Replay of an older version is acknowledged but does not roll back.
	n, err = q.UpdateUserEnterpriseAuthzVersion(ctx, db.UpdateUserEnterpriseAuthzVersionParams{
		ID: u, EnterpriseAuthzVersion: pgtype.Int8{Int64: 7, Valid: true},
	})
	if err != nil {
		t.Fatalf("replay write: %v", err)
	}
	if n != 0 {
		t.Fatalf("older version rolled the row forward-guard: rows=%d", n)
	}
	var version int64
	if err := pool.QueryRow(ctx, `SELECT enterprise_authz_version FROM "user" WHERE id = $1`, u).Scan(&version); err != nil {
		t.Fatalf("read version: %v", err)
	}
	if version != 99 {
		t.Fatalf("version = %d, want 99 (replay must not roll back)", version)
	}
}
