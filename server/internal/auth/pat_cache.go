package auth

import (
	"context"
	"errors"
	"log/slog"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"
)

// AuthCacheTTL bounds how long a token-hash lookup stays cached before
// the auth middleware goes back to Postgres. Shared by PATCache and
// DaemonTokenCache so both kinds of token follow the same revocation
// latency contract. Short enough that revocation lag from a missed
// invalidation is bounded; long enough that a high-frequency client
// (CLI, daemon) collapses from one DB round-trip per request to one
// per TTL window.
const AuthCacheTTL = 10 * time.Minute

// patCachePrefix namespaces auth-cache keys away from the realtime relay
// (ws:*) and local-skill (mul:local_skill:*) keys.
const patCachePrefix = "mul:auth:pat:"

// PATCache caches resolved PAT lookups in Redis. A nil *PATCache is safe
// to use — every method becomes a no-op or reports a cache miss, and the
// auth middleware degrades to direct DB lookups.
type PATCache struct {
	rdb redis.UniversalClient
}

// NewPATCache returns a cache backed by rdb. Pass nil to disable caching;
// the returned *PATCache is safe to call but never hits Redis.
func NewPATCache(rdb redis.UniversalClient) *PATCache {
	if rdb == nil {
		return nil
	}
	return &PATCache{rdb: rdb}
}

func patCacheKey(hash string) string { return patCachePrefix + hash }

// Get returns the cached user_id for a token hash. ok=false on cache miss
// or any Redis error — a dead Redis must not take down auth.
func (c *PATCache) Get(ctx context.Context, hash string) (userID string, ok bool) {
	userID, _, ok = c.GetIdentity(ctx, hash)
	return userID, ok
}

// Set populates the cache with the given TTL. Callers MUST pass a TTL no
// longer than the token's remaining lifetime — otherwise an entry could
// outlive the PAT's expires_at and let an expired token pass auth on
// cache hit. Use TTLForExpiry to compute it from a token's expires_at.
//
// Errors are logged and swallowed — a cache write failure is not a
// request failure.
func (c *PATCache) Set(ctx context.Context, hash, userID string, ttl time.Duration) {
	c.SetIdentity(ctx, hash, userID, "", ttl)
}

// patValueSep separates user_id from the enterprise subject snapshot inside
// a cached value. Entries written before enterprise support decode as a
// bare user_id with an empty subject, which is exactly right for them.
// A second separator carries the authorization version snapshot; entries
// written before it existed decode with an empty version.
const patValueSep = "\x1f"

func patCacheEncode(userID, enterpriseSubject string) string {
	return userID + patValueSep + enterpriseSubject
}

func patCacheEncodeIdentity(userID, enterpriseSubject, enterpriseVersion string) string {
	return userID + patValueSep + enterpriseSubject + patValueSep + enterpriseVersion
}

// GetIdentity returns the cached (user_id, enterprise subject) pair for a
// token hash. Entries written by the pre-enterprise Set carry no subject —
// they report an empty one, matching a PAT minted before linkage.
func (c *PATCache) GetIdentity(ctx context.Context, hash string) (userID, enterpriseSubject string, ok bool) {
	userID, enterpriseSubject, _, ok = c.GetIdentityFull(ctx, hash)
	return userID, enterpriseSubject, ok
}

// GetIdentityFull additionally returns the authorization version snapshot.
func (c *PATCache) GetIdentityFull(ctx context.Context, hash string) (userID, enterpriseSubject, enterpriseVersion string, ok bool) {
	raw, ok := c.getRaw(ctx, hash)
	if !ok {
		return "", "", "", false
	}
	parts := strings.SplitN(raw, patValueSep, 3)
	userID = parts[0]
	if len(parts) > 1 {
		enterpriseSubject = parts[1]
	}
	if len(parts) > 2 {
		enterpriseVersion = parts[2]
	}
	return userID, enterpriseSubject, enterpriseVersion, true
}

// SetIdentity stores the resolution including the enterprise subject
// snapshot so the enterprise version check survives the 10-minute PAT cache.
func (c *PATCache) SetIdentity(ctx context.Context, hash, userID, enterpriseSubject string, ttl time.Duration) {
	c.SetIdentityFull(ctx, hash, userID, enterpriseSubject, "", ttl)
}

// SetIdentityFull additionally stores the authorization version snapshot.
func (c *PATCache) SetIdentityFull(ctx context.Context, hash, userID, enterpriseSubject, enterpriseVersion string, ttl time.Duration) {
	if c == nil || ttl <= 0 {
		return
	}
	if err := c.rdb.Set(ctx, patCacheKey(hash), patCacheEncodeIdentity(userID, enterpriseSubject, enterpriseVersion), ttl).Err(); err != nil {
		slog.Warn("pat_cache: set failed", "error", err)
	}
}

func (c *PATCache) getRaw(ctx context.Context, hash string) (string, bool) {
	if c == nil {
		return "", false
	}
	v, err := c.rdb.Get(ctx, patCacheKey(hash)).Result()
	if err != nil {
		if !errors.Is(err, redis.Nil) {
			slog.Warn("pat_cache: get failed; falling back to DB", "error", err)
		}
		return "", false
	}
	return v, true
}

// TTLForExpiry returns the cache TTL for a token given its expires_at.
//   - Zero expiresAt (token never expires) → full AuthCacheTTL.
//   - expiresAt in the future → min(AuthCacheTTL, time until expiry).
//   - expiresAt at or before now → 0 (caller should skip caching; the
//     middleware shouldn't reach here because the SELECT already
//     filters expired tokens, but a TOCTOU between SELECT and Set is
//     possible).
//
// Pass time.Time{} when the token has no expiry (pgtype.Timestamptz with
// Valid=false maps to a zero Time).
func TTLForExpiry(now, expiresAt time.Time) time.Duration {
	if expiresAt.IsZero() {
		return AuthCacheTTL
	}
	remaining := expiresAt.Sub(now)
	if remaining <= 0 {
		return 0
	}
	if remaining < AuthCacheTTL {
		return remaining
	}
	return AuthCacheTTL
}

// Invalidate removes the entry for hash. Called on PAT revocation so the
// revoke takes effect immediately rather than waiting for the TTL.
func (c *PATCache) Invalidate(ctx context.Context, hash string) {
	if c == nil {
		return
	}
	if err := c.rdb.Del(ctx, patCacheKey(hash)).Err(); err != nil {
		slog.Warn("pat_cache: invalidate failed; entry will expire on TTL", "error", err)
	}
}
