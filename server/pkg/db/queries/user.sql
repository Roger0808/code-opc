-- name: GetUser :one
SELECT * FROM "user"
WHERE id = $1;

-- name: GetUserByEmail :one
SELECT * FROM "user"
WHERE email = $1;

-- name: GetUsersByIDs :many
-- Batch lookup from the GLOBAL user table (not gated on membership, so departed
-- members still render). Used to enrich attribution initiator / originator refs on
-- task responses without an N+1 (MUL-4302 §9). Returns only the display fields.
SELECT id, name, email, avatar_url FROM "user"
WHERE id = ANY(@ids::uuid[]);

-- name: CreateUser :one
INSERT INTO "user" (name, email, avatar_url)
VALUES ($1, $2, $3)
RETURNING *;

-- name: UpdateUser :one
-- Patches the user-controlled profile fields. Each parameter follows
-- COALESCE-on-NULL semantics so the handler can omit any field it
-- doesn't intend to write.
--
-- `timezone` (Viewing-tz preference) participates in
-- the same shape but uses sqlc.narg + a sentinel-string convention:
-- the handler passes the empty string "" to mean "clear back to NULL"
-- (browser-detected fallback), an IANA name like "Asia/Shanghai" to
-- pin a value, and `sqlc.narg('timezone') IS NULL` (no value at all)
-- to leave the existing column untouched. Folding it into UpdateUser
-- rather than carrying a dedicated UpdateUserTimezone keeps the
-- profile-patch shape uniform between Preferences fields.
UPDATE "user" SET
    name = COALESCE($2, name),
    avatar_url = COALESCE($3, avatar_url),
    language = COALESCE($4, language),
    profile_description = COALESCE(sqlc.narg('profile_description'), profile_description),
    timezone = CASE
        WHEN sqlc.narg('timezone')::text IS NULL THEN timezone
        WHEN sqlc.narg('timezone')::text = ''    THEN NULL
        ELSE sqlc.narg('timezone')::text
    END,
    updated_at = now()
WHERE id = $1
RETURNING *;

-- name: MarkUserOnboarded :one
UPDATE "user" SET
    onboarded_at = COALESCE(onboarded_at, now()),
    updated_at = now()
WHERE id = $1
RETURNING *;

-- name: PatchUserOnboarding :one
-- Partial update of the user's onboarding decision fields. Currently only the
-- questionnaire JSONB is patchable — the v2 attempt at persisting Step 3
-- runtime choice on the user row was reverted; that state now lives in a
-- frontend Zustand transient store.
UPDATE "user" SET
    onboarding_questionnaire = COALESCE(sqlc.narg('questionnaire'), onboarding_questionnaire),
    updated_at = now()
WHERE id = sqlc.arg('id')
RETURNING *;

-- name: JoinCloudWaitlist :one
-- Records interest in cloud runtimes. Does NOT mark onboarding
-- complete — the user still has to pick a real path (CLI / Skip)
-- in Step 3. Repeating the call overwrites email + reason.
UPDATE "user" SET
    cloud_waitlist_email = $2,
    cloud_waitlist_reason = $3,
    updated_at = now()
WHERE id = $1
RETURNING *;

-- name: GetUserByEnterpriseSubject :one
-- Enterprise identity lookup for the code-exchange flow: the platform subject
-- is the stable key; the local email is only a placeholder.
SELECT * FROM "user"
WHERE enterprise_subject = $1;

-- name: CreateEnterpriseUser :one
-- Creates a locally-managed user row for a platform (enterprise) identity.
-- The email is an internal placeholder, not a deliverable mailbox.
INSERT INTO "user" (name, email, enterprise_subject, enterprise_identity_link_id, enterprise_authz_version, enterprise_session_id)
VALUES ($1, $2, $3, $4, $5, $6)
RETURNING *;

-- name: UpdateUserEnterpriseIdentity :one
-- Refreshes the platform identity binding on a subsequent exchange: a new
-- session epoch is minted per exchange and the authorization version is
-- re-anchored to whatever the platform currently reports.
UPDATE "user" SET
    enterprise_subject = COALESCE($2, enterprise_subject),
    enterprise_identity_link_id = COALESCE($3, enterprise_identity_link_id),
    enterprise_authz_version = COALESCE($4, enterprise_authz_version),
    enterprise_session_id = COALESCE($5, enterprise_session_id),
    updated_at = now()
WHERE id = $1
RETURNING *;

-- name: UpdateUserEnterpriseAuthzVersion :execrows
-- Re-anchors a user's enterprise authorization version from the platform
-- (revocation propagation path; see EnterpriseVersion middleware refresher).
-- Monotonic: a stale platform read (or a replayed invalidate frame) carrying
-- an older version must never roll the row back, so the write only lands when
-- it moves the version forward. Callers read the row back when they need the
-- winning value.
UPDATE "user" SET enterprise_authz_version = $2, updated_at = now()
WHERE id = $1 AND enterprise_subject IS NOT NULL
  AND (enterprise_authz_version IS NULL OR enterprise_authz_version < $2);
