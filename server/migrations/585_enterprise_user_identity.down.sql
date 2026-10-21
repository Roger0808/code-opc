ALTER TABLE "user"
    DROP COLUMN IF EXISTS enterprise_session_id,
    DROP COLUMN IF EXISTS enterprise_authz_version,
    DROP COLUMN IF EXISTS enterprise_identity_link_id,
    DROP COLUMN IF EXISTS enterprise_subject;
