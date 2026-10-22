-- Enterprise identity linkage for the local user row (OPC integration).
-- All columns stay NULL for non-enterprise users; a NULL enterprise_subject
-- must never be read as "unlimited enterprise access".
ALTER TABLE "user"
    ADD COLUMN IF NOT EXISTS enterprise_subject TEXT,
    ADD COLUMN IF NOT EXISTS enterprise_identity_link_id TEXT,
    ADD COLUMN IF NOT EXISTS enterprise_authz_version BIGINT,
    ADD COLUMN IF NOT EXISTS enterprise_session_id TEXT;
