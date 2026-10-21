ALTER TABLE personal_access_token
    ADD COLUMN IF NOT EXISTS enterprise_authz_version BIGINT;
