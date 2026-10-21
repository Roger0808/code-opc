-- Enterprise subject snapshot taken at PAT issuance. The auth middleware
-- re-checks the snapshot against the user's current enterprise identity on
-- every enterprise-gated request, layered on top of the 10-minute PAT cache.
ALTER TABLE personal_access_token
    ADD COLUMN IF NOT EXISTS enterprise_subject TEXT;
