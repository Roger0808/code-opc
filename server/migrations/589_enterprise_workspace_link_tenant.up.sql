-- Tenant hint the platform attached to the mirrored space at exchange time.
-- It is the tenant segment of the BND-142 enterprise skill cache key, so
-- packages pinned for one tenant never satisfy another. Empty string when
-- the platform space carried no tenant hint.
ALTER TABLE enterprise_workspace_link ADD COLUMN IF NOT EXISTS platform_tenant TEXT NOT NULL DEFAULT '';
