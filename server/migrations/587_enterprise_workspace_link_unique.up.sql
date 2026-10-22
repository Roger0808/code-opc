-- One link per (local user, platform workspace); the exchange flow upserts on
-- this pair. Single-statement concurrent build, per repository migration rules.
CREATE UNIQUE INDEX CONCURRENTLY IF NOT EXISTS idx_enterprise_workspace_link_user_platform
    ON enterprise_workspace_link (user_id, platform_workspace_id);
