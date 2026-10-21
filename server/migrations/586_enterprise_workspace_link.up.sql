-- Maps a local workspace to the platform (enterprise) workspace it mirrors.
-- A row present here marks the workspace as enterprise-managed: daemon task
-- claims for it require a platform lease, and MCP config resolution fails
-- closed instead of falling back to local agent config. No foreign keys by
-- repository rule; referential cleanup happens in application code.
CREATE TABLE IF NOT EXISTS enterprise_workspace_link (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL,
    workspace_id UUID NOT NULL,
    platform_workspace_id TEXT NOT NULL,
    source TEXT NOT NULL DEFAULT 'enterprise_exchange',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
