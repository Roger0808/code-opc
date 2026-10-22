-- name: UpsertEnterpriseWorkspaceLink :one
-- Exchange-time binding between a local user, a local workspace and the
-- platform workspace it mirrors. One row per (user, platform workspace);
-- a re-exchange moves the local workspace binding forward. The tenant hint
-- is refreshed on re-exchange: it is only ever a cache-key segment, so
-- keeping the latest value cannot strand a workspace.
INSERT INTO enterprise_workspace_link (user_id, workspace_id, platform_workspace_id, source, platform_tenant)
VALUES ($1, $2, $3, $4, $5)
ON CONFLICT (user_id, platform_workspace_id)
DO UPDATE SET workspace_id = EXCLUDED.workspace_id, source = EXCLUDED.source, platform_tenant = EXCLUDED.platform_tenant
RETURNING *;

-- name: GetEnterpriseWorkspaceLinkByWorkspace :one
-- Presence of a row marks the workspace as enterprise-managed: daemon task
-- claims for it require a platform lease and MCP resolution fails closed.
SELECT * FROM enterprise_workspace_link
WHERE workspace_id = $1
LIMIT 1;

-- name: GetEnterpriseWorkspaceLinkByUserAndPlatform :one
SELECT * FROM enterprise_workspace_link
WHERE user_id = $1 AND platform_workspace_id = $2;

-- name: ListEnterpriseWorkspaceLinksByUser :many
SELECT * FROM enterprise_workspace_link
WHERE user_id = $1
ORDER BY created_at;

-- name: DeleteEnterpriseWorkspaceLinksByWorkspace :exec
-- Workspace teardown (no foreign keys by repository rule): the link row is
-- what marks a workspace as enterprise-managed, so it must not outlive the
-- workspace or every later claim would still treat the gone workspace as
-- enterprise.
DELETE FROM enterprise_workspace_link
WHERE workspace_id = $1;
