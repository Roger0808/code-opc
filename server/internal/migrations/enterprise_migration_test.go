package migrations

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// enterpriseSchema builds the two parent tables the enterprise migrations
// touch, then applies each new migration up and down in the same scratch
// schema the other migration tests use.
func enterpriseSchema(t *testing.T, ctx context.Context, pool *pgxpool.Pool) (*pgx.Conn, func()) {
	t.Helper()
	schema := "enterprise_migration_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	quoted := pgx.Identifier{schema}.Sanitize()
	if _, err := pool.Exec(ctx, "CREATE SCHEMA "+quoted); err != nil {
		t.Fatalf("create schema: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), "DROP SCHEMA "+quoted+" CASCADE")
	})

	conn, err := pool.Acquire(ctx)
	if err != nil {
		t.Fatalf("acquire connection: %v", err)
	}
	if _, err := conn.Exec(ctx, `SELECT set_config('search_path', $1, false)`, schema); err != nil {
		t.Fatalf("set search path: %v", err)
	}
	if _, err := conn.Exec(ctx, `
		CREATE TABLE "user" (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			name TEXT NOT NULL,
			email TEXT UNIQUE NOT NULL,
			created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
			updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
		);
		CREATE TABLE personal_access_token (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			user_id UUID NOT NULL,
			name TEXT NOT NULL,
			token_hash TEXT NOT NULL,
			token_prefix TEXT NOT NULL,
			expires_at TIMESTAMPTZ,
			last_used_at TIMESTAMPTZ,
			revoked BOOLEAN NOT NULL DEFAULT FALSE,
			created_at TIMESTAMPTZ NOT NULL DEFAULT now()
		);
	`); err != nil {
		t.Fatalf("create fixture tables: %v", err)
	}
	return conn.Conn(), func() { conn.Release() }
}

func TestEnterpriseUserIdentityMigrationUpDown(t *testing.T) {
	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		t.Skip("integration test requires Postgres at DATABASE_URL")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dbURL)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer pool.Close()

	conn, release := enterpriseSchema(t, ctx, pool)
	defer release()

	// All four columns arrive nullable with NULL defaults: a non-enterprise
	// user must look exactly like a row in the pre-migration schema.
	applyMigrationFile(t, ctx, conn, "585_enterprise_user_identity.up.sql")
	var userID string
	if err := conn.QueryRow(ctx, `
		INSERT INTO "user" (name, email) VALUES ('plain', 'plain@example.com') RETURNING id
	`).Scan(&userID); err != nil {
		t.Fatalf("insert plain user: %v", err)
	}
	var subject, linkID, sessionID *string
	var version *int64
	if err := conn.QueryRow(ctx, `
		SELECT enterprise_subject, enterprise_identity_link_id, enterprise_authz_version, enterprise_session_id
		FROM "user" WHERE id = $1
	`, userID).Scan(&subject, &linkID, &version, &sessionID); err != nil {
		t.Fatalf("read enterprise columns: %v", err)
	}
	if subject != nil || linkID != nil || version != nil || sessionID != nil {
		t.Fatal("non-enterprise user must keep NULL enterprise columns")
	}
	if _, err := conn.Exec(ctx, `
		INSERT INTO "user" (name, email, enterprise_subject, enterprise_authz_version)
		VALUES ('ent', 'ent@example.com', 'sub-1', 9)
	`); err != nil {
		t.Fatalf("insert enterprise user: %v", err)
	}

	applyMigrationFile(t, ctx, conn, "585_enterprise_user_identity.down.sql")
	var colExists bool
	if err := conn.QueryRow(ctx, `SELECT count(*) > 0 FROM information_schema.columns
		WHERE table_schema = current_schema() AND table_name = 'user' AND column_name = 'enterprise_subject'`).Scan(&colExists); err != nil {
		t.Fatalf("check dropped column: %v", err)
	}
	if colExists {
		t.Fatal("down migration left enterprise_subject behind")
	}
}

func TestEnterpriseWorkspaceLinkMigrationUpDown(t *testing.T) {
	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		t.Skip("integration test requires Postgres at DATABASE_URL")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dbURL)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer pool.Close()

	conn, release := enterpriseSchema(t, ctx, pool)
	defer release()

	applyMigrationFile(t, ctx, conn, "585_enterprise_user_identity.up.sql")
	applyMigrationFile(t, ctx, conn, "586_enterprise_workspace_link.up.sql")
	applyMigrationFile(t, ctx, conn, "587_enterprise_workspace_link_unique.up.sql")

	var userID, workspaceID string
	if err := conn.QueryRow(ctx, `INSERT INTO "user" (name, email) VALUES ('l', 'l@example.com') RETURNING id`).Scan(&userID); err != nil {
		t.Fatalf("insert user: %v", err)
	}
	workspaceID = "11111111-1111-1111-1111-111111111111"
	if _, err := conn.Exec(ctx, `
		INSERT INTO enterprise_workspace_link (user_id, workspace_id, platform_workspace_id)
		VALUES ($1, $2, 'pw-1')
	`, userID, workspaceID); err != nil {
		t.Fatalf("insert link: %v", err)
	}
	// The concurrent unique index enforces one link per (user, platform ws).
	if _, err := conn.Exec(ctx, `
		INSERT INTO enterprise_workspace_link (user_id, workspace_id, platform_workspace_id)
		VALUES ($1, $2, 'pw-1')
	`, userID, workspaceID); err == nil {
		t.Fatal("duplicate (user_id, platform_workspace_id) link was accepted")
	}

	applyMigrationFile(t, ctx, conn, "587_enterprise_workspace_link_unique.down.sql")
	// Without the index the duplicate is representable again...
	if _, err := conn.Exec(ctx, `
		INSERT INTO enterprise_workspace_link (user_id, workspace_id, platform_workspace_id)
		VALUES ($1, $2, 'pw-1')
	`, userID, workspaceID); err != nil {
		t.Fatalf("insert after index down: %v", err)
	}
	// ...and the table itself drops with 586.
	applyMigrationFile(t, ctx, conn, "586_enterprise_workspace_link.down.sql")
	var tableExists bool
	if err := conn.QueryRow(ctx, `SELECT to_regclass('enterprise_workspace_link') IS NOT NULL`).Scan(&tableExists); err != nil {
		t.Fatalf("check dropped table: %v", err)
	}
	if tableExists {
		t.Fatal("down migration left enterprise_workspace_link behind")
	}
}

func TestEnterprisePATSubjectMigrationUpDown(t *testing.T) {
	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		t.Skip("integration test requires Postgres at DATABASE_URL")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dbURL)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer pool.Close()

	conn, release := enterpriseSchema(t, ctx, pool)
	defer release()

	var userID string
	if err := conn.QueryRow(ctx, `INSERT INTO "user" (name, email) VALUES ('p', 'p@example.com') RETURNING id`).Scan(&userID); err != nil {
		t.Fatalf("insert user: %v", err)
	}

	applyMigrationFile(t, ctx, conn, "588_enterprise_pat_subject.up.sql")
	var patID string
	if err := conn.QueryRow(ctx, `
		INSERT INTO personal_access_token (user_id, name, token_hash, token_prefix)
		VALUES ($1, 't', 'h', 'p') RETURNING id
	`, userID).Scan(&patID); err != nil {
		t.Fatalf("insert pat: %v", err)
	}
	var subject *string
	if err := conn.QueryRow(ctx, `SELECT enterprise_subject FROM personal_access_token WHERE id = $1`, patID).Scan(&subject); err != nil {
		t.Fatalf("read snapshot: %v", err)
	}
	if subject != nil {
		t.Fatal("default enterprise_subject must be NULL")
	}

	applyMigrationFile(t, ctx, conn, "588_enterprise_pat_subject.down.sql")
	var colExists bool
	if err := conn.QueryRow(ctx, `SELECT count(*) > 0 FROM information_schema.columns
		WHERE table_schema = current_schema() AND table_name = 'personal_access_token' AND column_name = 'enterprise_subject'`).Scan(&colExists); err != nil {
		t.Fatalf("check dropped column: %v", err)
	}
	if colExists {
		t.Fatal("down migration left enterprise_subject behind")
	}
}
