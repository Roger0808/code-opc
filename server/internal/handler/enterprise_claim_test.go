package handler

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/multica-ai/multica/server/internal/platform"
	"github.com/multica-ai/multica/server/internal/testutil"
	"github.com/multica-ai/multica/server/pkg/protocol"
)

// enterpriseTestSubject is the platform subject the fixtures bind to.
const enterpriseTestSubject = "sub-ent-test-1"

// signTestLease signs an X-Enterprise-Lease JWT the way the platform would.
func signTestLease(t *testing.T, secret string, claims map[string]any) string {
	t.Helper()
	jc := jwt.MapClaims{}
	for k, v := range claims {
		jc[k] = v
	}
	if _, ok := jc["exp"]; !ok {
		jc["exp"] = time.Now().Add(10 * time.Minute).Unix()
	}
	signed, err := jwt.NewWithClaims(jwt.SigningMethodHS256, jc).SignedString([]byte(secret))
	if err != nil {
		t.Fatalf("sign lease: %v", err)
	}
	return signed
}

// enterpriseFixture builds an enterprise workspace with a linked enterprise
// user, runtime, agent, issue and queued task.
type enterpriseFixture struct {
	workspaceID string
	userID      string
	personalID  string
	runtimeID   string
	agentID     string
	issueID     string
	taskID      string
}

func newEnterpriseFixture(t *testing.T) *enterpriseFixture {
	t.Helper()
	if testHandler == nil || testPool == nil {
		t.Skip("database not available")
	}
	f := &enterpriseFixture{}
	f.workspaceID = dbfx.Insert(t, "workspace", testutil.Cols{
		"name":         "Enterprise WS " + t.Name(),
		"slug":         "ent-ws-" + strings.ReplaceAll(t.Name(), "/", "-"),
		"issue_prefix": "ENT",
	})
	f.userID = dbfx.Insert(t, "user", testutil.Cols{
		"name":                     "ent user",
		"email":                    "ent-" + strings.ReplaceAll(t.Name(), "/", "-") + "@platform.local",
		"enterprise_subject":       enterpriseTestSubject,
		"enterprise_session_id":    "sess-ent-1",
		"enterprise_authz_version": 42,
	})
	f.personalID = dbfx.Insert(t, "user", testutil.Cols{
		"name":  "personal member",
		"email": "personal-" + strings.ReplaceAll(t.Name(), "/", "-") + "@multica.ai",
	})
	dbfx.Insert(t, "member", testutil.Cols{"workspace_id": f.workspaceID, "user_id": f.userID, "role": "owner"})
	dbfx.Insert(t, "member", testutil.Cols{"workspace_id": f.workspaceID, "user_id": f.personalID, "role": "member"})
	dbfx.Insert(t, "enterprise_workspace_link", testutil.Cols{
		"user_id": f.userID, "workspace_id": f.workspaceID, "platform_workspace_id": "pw-ent-1",
	})
	f.runtimeID = dbfx.Runtime(t, "ent runtime "+t.Name(), testutil.Cols{
		"workspace_id": f.workspaceID,
		"owner_id":     f.userID,
		"daemon_id":    "ent-daemon",
	})
	f.agentID = dbfx.Agent(t, "ent agent "+t.Name(), f.runtimeID, testutil.Cols{
		"workspace_id": f.workspaceID,
		"owner_id":     f.userID,
	})
	f.issueID = dbfx.Issue(t, "ent issue "+t.Name(), testutil.Cols{
		"workspace_id": f.workspaceID,
		"creator_id":   f.userID,
	})
	f.taskID = dbfx.Task(t, f.agentID, testutil.Cols{
		"runtime_id": f.runtimeID,
		"issue_id":   f.issueID,
		"status":     "queued",
	})
	return f
}

// withTestPlatform installs a platform client with the given lease secret on
// the shared handler, restoring whatever was there before.
func withTestPlatform(t *testing.T, baseURL, leaseSecret string) {
	t.Helper()
	client, err := platform.New(platform.Config{
		BaseURL:         baseURL,
		ServiceToken:    "svc",
		LeaseHMACSecret: leaseSecret,
	})
	if err != nil {
		t.Fatalf("platform.New: %v", err)
	}
	previous := testHandler.Platform
	testHandler.Platform = client
	t.Cleanup(func() { testHandler.Platform = previous })
}

// withGrantPlatform points the handler's platform client at an httptest
// server that mints INT-102 leases with the request's task/runtime binding
// (signed by testLeaseSecret). Claim-success tests use this; refusal paths
// keep using an unreachable base URL.
func withGrantPlatform(t *testing.T) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && r.URL.Path == "/integration/v1/internal/grants" {
			var req struct {
				Subject   string `json:"subject"`
				TenantID  string `json:"tenant_id"`
				TaskID    string `json:"task_id"`
				RuntimeID string `json:"runtime_id"`
			}
			_ = json.NewDecoder(r.Body).Decode(&req)
			lease := signTestLease(t, testLeaseSecret, map[string]any{
				"grant_id":   "grant-test-1",
				"sub":        req.Subject,
				"tenant_id":  req.TenantID,
				"task_id":    req.TaskID,
				"runtime_id": req.RuntimeID,
			})
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"grant_id":         "grant-test-1",
				"lease_token":      lease,
				"lease_expires_at": time.Now().Add(30 * time.Second).UTC().Format(time.RFC3339),
			})
			return
		}
		http.NotFound(w, r)
	}))
	t.Cleanup(srv.Close)
	withTestPlatform(t, srv.URL, testLeaseSecret)
}

const testLeaseSecret = "test-lease-secret"

func enterpriseClaimRequest(t *testing.T, f *enterpriseFixture, capabilities, lease string) *http.Request {
	t.Helper()
	req := newDaemonTokenRequest("POST", "/api/daemon/runtimes/"+f.runtimeID+"/tasks/claim", nil,
		f.workspaceID, "ent-daemon")
	req = withURLParam(req, "runtimeId", f.runtimeID)
	if capabilities != "" {
		req.Header.Set("X-Client-Capabilities", capabilities)
	}
	if lease != "" {
		req.Header.Set("X-Enterprise-Lease", lease)
	}
	return req
}

type enterpriseClaimResponse struct {
	Task *struct {
		ID               string `json:"id"`
		ManagedMcpStatus string `json:"managed_mcp_status"`
		Enterprise       bool   `json:"enterprise"`
		EnterpriseLease  *struct {
			GrantID        string `json:"grant_id"`
			LeaseToken     string `json:"lease_token"`
			LeaseExpiresAt string `json:"lease_expires_at"`
		} `json:"enterprise_lease"`
		Agent *struct {
			McpConfig json.RawMessage `json:"mcp_config"`
		} `json:"agent"`
	} `json:"task"`
}

func decodeEnterpriseClaim(t *testing.T, body string) enterpriseClaimResponse {
	t.Helper()
	var out enterpriseClaimResponse
	if err := json.Unmarshal([]byte(body), &out); err != nil {
		t.Fatalf("decode claim response: %v (%s)", err, body)
	}
	return out
}

func errorCode(t *testing.T, body string) string {
	t.Helper()
	var parsed struct {
		Code string `json:"code"`
	}
	if err := json.Unmarshal([]byte(body), &parsed); err != nil {
		t.Fatalf("decode error body: %v (%s)", err, body)
	}
	return parsed.Code
}

func enterpriseTaskStatus(t *testing.T, taskID string) string {
	t.Helper()
	var status string
	dbfx.QueryRow(t, `SELECT status FROM agent_task_queue WHERE id = $1`, taskID).Scan(&status)
	return status
}

func TestEnterpriseClaimOldDaemonRejected(t *testing.T) {
	f := newEnterpriseFixture(t)
	withTestPlatform(t, "http://platform.invalid", testLeaseSecret)

	rec := testutil.Call(t, testHandler.ClaimTaskByRuntime, enterpriseClaimRequest(t, f, "", ""))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 (%s)", rec.Code, rec.Body.String())
	}
	if got := errorCode(t, rec.Body.String()); got != "enterprise_protocol_required" {
		t.Fatalf("code = %q", got)
	}
	if status := enterpriseTaskStatus(t, f.taskID); status != "queued" {
		t.Fatalf("refused enterprise task must be requeued, status = %q", status)
	}
}

func TestEnterpriseClaimCapabilityFromRegisterMetadata(t *testing.T) {
	f := newEnterpriseFixture(t)
	withTestPlatform(t, "http://platform.invalid", testLeaseSecret)
	// A daemon that declared the capability at register time (persisted in
	// runtime metadata) is not "old" even when this request omits the header.
	dbfx.Exec(t, `UPDATE agent_runtime SET metadata = $2 WHERE id = $1`, f.runtimeID,
		fmt.Sprintf(`{"capabilities":[%q]}`, protocol.DaemonCapabilityEnterpriseProtocolV1))

	rec := testutil.Call(t, testHandler.ClaimTaskByRuntime, enterpriseClaimRequest(t, f, "", ""))
	// Capability gate passes via register metadata, so the checkpoint proceeds
	// to lease issuance — which fails because the platform is unreachable.
	if got := errorCode(t, rec.Body.String()); got != "enterprise_lease_unavailable" {
		t.Fatalf("code = %q, want enterprise_lease_unavailable (capability gate passed; platform unreachable)", got)
	}
}

func TestEnterpriseClaimLeaseMatrix(t *testing.T) {
	f := newEnterpriseFixture(t)
	withTestPlatform(t, "http://platform.invalid", testLeaseSecret)

	// 租约头校验矩阵（renew 路径：claim 由服务端签发租约，daemon 续期时
	// 出示 X-Enterprise-Lease，服务端先验签/过期/绑定再代理给平台）。
	renewRequest := func(lease string) *http.Request {
		req := newDaemonTokenRequest("POST", "/api/daemon/runtimes/"+f.runtimeID+"/tasks/"+f.taskID+"/enterprise-lease/renew", nil,
			f.workspaceID, "ent-daemon")
		req = withURLParams(req, "runtimeId", f.runtimeID, "taskId", f.taskID)
		if lease != "" {
			req.Header.Set("X-Enterprise-Lease", lease)
		}
		return req
	}

	cases := []struct {
		name     string
		mutate   func() string // returns lease header value
		wantCode string
	}{
		{
			name:     "missing lease",
			mutate:   func() string { return "" },
			wantCode: "enterprise_lease_required",
		},
		{
			name: "garbage lease",
			mutate: func() string {
				return "not-a-jwt"
			},
			wantCode: "enterprise_lease_invalid",
		},
		{
			name: "expired lease",
			mutate: func() string {
				return signTestLease(t, testLeaseSecret, map[string]any{
					"sub": enterpriseTestSubject, "task_id": f.taskID, "runtime_id": f.runtimeID,
					"exp": time.Now().Add(-time.Minute).Unix(),
				})
			},
			wantCode: "LEASE_EXPIRED",
		},
		{
			name: "task mismatch",
			mutate: func() string {
				return signTestLease(t, testLeaseSecret, map[string]any{
					"sub": enterpriseTestSubject, "task_id": "99999999-9999-9999-9999-999999999999", "runtime_id": f.runtimeID,
				})
			},
			wantCode: "enterprise_lease_mismatch",
		},
		{
			name: "runtime mismatch",
			mutate: func() string {
				return signTestLease(t, testLeaseSecret, map[string]any{
					"sub": enterpriseTestSubject, "task_id": f.taskID, "runtime_id": "99999999-9999-9999-9999-999999999999",
				})
			},
			wantCode: "enterprise_lease_mismatch",
		},
		{
			name: "wrong signature",
			mutate: func() string {
				return signTestLease(t, "attacker-secret", map[string]any{
					"sub": enterpriseTestSubject, "task_id": f.taskID, "runtime_id": f.runtimeID,
				})
			},
			wantCode: "enterprise_lease_invalid",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			lease := tc.mutate()
			rec := testutil.Call(t, testHandler.RenewEnterpriseLease, renewRequest(lease))
			if got := errorCode(t, rec.Body.String()); got != tc.wantCode {
				t.Fatalf("code = %q, want %q (body %s)", got, tc.wantCode, rec.Body.String())
			}
		})
	}
}

func TestEnterpriseClaimSuccessAndManagedMCPStatus(t *testing.T) {
	f := newEnterpriseFixture(t)
	withGrantPlatform(t)
	// Agent carries a valid managed MCP set.
	dbfx.Exec(t, `UPDATE agent SET mcp_config = '{"mcpServers":{"managed":{"command":"mcp"}}}' WHERE id = $1`, f.agentID)

	lease := signTestLease(t, testLeaseSecret, map[string]any{
		"sub": enterpriseTestSubject, "task_id": f.taskID, "runtime_id": f.runtimeID,
	})
	rec := testutil.Call(t, testHandler.ClaimTaskByRuntime,
		enterpriseClaimRequest(t, f, protocol.DaemonCapabilityEnterpriseProtocolV1, lease))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d (%s)", rec.Code, rec.Body.String())
	}
	out := decodeEnterpriseClaim(t, rec.Body.String())
	if out.Task == nil || out.Task.ID != f.taskID {
		t.Fatalf("claimed task = %+v", out.Task)
	}
	if out.Task.ManagedMcpStatus != "ok" {
		t.Fatalf("managed_mcp_status = %q, want ok", out.Task.ManagedMcpStatus)
	}
	if !out.Task.Enterprise {
		t.Fatalf("enterprise claim response missing the enterprise marker: %s", rec.Body.String())
	}
	// The server mints the task's platform lease at claim time (INT-102): the
	// response carries the grant the daemon renews for the life of the task.
	if out.Task.EnterpriseLease == nil || out.Task.EnterpriseLease.GrantID != "grant-test-1" || out.Task.EnterpriseLease.LeaseToken == "" {
		t.Fatalf("claim response missing the server-issued enterprise_lease: %s", rec.Body.String())
	}
	if !strings.Contains(string(out.Task.Agent.McpConfig), "managed") {
		t.Fatalf("mcp_config lost the managed server: %s", out.Task.Agent.McpConfig)
	}
}

func TestEnterpriseClaimEmptyManagedSet(t *testing.T) {
	f := newEnterpriseFixture(t)
	withGrantPlatform(t)
	// Explicit empty managed set: legal for enterprise tasks.
	dbfx.Exec(t, `UPDATE agent SET mcp_config = '{}' WHERE id = $1`, f.agentID)

	lease := signTestLease(t, testLeaseSecret, map[string]any{
		"sub": enterpriseTestSubject, "task_id": f.taskID, "runtime_id": f.runtimeID,
	})
	rec := testutil.Call(t, testHandler.ClaimTaskByRuntime,
		enterpriseClaimRequest(t, f, protocol.DaemonCapabilityEnterpriseProtocolV1, lease))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d (%s)", rec.Code, rec.Body.String())
	}
	out := decodeEnterpriseClaim(t, rec.Body.String())
	if out.Task.ManagedMcpStatus != "empty" {
		t.Fatalf("managed_mcp_status = %q, want empty (%s)", out.Task.ManagedMcpStatus, rec.Body.String())
	}
	if trimmed := strings.TrimSpace(string(out.Task.Agent.McpConfig)); trimmed != "{}" {
		t.Fatalf("empty managed set must round-trip as {}, got %s", trimmed)
	}
}

func TestEnterpriseClaimNullManagedSetFailsClosed(t *testing.T) {
	f := newEnterpriseFixture(t)
	withGrantPlatform(t)
	// NULL managed set is only legal for personal tasks.
	dbfx.Exec(t, `UPDATE agent SET mcp_config = NULL WHERE id = $1`, f.agentID)

	lease := signTestLease(t, testLeaseSecret, map[string]any{
		"sub": enterpriseTestSubject, "task_id": f.taskID, "runtime_id": f.runtimeID,
	})
	rec := testutil.Call(t, testHandler.ClaimTaskByRuntime,
		enterpriseClaimRequest(t, f, protocol.DaemonCapabilityEnterpriseProtocolV1, lease))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d (%s)", rec.Code, rec.Body.String())
	}
	out := decodeEnterpriseClaim(t, rec.Body.String())
	if out.Task.ManagedMcpStatus != "failed_closed" {
		t.Fatalf("managed_mcp_status = %q, want failed_closed", out.Task.ManagedMcpStatus)
	}
	if trimmed := strings.TrimSpace(string(out.Task.Agent.McpConfig)); trimmed != "{}" {
		t.Fatalf("failed-closed managed set must be {}, got %s", trimmed)
	}
}

func TestEnterpriseClaimResolveFailureFailsClosedWithoutLocalFallback(t *testing.T) {
	f := newEnterpriseFixture(t)
	withGrantPlatform(t)
	// The agent's own config is malformed AND a workspace server is bound:
	// ResolveAgentMcpConfig errors. A personal task falls back to the local
	// config; an enterprise task must NOT — the response carries {} plus
	// failed_closed, and the local server name must not leak into it.
	dbfx.Exec(t, `UPDATE agent SET mcp_config = '{"mcpServers": "oops"}' WHERE id = $1`, f.agentID)
	serverID := dbfx.Insert(t, "workspace_mcp_server", testutil.Cols{
		"workspace_id": f.workspaceID,
		"name":         "shared-srv",
		"config":       testutil.Raw(`'{"command":"shared"}'::jsonb`),
	})
	dbfx.InsertNoID(t, "agent_mcp_server",
		testutil.Cols{"agent_id": f.agentID, "server_id": serverID},
		"agent_id = $1", f.agentID)

	lease := signTestLease(t, testLeaseSecret, map[string]any{
		"sub": enterpriseTestSubject, "task_id": f.taskID, "runtime_id": f.runtimeID,
	})
	rec := testutil.Call(t, testHandler.ClaimTaskByRuntime,
		enterpriseClaimRequest(t, f, protocol.DaemonCapabilityEnterpriseProtocolV1, lease))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d (%s)", rec.Code, rec.Body.String())
	}
	out := decodeEnterpriseClaim(t, rec.Body.String())
	if out.Task == nil {
		t.Fatalf("no task claimed: %s", rec.Body.String())
	}
	if out.Task.ManagedMcpStatus != "failed_closed" {
		t.Fatalf("managed_mcp_status = %q, want failed_closed", out.Task.ManagedMcpStatus)
	}
	if strings.Contains(string(out.Task.Agent.McpConfig), "oops") || strings.Contains(string(out.Task.Agent.McpConfig), "shared-srv") {
		t.Fatalf("local/merged MCP config leaked into failed-closed response: %s", out.Task.Agent.McpConfig)
	}
	if trimmed := strings.TrimSpace(string(out.Task.Agent.McpConfig)); trimmed != "{}" {
		t.Fatalf("failed-closed managed set must be the empty object, got %s", trimmed)
	}

	// Personal twin: same fixture shape in the personal workspace keeps the
	// historical fallback (agent config passes through, no status field).
	personalTaskID, personalAgentID := personalTwinTask(t)
	dbfx.Exec(t, `UPDATE agent SET mcp_config = '{"mcpServers": "oops"}' WHERE id = $1`, personalAgentID)
	serverID2 := dbfx.Insert(t, "workspace_mcp_server", testutil.Cols{
		"workspace_id": testWorkspaceID,
		"name":         "shared-srv-personal",
		"config":       testutil.Raw(`'{"command":"shared"}'::jsonb`),
	})
	dbfx.InsertNoID(t, "agent_mcp_server",
		testutil.Cols{"agent_id": personalAgentID, "server_id": serverID2},
		"agent_id = $1", personalAgentID)

	pReq := newDaemonTokenRequest("POST", "/api/daemon/runtimes/"+testRuntimeID+"/tasks/claim", nil,
		testWorkspaceID, "personal-daemon")
	pReq = withURLParam(pReq, "runtimeId", testRuntimeID)
	pRecorder := httptest.NewRecorder()
	testHandler.ClaimTaskByRuntime(pRecorder, pReq)
	if pRecorder.Code != http.StatusOK {
		t.Fatalf("personal claim status = %d (%s)", pRecorder.Code, pRecorder.Body.String())
	}
	var personal struct {
		Task *struct {
			ID               string `json:"id"`
			ManagedMcpStatus string `json:"managed_mcp_status"`
			Enterprise       bool   `json:"enterprise"`
			Agent            *struct {
				McpConfig json.RawMessage `json:"mcp_config"`
			} `json:"agent"`
		} `json:"task"`
	}
	if err := json.Unmarshal(pRecorder.Body.Bytes(), &personal); err != nil {
		t.Fatalf("decode personal claim: %v", err)
	}
	if personal.Task == nil || personal.Task.ID != personalTaskID {
		t.Fatalf("personal task not claimed: %s", pRecorder.Body.String())
	}
	if personal.Task.ManagedMcpStatus != "" {
		t.Fatalf("personal task gained managed_mcp_status %q", personal.Task.ManagedMcpStatus)
	}
	if personal.Task.Enterprise {
		t.Fatal("personal task gained the enterprise marker")
	}
	if !strings.Contains(string(personal.Task.Agent.McpConfig), "oops") {
		t.Fatalf("personal fallback lost the agent config: %s", personal.Task.Agent.McpConfig)
	}
}

// personalTwinTask queues a task on the shared personal test workspace.
func personalTwinTask(t *testing.T) (taskID, agentID string) {
	t.Helper()
	agentID = dbfx.Agent(t, "personal twin agent "+t.Name(), testRuntimeID)
	issueID := dbfx.Issue(t, "personal twin issue "+t.Name())
	taskID = dbfx.Task(t, agentID, testutil.Cols{
		"runtime_id": testRuntimeID,
		"issue_id":   issueID,
		"status":     "queued",
	})
	return taskID, agentID
}

func TestEnterpriseBatchClaimRejectionList(t *testing.T) {
	f := newEnterpriseFixture(t)
	withGrantPlatform(t)

	// Old daemon: task refused, requeued, reported.
	req := newDaemonTokenRequest("POST", "/api/daemon/tasks/claim",
		map[string]any{"daemon_id": "ent-daemon", "runtime_ids": []string{f.runtimeID}, "max_tasks": 4},
		f.workspaceID, "ent-daemon")
	rec := httptest.NewRecorder()
	testHandler.ClaimTasksByRuntime(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("batch status = %d", rec.Code)
	}
	var out struct {
		Tasks                []json.RawMessage `json:"tasks"`
		EnterpriseRejections []struct {
			TaskID string `json:"task_id"`
			Reason string `json:"reason"`
		} `json:"enterprise_rejections"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode batch: %v", err)
	}
	if len(out.Tasks) != 0 {
		t.Fatalf("old daemon got %d enterprise tasks", len(out.Tasks))
	}
	if len(out.EnterpriseRejections) != 1 || out.EnterpriseRejections[0].Reason != "enterprise_protocol_required" {
		t.Fatalf("rejections = %+v", out.EnterpriseRejections)
	}
	if status := enterpriseTaskStatus(t, f.taskID); status != "queued" {
		t.Fatalf("refused enterprise task must be requeued, status = %q", status)
	}

	// Capable daemon with a valid lease gets the task.
	lease := signTestLease(t, testLeaseSecret, map[string]any{
		"sub": enterpriseTestSubject, "task_id": f.taskID, "runtime_id": f.runtimeID,
	})
	req = newDaemonTokenRequest("POST", "/api/daemon/tasks/claim",
		map[string]any{"daemon_id": "ent-daemon", "runtime_ids": []string{f.runtimeID}, "max_tasks": 4},
		f.workspaceID, "ent-daemon")
	req.Header.Set("X-Client-Capabilities", protocol.DaemonCapabilityEnterpriseProtocolV1)
	req.Header.Set("X-Enterprise-Lease", lease)
	rec = httptest.NewRecorder()
	testHandler.ClaimTasksByRuntime(rec, req)
	var ok struct {
		Tasks []struct {
			ID               string `json:"id"`
			ManagedMcpStatus string `json:"managed_mcp_status"`
		} `json:"tasks"`
		EnterpriseRejections []json.RawMessage `json:"enterprise_rejections"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &ok); err != nil {
		t.Fatalf("decode batch: %v", err)
	}
	if len(ok.Tasks) != 1 || ok.Tasks[0].ID != f.taskID {
		t.Fatalf("batch tasks = %+v (%s)", ok.Tasks, rec.Body.String())
	}
	if len(ok.EnterpriseRejections) != 0 {
		t.Fatalf("unexpected rejections: %s", ok.EnterpriseRejections)
	}
}

func TestEnterpriseInitiatorGate(t *testing.T) {
	f := newEnterpriseFixture(t)
	ctx := context.Background()

	if err := testHandler.enterpriseInitiatorGate(ctx, "member", f.personalID, parseUUID(f.workspaceID)); err == nil {
		t.Fatal("personal member must not start enterprise runs")
	}
	if err := testHandler.enterpriseInitiatorGate(ctx, "member", f.userID, parseUUID(f.workspaceID)); err != nil {
		t.Fatalf("enterprise member rejected: %v", err)
	}
	if err := testHandler.enterpriseInitiatorGate(ctx, "agent", f.agentID, parseUUID(f.workspaceID)); err == nil {
		t.Fatal("agent actor must not start enterprise runs")
	}
	// Personal workspace: anyone may dispatch.
	if err := testHandler.enterpriseInitiatorGate(ctx, "member", f.personalID, parseUUID(testWorkspaceID)); err != nil {
		t.Fatalf("personal workspace gated: %v", err)
	}
}

func TestEnterpriseRerunRejectedForPersonalMember(t *testing.T) {
	f := newEnterpriseFixture(t)
	req := withURLParam(httptest.NewRequest("POST", "/api/issues/"+f.issueID+"/rerun", strings.NewReader("{}")), "id", f.issueID)
	req.Header.Set("X-User-ID", f.personalID)
	req.Header.Set("X-Workspace-ID", f.workspaceID)
	rec := httptest.NewRecorder()
	testHandler.RerunIssue(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 (%s)", rec.Code, rec.Body.String())
	}
	if got := errorCode(t, rec.Body.String()); got != "enterprise_initiator_required" {
		t.Fatalf("code = %q", got)
	}

	// The enterprise member passes the gate (the service may still refuse the
	// rerun for its own reasons — but never with the initiator code).
	req = withURLParam(httptest.NewRequest("POST", "/api/issues/"+f.issueID+"/rerun", strings.NewReader("{}")), "id", f.issueID)
	req.Header.Set("X-User-ID", f.userID)
	req.Header.Set("X-Workspace-ID", f.workspaceID)
	rec = httptest.NewRecorder()
	testHandler.RerunIssue(rec, req)
	if got := errorCode(t, rec.Body.String()); got == "enterprise_initiator_required" {
		t.Fatalf("enterprise member hit the initiator gate: %s", rec.Body.String())
	}
}
