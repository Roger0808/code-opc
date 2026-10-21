package agent

import (
	"encoding/json"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// BND-162 managed execution parameters: the enterprise/personal matrix for
// the three CLIs this deployment ships (Claude, Codex, Kimi ACP). Every
// test here is adapter-level — argv and generated config content only, no
// real CLI is resolved or executed.

// argsContain (browser_mcp_config.go) provides substring flag detection for
// the whole package; argValue extracts the value of an exact two-token flag.

func argValue(args []string, flag string) (string, bool) {
	for i, a := range args {
		if a == flag && i+1 < len(args) {
			return args[i+1], true
		}
	}
	return "", false
}

// longLivedTokenPatterns matches credential material that must never ride
// enterprise argv or generated config: refresh tokens, OAuth bearer
// material, and well-known API-key shapes. Task-scoped mat_ tokens are
// deliberately absent — the task-level mat_ environment mechanism is the
// sanctioned carrier and stays legal.
var longLivedTokenPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)refresh[_-]?token`),
	regexp.MustCompile(`(?i)oauth[^\n]{0,20}secret`),
	regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{10,}\b`),
	regexp.MustCompile(`\bsk-(ant|proj)-[A-Za-z0-9_-]+`),
	regexp.MustCompile(`\bgh[pousr]_[A-Za-z0-9]{20,}`),
	regexp.MustCompile(`\bxox[baprs]-[A-Za-z0-9-]+`),
}

func assertNoLongLivedTokenMaterial(t *testing.T, label string, contents ...string) {
	t.Helper()
	for _, content := range contents {
		for _, re := range longLivedTokenPatterns {
			if loc := re.FindString(content); loc != "" {
				t.Fatalf("%s carries long-lived token material %q (pattern %s)", label, loc, re.String())
			}
		}
	}
}

func TestBuildClaudeArgsEnterpriseMatrix(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name         string
		opts         ExecOptions
		wantMode     string
		forbiddenArg string
	}{
		{
			name:     "personal keeps bypassPermissions",
			opts:     ExecOptions{},
			wantMode: "bypassPermissions",
		},
		{
			name:     "enterprise uses managed default",
			opts:     ExecOptions{Enterprise: true},
			wantMode: "default",
		},
		{
			name:     "enterprise config override wins",
			opts:     ExecOptions{Enterprise: true, EnterpriseClaudePermissionMode: "plan"},
			wantMode: "plan",
		},
		{
			name:         "enterprise rejects bypass override",
			opts:         ExecOptions{Enterprise: true, EnterpriseClaudePermissionMode: "bypassPermissions"},
			wantMode:     "default",
			forbiddenArg: "bypassPermissions",
		},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			args := buildClaudeArgs(tc.opts, slog.Default())
			mode, ok := argValue(args, "--permission-mode")
			if !ok || mode != tc.wantMode {
				t.Fatalf("--permission-mode = %q (ok=%v), want %q in %v", mode, ok, tc.wantMode, args)
			}
			if tc.forbiddenArg != "" {
				for _, a := range args {
					if a == tc.forbiddenArg {
						t.Fatalf("forbidden arg %q present in %v", tc.forbiddenArg, args)
					}
				}
			}
		})
	}
}

func TestBuildClaudeArgsEnterpriseBlocksBypassFlags(t *testing.T) {
	t.Parallel()

	custom := []string{"--dangerously-skip-permissions", "--permission-mode", "bypassPermissions"}

	personal := buildClaudeArgs(ExecOptions{CustomArgs: custom}, slog.Default())
	if mode, _ := argValue(personal, "--permission-mode"); mode != "bypassPermissions" {
		t.Fatalf("personal launch lost its managed bypass mode: %v", personal)
	}
	// Personal tasks keep the historical blocklist: the extra enterprise
	// bypass flags are scoped to enterprise launches so personal behavior
	// predating the integration is unchanged.
	if !argsContain(personal, "--dangerously-skip-permissions") {
		t.Fatalf("personal launch must keep its historical custom args: %v", personal)
	}

	enterprise := buildClaudeArgs(ExecOptions{Enterprise: true, CustomArgs: custom}, slog.Default())
	if argsContain(enterprise, "--dangerously-skip-permissions") {
		t.Fatalf("enterprise launch must drop --dangerously-skip-permissions: %v", enterprise)
	}
	if mode, _ := argValue(enterprise, "--permission-mode"); mode != "default" {
		t.Fatalf("enterprise --permission-mode = %q, want default (user bypass override dropped): %v", mode, enterprise)
	}

	// The --settings disabled-inherited-skills semantics are untouched:
	// when no settings path is set, no --settings flag appears.
	if argsContain(enterprise, "--settings") {
		t.Fatalf("enterprise launch without ClaudeSettingsPath must not gain --settings: %v", enterprise)
	}
}

func TestBuildClaudeArgsEnterpriseManagedMCPNoLongLivedTokens(t *testing.T) {
	t.Parallel()

	mcpConfig := json.RawMessage(`{"mcpServers":{"fetch":{"command":"npx","args":["-y","@modelcontextprotocol/server-fetch"]},"fs":{"command":"node","args":["/opt/mcp/fs.js"],"env":{"API_KEY":"mat_placeholder_task_scoped"}}}}`)
	opts := ExecOptions{Enterprise: true, McpConfig: mcpConfig}

	args := buildClaudeArgs(opts, slog.Default())
	if !argsContain(args, "--strict-mcp-config") {
		t.Fatalf("managed mcp-config must keep --strict-mcp-config: %v", args)
	}
	// The backend (not buildClaudeArgs) materialises the config and appends
	// --mcp-config <path>; mirror those two steps here so the scan covers
	// the generated file.
	mcpPath, err := writeMcpConfigToTemp(opts.McpConfig)
	if err != nil {
		t.Fatalf("writeMcpConfigToTemp: %v", err)
	}
	defer cleanupMcpConfigTemp(mcpPath)
	fullArgs := append(append([]string(nil), args...), "--mcp-config", mcpPath)

	data, err := os.ReadFile(mcpPath)
	if err != nil {
		t.Fatalf("read generated mcp-config: %v", err)
	}
	assertNoLongLivedTokenMaterial(t, "claude argv", strings.Join(fullArgs, " "))
	assertNoLongLivedTokenMaterial(t, "claude mcp-config", string(data))

	// Sanity: the scanner would have caught a refresh token had one been
	// generated — prove it is not a no-op.
	evil := strings.Replace(string(data), `"mat_placeholder_task_scoped"`, `"refresh_token_xyz"`, 1)
	if !regexp.MustCompile(`(?i)refresh[_-]?token`).MatchString(evil) {
		t.Fatal("scanner sanity check failed")
	}
}

func TestCodexThreadStartParamsEnterpriseMatrix(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name        string
		opts        ExecOptions
		wantPolicy  any // nil = inherit
		wantSandbox any
	}{
		{
			name: "personal inherits",
			opts: ExecOptions{},
		},
		{
			name:        "enterprise pins managed defaults",
			opts:        ExecOptions{Enterprise: true, CodexSandboxMode: "danger-full-access"},
			wantPolicy:  "untrusted",
			wantSandbox: "danger-full-access",
		},
		{
			name:        "enterprise policy override",
			opts:        ExecOptions{Enterprise: true, EnterpriseCodexApprovalPolicy: "on-failure", CodexSandboxMode: "workspace-write"},
			wantPolicy:  "on-failure",
			wantSandbox: "workspace-write",
		},
		{
			name:       "enterprise without resolved sandbox inherits task config",
			opts:       ExecOptions{Enterprise: true},
			wantPolicy: "untrusted",
		},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			params := codexThreadStartParams(tc.opts)
			if got := params["approvalPolicy"]; got != tc.wantPolicy {
				t.Fatalf("approvalPolicy = %v, want %v", got, tc.wantPolicy)
			}
			if got := params["sandbox"]; got != tc.wantSandbox {
				t.Fatalf("sandbox = %v, want %v", got, tc.wantSandbox)
			}
			// cwd/model contract unchanged.
			if _, ok := params["cwd"]; !ok {
				t.Fatalf("cwd missing from params: %v", params)
			}
		})
	}
}

func TestCodexHandleServerRequestEnterpriseNeverAutoAccepts(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name       string
		method     string
		params     string
		assertFunc func(t *testing.T, result map[string]any)
	}{
		{
			name:   "command execution denied",
			method: "item/commandExecution/requestApproval",
			assertFunc: func(t *testing.T, result map[string]any) {
				if result["decision"] != "reject" {
					t.Fatalf("decision = %v, want reject", result["decision"])
				}
			},
		},
		{
			name:   "legacy exec denied",
			method: "execCommandApproval",
			assertFunc: func(t *testing.T, result map[string]any) {
				if result["decision"] != "reject" {
					t.Fatalf("decision = %v, want reject", result["decision"])
				}
			},
		},
		{
			name:   "file change denied",
			method: "applyPatchApproval",
			assertFunc: func(t *testing.T, result map[string]any) {
				if result["decision"] != "reject" {
					t.Fatalf("decision = %v, want reject", result["decision"])
				}
			},
		},
		{
			name:   "permissions granted empty",
			method: "item/permissions/requestApproval",
			params: `{"permissions":{"network":{"enabled":true},"fileSystem":{"read":["/tmp"]}}}`,
			assertFunc: func(t *testing.T, result map[string]any) {
				perms, ok := result["permissions"].(map[string]any)
				if !ok || len(perms) != 0 {
					t.Fatalf("permissions = %v, want empty grant", result["permissions"])
				}
				if result["scope"] != "turn" {
					t.Fatalf("scope = %v, want turn", result["scope"])
				}
			},
		},
		{
			name:   "mcp elicitation denied",
			method: "mcpServer/elicitation/request",
			assertFunc: func(t *testing.T, result map[string]any) {
				if result["action"] != "reject" {
					t.Fatalf("action = %v, want reject", result["action"])
				}
			},
		},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			c, fs, _ := newTestCodexClient(t)
			c.enterprise = true

			line := `{"jsonrpc":"2.0","id":7,"method":"` + tc.method + `","params":` + tc.params + `}`
			if tc.params == "" {
				line = `{"jsonrpc":"2.0","id":7,"method":"` + tc.method + `","params":{}}`
			}
			c.handleLine(line)

			lines := fs.Lines()
			if len(lines) != 1 {
				t.Fatalf("responses = %d, want 1", len(lines))
			}
			var resp struct {
				ID     int            `json:"id"`
				Result map[string]any `json:"result"`
				Error  map[string]any `json:"error"`
			}
			if err := json.Unmarshal([]byte(lines[0]), &resp); err != nil {
				t.Fatalf("unmarshal: %v", err)
			}
			if resp.ID != 7 {
				t.Fatalf("id = %d, want 7", resp.ID)
			}
			tc.assertFunc(t, resp.Result)
		})
	}
}

func TestCodexManagedMcpConfigEnterpriseNoLongLivedTokens(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.toml")
	mcpConfig := json.RawMessage(`{"mcpServers":{"fetch":{"command":"npx","args":["-y","mcp-fetch"],"env":{"TOKEN":"mat_task_scoped"}}}}`)
	if err := ensureCodexMcpConfig(configPath, mcpConfig, slog.Default()); err != nil {
		t.Fatalf("ensureCodexMcpConfig: %v", err)
	}
	data, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("read config.toml: %v", err)
	}
	content := string(data)
	if !strings.Contains(content, "[mcp_servers.fetch]") {
		t.Fatalf("managed mcp_servers block missing: %s", content)
	}
	if !strings.Contains(content, `TOKEN = "mat_task_scoped"`) {
		t.Fatalf("managed env value missing: %s", content)
	}
	assertNoLongLivedTokenMaterial(t, "codex config.toml", content)
}

// TestACPPermissionEnterpriseMatrix pins the Kimi (shared hermesClient
// transport) permission policy for enterprise tasks: only an offered
// reject_once is selectable — never an allow kind, never a session grant —
// and a request offering no reject_once fails closed with a protocol error.
func TestACPPermissionEnterpriseMatrix(t *testing.T) {
	t.Parallel()

	grantingSelector := func(json.RawMessage) (string, bool, bool) { return "allow_once", true, true }

	cases := []struct {
		name         string
		options      string
		selectPerms  func(json.RawMessage) (string, bool, bool)
		wantOptionID string
		wantErr      bool
	}{
		{
			name:         "reject_once selected over allow_once",
			options:      `[{"optionId":"allow_once","kind":"allow_once"},{"optionId":"deny","kind":"reject_once"}]`,
			wantOptionID: "deny",
		},
		{
			name:         "session grant not selected",
			options:      `[{"optionId":"approve_for_session","kind":"allow_always"},{"optionId":"deny","kind":"reject_once"}]`,
			wantOptionID: "deny",
		},
		{
			name:         "allow_always only errors",
			options:      `[{"optionId":"allow_always","kind":"allow_always"}]`,
			wantErr:      true,
		},
		{
			name:         "allow_once only errors",
			options:      `[{"optionId":"allow_once","kind":"allow_once"}]`,
			wantErr:      true,
		},
		{
			name:         "dialect grant selector overridden",
			options:      `[{"optionId":"allow_once","kind":"allow_once"},{"optionId":"deny","kind":"reject_once"}]`,
			selectPerms:  grantingSelector,
			wantOptionID: "deny",
		},
		{
			name:         "malformed options errors",
			options:      `"not-an-array"`,
			wantErr:      true,
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			w := &bufferWriter{}
			c := &hermesClient{
				cfg:             Config{Logger: slog.Default()},
				stdin:           w,
				pending:         make(map[int]*pendingRPC),
				enterprise:      true,
				selectPermission: tc.selectPerms,
			}
			c.handleLine(`{"jsonrpc":"2.0","id":9,"method":"session/request_permission","params":{"sessionId":"s","options":` + tc.options + `}}`)

			var resp struct {
				ID     int `json:"id"`
				Result *struct {
					Outcome struct {
						Outcome  string `json:"outcome"`
						OptionID string `json:"optionId"`
					} `json:"outcome"`
				} `json:"result"`
				Error *struct {
					Code int `json:"code"`
				} `json:"error"`
			}
			if err := json.Unmarshal([]byte(strings.TrimSpace(w.String())), &resp); err != nil {
				t.Fatalf("reply is not valid JSON: %q", w.String())
			}
			if resp.ID != 9 {
				t.Fatalf("id = %d, want 9", resp.ID)
			}
			if tc.wantErr {
				if resp.Error == nil || resp.Result != nil {
					t.Fatalf("want protocol error only, got %+v", resp)
				}
				return
			}
			if resp.Result == nil || resp.Result.Outcome.OptionID != tc.wantOptionID {
				t.Fatalf("selected optionId = %+v, want %q", resp.Result, tc.wantOptionID)
			}
		})
	}
}

func TestSelectEnterpriseACPRejectOnly(t *testing.T) {
	t.Parallel()

	if id, grant, ok := selectEnterpriseACPRejectOnly(json.RawMessage(`{"options":[{"optionId":"a","kind":"allow_once"},{"optionId":"d","kind":"reject_once"}]}`)); !ok || grant || id != "d" {
		t.Fatalf("got (%q,%v,%v), want (d,false,true)", id, grant, ok)
	}
	if _, _, ok := selectEnterpriseACPRejectOnly(json.RawMessage(`{"options":[{"optionId":"a","kind":"allow_once"}]}`)); ok {
		t.Fatal("allow_once must not be selectable for enterprise")
	}
	if _, _, ok := selectEnterpriseACPRejectOnly(json.RawMessage(`{"options":[{"optionId":"s","kind":"allow_always"}]}`)); ok {
		t.Fatal("session grant must not be selectable for enterprise")
	}
	if _, _, ok := selectEnterpriseACPRejectOnly(nil); ok {
		t.Fatal("empty options must fail closed")
	}
}

// TestCodexEnterpriseManagedMcpNamespaceKept pins the BND-162 codex MCP
// contract for enterprise tasks: the daemon-owned mcp_servers namespace is
// still enforced — user `-c mcp_servers.*` overrides are stripped — and the
// managed block lands in config.toml.
func TestCodexEnterpriseManagedMcpNamespaceKept(t *testing.T) {
	t.Parallel()

	mcpConfig := json.RawMessage(`{"mcpServers":{"fetch":{"command":"npx","args":["-y","mcp-fetch"]}}}`)
	custom := []string{"-c", "mcp_servers.evil.command = \"rm -rf\"", "--profile", "enterprise"}

	args := NormalizeCodexLaunchArgs(nil, custom, mcpConfig, slog.Default())
	joined := strings.Join(args, " ")
	if strings.Contains(joined, "mcp_servers.evil") {
		t.Fatalf("user mcp_servers override must be stripped: %v", args)
	}
	if !argsContain(args, "--profile") {
		t.Fatalf("unrelated custom args must survive filtering: %v", args)
	}

	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.toml")
	if err := ensureCodexMcpConfig(configPath, mcpConfig, slog.Default()); err != nil {
		t.Fatalf("ensureCodexMcpConfig: %v", err)
	}
	data, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("read config.toml: %v", err)
	}
	if !strings.Contains(string(data), "[mcp_servers.fetch]") {
		t.Fatalf("managed block missing: %s", data)
	}
	assertNoLongLivedTokenMaterial(t, "codex enterprise config.toml", string(data))
}

func TestKimiCmdEnvEnterpriseIsolatesHome(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	base := map[string]string{"PATH": "/usr/bin", "KIMI_CODE_HOME": "/home/user/.kimi-code"}

	personal, err := kimiCmdEnv(base, dir, false)
	if err != nil {
		t.Fatalf("personal env: %v", err)
	}
	if personal["KIMI_CODE_HOME"] != "/home/user/.kimi-code" {
		t.Fatalf("personal launch must inherit ambient KIMI_CODE_HOME: %v", personal)
	}

	ent, err := kimiCmdEnv(base, dir, true)
	if err != nil {
		t.Fatalf("enterprise env: %v", err)
	}
	want := filepath.Join(dir, ".multica-isolated-kimi-home")
	if ent["KIMI_CODE_HOME"] != want {
		t.Fatalf("enterprise KIMI_CODE_HOME = %q, want %q", ent["KIMI_CODE_HOME"], want)
	}
	if _, err := os.Stat(want); err != nil {
		t.Fatalf("isolated home not created: %v", err)
	}
	if base["KIMI_CODE_HOME"] != "/home/user/.kimi-code" {
		t.Fatalf("shared cfg.Env mutated: %v", base)
	}
	// The isolated home has no mcp.json for `kimi acp` to natively merge.
	if _, err := os.Stat(filepath.Join(want, "mcp.json")); !os.IsNotExist(err) {
		t.Fatalf("isolated home must not carry an mcp.json: %v", err)
	}
}
