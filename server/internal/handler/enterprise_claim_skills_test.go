package handler

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/multica-ai/multica/server/internal/enterprise"
	"github.com/multica-ai/multica/server/internal/platform"
	"github.com/multica-ai/multica/server/internal/testutil"
	"github.com/multica-ai/multica/server/pkg/protocol"
)

// Claim-time enterprise SkillRef issuance (TASK-C06). The fake platform
// speaks both halves of the contract the claim now consumes: the internal
// skills listing (subject + tenant entitlement view) and the INT-142 pinned
// download. Together with the resolve tests in daemon_enterprise_skills_test.go
// these cover the full chain: listing -> claim refs -> pinned resolve.

// fakeListingPlatform serves GET /integration/v1/internal/skills from a
// canned envelope and delegates downloads to the INT-142 fake. It records
// the listing's subject/tenant query so tests can assert the entitlement
// scoping.
type fakeListingPlatform struct {
	mu           sync.Mutex
	status       int
	envelope     map[string]any
	listSubjects []string
	listTenants  []string
	downloads    *fakeSkillPlatform
}

func (f *fakeListingPlatform) handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/integration/v1/internal/grants" && r.Method == http.MethodPost {
			var req struct {
				Subject   string `json:"subject"`
				TenantID  string `json:"tenant_id"`
				TaskID    string `json:"task_id"`
				RuntimeID string `json:"runtime_id"`
			}
			_ = json.NewDecoder(r.Body).Decode(&req)
			lease := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
				"grant_id":   "grant-test-1",
				"sub":        req.Subject,
				"tenant_id":  req.TenantID,
				"task_id":    req.TaskID,
				"runtime_id": req.RuntimeID,
				"exp":        time.Now().Add(30 * time.Second).Unix(),
			})
			signed, err := lease.SignedString([]byte(testLeaseSecret))
			if err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"grant_id":         "grant-test-1",
				"lease_token":      signed,
				"lease_expires_at": time.Now().Add(30 * time.Second).UTC().Format(time.RFC3339),
			})
			return
		}
		if r.URL.Path == "/integration/v1/internal/skills" {
			f.mu.Lock()
			f.listSubjects = append(f.listSubjects, r.URL.Query().Get("subject"))
			tenant := r.URL.Query().Get("tenant")
			f.listTenants = append(f.listTenants, tenant)
			status, envelope := f.status, f.envelope
			f.mu.Unlock()
			if status == 0 {
				status = http.StatusOK
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(status)
			_ = json.NewEncoder(w).Encode(envelope)
			return
		}
		f.downloads.handler().ServeHTTP(w, r)
	})
}

func (f *fakeListingPlatform) lastListingQuery() (string, string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.listSubjects) == 0 {
		return "", ""
	}
	i := len(f.listSubjects) - 1
	return f.listSubjects[i], f.listTenants[i]
}

// withClaimSkillPlatform installs a platform client + enterprise skill
// resolver pointed at the given handler, restoring both afterwards.
func withClaimSkillPlatform(t *testing.T, handler http.Handler) {
	t.Helper()
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	client, err := platform.New(platform.Config{
		BaseURL:         server.URL,
		ServiceToken:    "svc",
		LeaseHMACSecret: testLeaseSecret,
		Issuer:          "issuer-test",
		HTTPClient:      server.Client(),
	})
	if err != nil {
		t.Fatalf("platform.New: %v", err)
	}
	resolver, err := enterprise.NewResolver(client, t.TempDir())
	if err != nil {
		t.Fatalf("NewResolver: %v", err)
	}
	prevPlatform, prevResolver := testHandler.Platform, testHandler.EnterpriseSkillResolver
	testHandler.Platform = client
	testHandler.EnterpriseSkillResolver = resolver
	t.Cleanup(func() {
		testHandler.Platform = prevPlatform
		testHandler.EnterpriseSkillResolver = prevResolver
	})
}

type claimSkillRef struct {
	Source  string `json:"source"`
	ID      string `json:"id"`
	Name    string `json:"name"`
	Version string `json:"version"`
	Hash    string `json:"hash"`
}

type claimSkillsResponse struct {
	Task *struct {
		EnterpriseSkillsStatus string          `json:"enterprise_skills_status"`
		EnterpriseSkills       []claimSkillRef `json:"enterprise_skills"`
		Enterprise             bool            `json:"enterprise"`
		ManagedMcpStatus       string          `json:"managed_mcp_status"`
	} `json:"task"`
}

func claimEnterpriseSkills(t *testing.T, f *enterpriseFixture, leaseTenant string) *claimSkillsResponse {
	t.Helper()
	claims := map[string]any{
		"sub": enterpriseTestSubject, "task_id": f.taskID, "runtime_id": f.runtimeID,
	}
	if leaseTenant != "" {
		claims["tenant_id"] = leaseTenant
	}
	lease := signTestLease(t, testLeaseSecret, claims)
	rec := testutil.Call(t, testHandler.ClaimTaskByRuntime,
		enterpriseClaimRequest(t, f, protocol.DaemonCapabilityEnterpriseProtocolV1, lease))
	if rec.Code != http.StatusOK {
		t.Fatalf("claim status = %d (%s)", rec.Code, rec.Body.String())
	}
	var out claimSkillsResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode claim: %v (%s)", err, rec.Body.String())
	}
	if out.Task == nil {
		t.Fatalf("no task in claim response: %s", rec.Body.String())
	}
	return &out
}

func listingEnvelope(entries ...map[string]any) map[string]any {
	return map[string]any{"skills": entries}
}

func manifestEntry(publishID, name, version, pin string) map[string]any {
	return map[string]any{
		"publish_id": publishID,
		"name":       name,
		"version":    version,
		"manifest":   map[string]string{"sha256": pin},
	}
}

func TestEnterpriseClaimIssuesPinnedSkillRefs(t *testing.T) {
	if testHandler == nil || testPool == nil {
		t.Skip("database not available")
	}
	f := newEnterpriseFixture(t)
	dbfx.Exec(t, `UPDATE enterprise_workspace_link SET platform_tenant = 'tenant-a' WHERE workspace_id = $1`, f.workspaceID)

	body, pin := buildEntSkillPackage(t, "pub-deploy", validEntSkillSpec())
	fake := &fakeListingPlatform{
		envelope: listingEnvelope(manifestEntry("pub-deploy", "deploy", "1.2.3", strings.TrimPrefix(pin, "sha256:"))),
		downloads: &fakeSkillPlatform{pkgs: map[string][]byte{
			"pub-deploy|" + strings.TrimPrefix(pin, "sha256:"): body,
		}},
	}
	withClaimSkillPlatform(t, fake.handler())

	out := claimEnterpriseSkills(t, f, "tenant-a")
	if out.Task.EnterpriseSkillsStatus != "ok" {
		t.Fatalf("status = %q (%v)", out.Task.EnterpriseSkillsStatus, out.Task.EnterpriseSkills)
	}
	if len(out.Task.EnterpriseSkills) != 1 {
		t.Fatalf("refs = %+v", out.Task.EnterpriseSkills)
	}
	ref := out.Task.EnterpriseSkills[0]
	if ref.Source != enterprise.Source || ref.ID != "pub-deploy" {
		t.Fatalf("ref identity = %+v", ref)
	}
	if ref.Hash != pin {
		t.Fatalf("ref hash = %q, want the platform manifest pin %q", ref.Hash, pin)
	}
	if ref.Name != "deploy" || ref.Version != "1.2.3" {
		t.Fatalf("ref metadata = %+v", ref)
	}

	// The listing is scoped by the originating user's subject and the lease
	// tenant, never by daemon-supplied input.
	subject, tenant := fake.lastListingQuery()
	if subject != enterpriseTestSubject || tenant != "tenant-a" {
		t.Fatalf("listing query = (%q, %q)", subject, tenant)
	}
}

func TestEnterpriseClaimSkillsAllTenantsWhenLeaseHasNoTenant(t *testing.T) {
	if testHandler == nil || testPool == nil {
		t.Skip("database not available")
	}
	f := newEnterpriseFixture(t)
	fake := &fakeListingPlatform{envelope: listingEnvelope()}
	withClaimSkillPlatform(t, fake.handler())

	out := claimEnterpriseSkills(t, f, "")
	if out.Task.EnterpriseSkillsStatus != "empty" {
		t.Fatalf("status = %q, want empty", out.Task.EnterpriseSkillsStatus)
	}
	if len(out.Task.EnterpriseSkills) != 0 {
		t.Fatalf("refs = %+v, want none", out.Task.EnterpriseSkills)
	}
	subject, tenant := fake.lastListingQuery()
	if subject != enterpriseTestSubject || tenant != "" {
		t.Fatalf("listing query = (%q, %q), want subject with no tenant", subject, tenant)
	}
}

func TestEnterpriseClaimSkillsEmptyListing(t *testing.T) {
	if testHandler == nil || testPool == nil {
		t.Skip("database not available")
	}
	f := newEnterpriseFixture(t)
	fake := &fakeListingPlatform{envelope: listingEnvelope()}
	withClaimSkillPlatform(t, fake.handler())

	out := claimEnterpriseSkills(t, f, "tenant-a")
	if out.Task.EnterpriseSkillsStatus != "empty" || len(out.Task.EnterpriseSkills) != 0 {
		t.Fatalf("empty listing => status %q refs %+v", out.Task.EnterpriseSkillsStatus, out.Task.EnterpriseSkills)
	}
}

func TestEnterpriseClaimSkillsUnavailableNeverBlocksClaim(t *testing.T) {
	if testHandler == nil || testPool == nil {
		t.Skip("database not available")
	}
	cases := []struct {
		name    string
		status  int
		handler http.Handler
	}{
		{"platform 404", http.StatusNotFound, nil},
		{"platform 500", http.StatusInternalServerError, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newEnterpriseFixture(t)
			fake := &fakeListingPlatform{status: tc.status, envelope: map[string]any{"error": "boom"}}
			withClaimSkillPlatform(t, fake.handler())

			out := claimEnterpriseSkills(t, f, "tenant-a")
			if out.Task.EnterpriseSkillsStatus != "unavailable" {
				t.Fatalf("status = %q, want unavailable", out.Task.EnterpriseSkillsStatus)
			}
			if len(out.Task.EnterpriseSkills) != 0 {
				t.Fatalf("refs = %+v, want none", out.Task.EnterpriseSkills)
			}
			// The claim itself is untouched: enterprise marker on, and the
			// fixture agent's NULL mcp_config keeps its failed_closed MCP
			// outcome regardless of the platform listing failure.
			if !out.Task.Enterprise || out.Task.ManagedMcpStatus != "failed_closed" {
				t.Fatalf("claim degraded elsewhere: enterprise=%v mcp=%q", out.Task.Enterprise, out.Task.ManagedMcpStatus)
			}
		})
	}

	t.Run("platform unreachable", func(t *testing.T) {
		f := newEnterpriseFixture(t)
		withTestPlatform(t, "http://platform.invalid", testLeaseSecret)
		// Lease 是企业任务的硬门槛（BND-102）：平台整体不可达时无法签发
		// 租约，claim 必须失败关闭（403 enterprise_lease_unavailable），
		// 任务被 requeue——与"listing 不可用不阻断 claim"是两个层级。
		rec := testutil.Call(t, testHandler.ClaimTaskByRuntime, enterpriseClaimRequest(t, f, protocol.DaemonCapabilityEnterpriseProtocolV1, ""))
		if rec.Code != http.StatusForbidden || errorCode(t, rec.Body.String()) != "enterprise_lease_unavailable" {
			t.Fatalf("claim = %d (%s), want 403 enterprise_lease_unavailable", rec.Code, rec.Body.String())
		}
		if status := enterpriseTaskStatus(t, f.taskID); status != "queued" {
			t.Fatalf("refused enterprise task must be requeued, status = %q", status)
		}
	})
}

func TestEnterpriseClaimSkillsSkipsUnpinnableEntries(t *testing.T) {
	if testHandler == nil || testPool == nil {
		t.Skip("database not available")
	}

	// One good entry, one whose digest is not a sha256 pin: only the good
	// one is issued, and the claim still reports ok.
	t.Run("skips the broken entry", func(t *testing.T) {
		f := newEnterpriseFixture(t)
		body, pin := buildEntSkillPackage(t, "pub-deploy", validEntSkillSpec())
		fake := &fakeListingPlatform{
			envelope: listingEnvelope(
				manifestEntry("pub-deploy", "deploy", "1.0.0", strings.TrimPrefix(pin, "sha256:")),
				manifestEntry("pub-broken", "broken", "1.0.0", "not-a-digest"),
			),
			downloads: &fakeSkillPlatform{pkgs: map[string][]byte{
				"pub-deploy|" + strings.TrimPrefix(pin, "sha256:"): body,
			}},
		}
		withClaimSkillPlatform(t, fake.handler())

		out := claimEnterpriseSkills(t, f, "tenant-a")
		if out.Task.EnterpriseSkillsStatus != "ok" || len(out.Task.EnterpriseSkills) != 1 ||
			out.Task.EnterpriseSkills[0].ID != "pub-deploy" {
			t.Fatalf("status/refs = %q %+v", out.Task.EnterpriseSkillsStatus, out.Task.EnterpriseSkills)
		}
	})

	// Every entry unpinnable: the listing lied, so the claim fails closed
	// into unavailable rather than advertising an empty skill set.
	t.Run("all broken becomes unavailable", func(t *testing.T) {
		f := newEnterpriseFixture(t)
		fake := &fakeListingPlatform{
			envelope: listingEnvelope(manifestEntry("pub-broken", "broken", "1.0.0", "not-a-digest")),
		}
		withClaimSkillPlatform(t, fake.handler())

		out := claimEnterpriseSkills(t, f, "tenant-a")
		if out.Task.EnterpriseSkillsStatus != "unavailable" || len(out.Task.EnterpriseSkills) != 0 {
			t.Fatalf("all-broken listing => status %q refs %+v", out.Task.EnterpriseSkillsStatus, out.Task.EnterpriseSkills)
		}
	})
}

func TestEnterpriseClaimPersonalTaskOmitsEnterpriseSkills(t *testing.T) {
	if testHandler == nil || testPool == nil {
		t.Skip("database not available")
	}
	personalTaskID, _ := personalTwinTask(t)
	fake := &fakeListingPlatform{envelope: listingEnvelope(manifestEntry("pub-x", "x", "1", "ab"))}
	withClaimSkillPlatform(t, fake.handler())

	req := newDaemonTokenRequest("POST", "/api/daemon/runtimes/"+testRuntimeID+"/tasks/claim", nil,
		testWorkspaceID, "personal-daemon")
	req = withURLParam(req, "runtimeId", testRuntimeID)
	rec := testutil.Call(t, testHandler.ClaimTaskByRuntime, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("personal claim status = %d (%s)", rec.Code, rec.Body.String())
	}
	var raw struct {
		Task map[string]json.RawMessage `json:"task"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &raw); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if raw.Task == nil {
		t.Fatalf("no task claimed: %s", rec.Body.String())
	}
	var id string
	_ = json.Unmarshal(raw.Task["id"], &id)
	if id != personalTaskID {
		t.Fatalf("claimed task = %q, want %q", id, personalTaskID)
	}
	if _, ok := raw.Task["enterprise_skills"]; ok {
		t.Fatal("personal task gained enterprise_skills")
	}
	if _, ok := raw.Task["enterprise_skills_status"]; ok {
		t.Fatal("personal task gained enterprise_skills_status")
	}
	if len(fake.listSubjects) != 0 {
		t.Fatalf("personal claim must not list platform skills, got %v", fake.listSubjects)
	}
}

// TestEnterpriseClaimRefsDrivePinnedResolve is the TASK-C06 end-to-end: the
// refs the claim issues resolve through the pinned-version path against the
// same fake platform, byte-for-byte the BND-142 contract.
func TestEnterpriseClaimRefsDrivePinnedResolve(t *testing.T) {
	if testHandler == nil || testPool == nil {
		t.Skip("database not available")
	}
	f := newEnterpriseFixture(t)
	body, pin := buildEntSkillPackage(t, "pub-deploy", validEntSkillSpec())
	fake := &fakeListingPlatform{
		envelope: listingEnvelope(manifestEntry("pub-deploy", "deploy", "2.0.0", strings.TrimPrefix(pin, "sha256:"))),
		downloads: &fakeSkillPlatform{pkgs: map[string][]byte{
			"pub-deploy|" + strings.TrimPrefix(pin, "sha256:"): body,
		}},
	}
	withClaimSkillPlatform(t, fake.handler())

	out := claimEnterpriseSkills(t, f, "tenant-a")
	if out.Task.EnterpriseSkillsStatus != "ok" || len(out.Task.EnterpriseSkills) != 1 {
		t.Fatalf("claim did not issue the platform ref: %q %+v", out.Task.EnterpriseSkillsStatus, out.Task.EnterpriseSkills)
	}
	issued := out.Task.EnterpriseSkills[0]

	dispatchEnterpriseTask(t, f.taskID)
	var resp entResolveResponse
	enterpriseResolve(t, f, resolveSkillBundleRef{ID: issued.ID, Source: issued.Source, Hash: issued.Hash}).
		Want(http.StatusOK).JSON(&resp)

	if len(resp.Bundles) != 1 || resp.Bundles[0].ID != "pub-deploy" || resp.Bundles[0].Source != enterprise.Source {
		t.Fatalf("bundles = %+v", resp.Bundles)
	}
	if resp.Bundles[0].Hash != pin {
		t.Fatalf("bundle hash = %q, want the issued pin %q", resp.Bundles[0].Hash, pin)
	}
	if len(resp.Status) != 1 || resp.Status[0].Status != "ok" {
		t.Fatalf("status = %+v", resp.Status)
	}
}
