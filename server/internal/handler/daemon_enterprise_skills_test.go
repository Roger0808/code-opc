package handler

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/multica-ai/multica/server/internal/enterprise"
	"github.com/multica-ai/multica/server/internal/platform"
	"github.com/multica-ai/multica/server/internal/service"
	"github.com/multica-ai/multica/server/internal/testutil"
	"github.com/multica-ai/multica/server/pkg/skillbundle"
)

// Enterprise skill bundle resolution through ResolveTaskSkillBundles
// (TASK-C03, BND-142). The fake platform speaks the INT-142 download
// contract over HTTP, so these tests cover the full server path: ref ->
// five-tuple context -> platform download -> pin validation -> response
// annotation.

type entSkillSpec struct {
	name     string
	content  string
	execMode string
	clients  []string
}

func buildEntSkillPackage(t *testing.T, publishID string, spec entSkillSpec) ([]byte, string) {
	t.Helper()
	payload, err := json.Marshal(map[string]any{
		"name":        spec.name,
		"description": spec.name + " description",
		"content":     spec.content,
	})
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}
	payloadDigest := sha256.Sum256(payload)
	manifest, err := json.Marshal(map[string]any{
		"exec_mode":      spec.execMode,
		"clients":        spec.clients,
		"payload_digest": "sha256:" + hex.EncodeToString(payloadDigest[:]),
	})
	if err != nil {
		t.Fatalf("marshal manifest: %v", err)
	}
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for name, body := range map[string]string{
		"opc-client.json": string(manifest),
		"skill.json":      string(payload),
	} {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatalf("zip create: %v", err)
		}
		if _, err := w.Write([]byte(body)); err != nil {
			t.Fatalf("zip write: %v", err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("zip close: %v", err)
	}
	skill := skillbundle.Skill{ID: publishID, Source: enterprise.Source, Name: spec.name, Description: spec.name + " description", Content: spec.content}
	return buf.Bytes(), skillbundle.BuildManifest(skill).Hash
}

// fakeSkillPlatform is an INT-142 download endpoint. Packages are keyed by
// publishID+"|"+pin; latest optionally serves one revision for any pin
// (a platform that ignores the pin), which the fixed-version resolver must
// never pass through under an old pin.
type fakeSkillPlatform struct {
	mu       sync.Mutex
	pkgs     map[string][]byte
	latest   map[string][]byte
	calls    []string
	serve404 bool
}

func (f *fakeSkillPlatform) handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		prefix := "/integration/v1/skills/"
		if !strings.HasPrefix(r.URL.Path, prefix) || !strings.HasSuffix(r.URL.Path, "/download") {
			http.NotFound(w, r)
			return
		}
		publishID := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, prefix), "/download")
		pin := r.URL.Query().Get("sha256")
		f.mu.Lock()
		f.calls = append(f.calls, publishID+"|"+pin)
		f.mu.Unlock()
		body, ok := f.pkgs[publishID+"|"+pin]
		if !ok {
			body, ok = f.latest[publishID]
		}
		if !ok || f.serve404 {
			w.WriteHeader(http.StatusNotFound)
			_ = json.NewEncoder(w).Encode(map[string]string{"code": "REVISION_NOT_FOUND", "message": "pinned revision gone"})
			return
		}
		digest := sha256.Sum256(body)
		w.Header().Set("X-SHA256", hex.EncodeToString(digest[:]))
		_, _ = w.Write(body)
	})
}

func (f *fakeSkillPlatform) callCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.calls)
}

// withEnterpriseSkillPlatform installs a platform client + enterprise skill
// resolver pointed at the fake platform, restoring both afterwards.
func withEnterpriseSkillPlatform(t *testing.T, fake *fakeSkillPlatform) {
	t.Helper()
	server := httptest.NewServer(fake.handler())
	t.Cleanup(server.Close)
	client, err := platform.New(platform.Config{
		BaseURL:         server.URL,
		ServiceToken:    "svc",
		LeaseHMACSecret: testLeaseSecret,
		Issuer:          "issuer-test",
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

func dispatchEnterpriseTask(t *testing.T, taskID string) {
	t.Helper()
	dbfx.Exec(t, `UPDATE agent_task_queue SET status = 'dispatched', dispatched_at = now() WHERE id = $1`, taskID)
}

// issueEnterpriseSkillRefs records the claim-issued enterprise skill set on
// the task row the way FinalizeTaskClaim does (M-5): only refs in this set
// resolve. Tests that drive the resolve endpoint directly (without a real
// claim) must declare their issued set here first.
func issueEnterpriseSkillRefs(t *testing.T, taskID string, refs ...resolveSkillBundleRef) {
	t.Helper()
	payload, err := json.Marshal(refs)
	if err != nil {
		t.Fatalf("marshal issued refs: %v", err)
	}
	dbfx.Exec(t, `UPDATE agent_task_queue
		SET context = jsonb_set(COALESCE(context, '{}'::jsonb), '{enterprise_skills_issued}', $2::jsonb, true)
		WHERE id = $1`, taskID, string(payload))
}

func enterpriseResolve(t *testing.T, f *enterpriseFixture, refs ...resolveSkillBundleRef) *testutil.Response {
	t.Helper()
	req := newDaemonTokenRequest("POST",
		"/api/daemon/runtimes/"+f.runtimeID+"/tasks/"+f.taskID+"/skill-bundles/resolve",
		resolveSkillBundlesRequest{Skills: refs}, f.workspaceID, "ent-daemon")
	req = withURLParams(req, "runtimeId", f.runtimeID, "taskId", f.taskID)
	return testutil.Call(t, testHandler.ResolveTaskSkillBundles, req)
}

func validEntSkillSpec() entSkillSpec {
	return entSkillSpec{name: "deploy", content: "deploy instructions", execMode: enterprise.ExecModeLocalInstruction, clients: []string{"code"}}
}

type entResolveResponse struct {
	Bundles []service.AgentSkillData `json:"bundles"`
	Status  []struct {
		ID           string `json:"id"`
		Status       string `json:"status"`
		Code         string `json:"code"`
		PinnedSHA256 string `json:"pinned_sha256"`
	} `json:"enterprise_skill_status"`
}

func TestEnterpriseSkillResolvePinnedVersion(t *testing.T) {
	if testHandler == nil || testPool == nil {
		t.Skip("database not available")
	}
	f := newEnterpriseFixture(t)
	fake := &fakeSkillPlatform{}
	body, pin := buildEntSkillPackage(t, "pub-deploy", validEntSkillSpec())
	fake.pkgs = map[string][]byte{"pub-deploy|" + strings.TrimPrefix(pin, "sha256:"): body}
	withEnterpriseSkillPlatform(t, fake)
	dispatchEnterpriseTask(t, f.taskID)
	issueEnterpriseSkillRefs(t, f.taskID, resolveSkillBundleRef{ID: "pub-deploy", Source: enterprise.Source, Hash: pin})

	var resp entResolveResponse
	enterpriseResolve(t, f, resolveSkillBundleRef{ID: "pub-deploy", Source: enterprise.Source, Hash: pin}).
		Want(http.StatusOK).JSON(&resp)

	if len(resp.Bundles) != 1 {
		t.Fatalf("bundles = %+v", resp.Bundles)
	}
	bundle := resp.Bundles[0]
	if bundle.ID != "pub-deploy" || bundle.Source != enterprise.Source {
		t.Fatalf("bundle identity = %+v", bundle)
	}
	if bundle.Name != "deploy" || bundle.Content != "deploy instructions" {
		t.Fatalf("bundle content = %+v", bundle)
	}
	if bundle.Hash != pin {
		t.Fatalf("bundle hash = %q, want the pin %q", bundle.Hash, pin)
	}
	if len(resp.Status) != 1 || resp.Status[0].Status != "ok" || resp.Status[0].PinnedSHA256 != strings.TrimPrefix(pin, "sha256:") {
		t.Fatalf("status = %+v", resp.Status)
	}

	// The second resolve is served from the server-side five-tuple cache.
	enterpriseResolve(t, f, resolveSkillBundleRef{ID: "pub-deploy", Source: enterprise.Source, Hash: pin}).
		Want(http.StatusOK).JSON(&resp)
	if fake.callCount() != 1 {
		t.Fatalf("platform calls = %d, want 1 (pinned cache must absorb the retry)", fake.callCount())
	}
}

func TestEnterpriseSkillResolveHashMismatch422(t *testing.T) {
	if testHandler == nil || testPool == nil {
		t.Skip("database not available")
	}
	f := newEnterpriseFixture(t)
	fake := &fakeSkillPlatform{}
	_, oldPin := buildEntSkillPackage(t, "pub-deploy", validEntSkillSpec())
	specV2 := validEntSkillSpec()
	specV2.content = "deploy instructions v2"
	bodyV2, _ := buildEntSkillPackage(t, "pub-deploy", specV2)
	// The platform ignores the pin and always serves the current revision.
	fake.latest = map[string][]byte{"pub-deploy": bodyV2}
	withEnterpriseSkillPlatform(t, fake)
	dispatchEnterpriseTask(t, f.taskID)
	issueEnterpriseSkillRefs(t, f.taskID, resolveSkillBundleRef{ID: "pub-deploy", Source: enterprise.Source, Hash: oldPin})

	rec := enterpriseResolve(t, f, resolveSkillBundleRef{ID: "pub-deploy", Source: enterprise.Source, Hash: oldPin})
	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status = %d, want 422 (%s)", rec.Code, rec.Body.String())
	}
	if got := errorCode(t, rec.Body.String()); got != enterprise.CodeHashMismatch {
		t.Fatalf("code = %q, want %q", got, enterprise.CodeHashMismatch)
	}
}

func TestEnterpriseSkillResolveCloudOnlyFailedClosed(t *testing.T) {
	if testHandler == nil || testPool == nil {
		t.Skip("database not available")
	}
	f := newEnterpriseFixture(t)
	fake := &fakeSkillPlatform{}
	cloudSpec := validEntSkillSpec()
	cloudSpec.execMode = enterprise.ExecModeCloudOnly
	cloudBody, cloudPin := buildEntSkillPackage(t, "pub-cloud", cloudSpec)
	goodBody, goodPin := buildEntSkillPackage(t, "pub-good", validEntSkillSpec())
	fake.pkgs = map[string][]byte{
		"pub-cloud|" + strings.TrimPrefix(cloudPin, "sha256:"): cloudBody,
		"pub-good|" + strings.TrimPrefix(goodPin, "sha256:"):   goodBody,
	}
	withEnterpriseSkillPlatform(t, fake)
	dispatchEnterpriseTask(t, f.taskID)
	issueEnterpriseSkillRefs(t, f.taskID,
		resolveSkillBundleRef{ID: "pub-cloud", Source: enterprise.Source, Hash: cloudPin},
		resolveSkillBundleRef{ID: "pub-good", Source: enterprise.Source, Hash: goodPin})

	var resp entResolveResponse
	enterpriseResolve(t, f,
		resolveSkillBundleRef{ID: "pub-cloud", Source: enterprise.Source, Hash: cloudPin},
		resolveSkillBundleRef{ID: "pub-good", Source: enterprise.Source, Hash: goodPin},
	).Want(http.StatusOK).JSON(&resp)

	// The cloud_only skill is dropped with a failed-closed status while the
	// legal skill still resolves: the task continues with the rest.
	if len(resp.Bundles) != 1 || resp.Bundles[0].ID != "pub-good" {
		t.Fatalf("bundles = %+v", resp.Bundles)
	}
	if len(resp.Status) != 2 {
		t.Fatalf("status = %+v", resp.Status)
	}
	byID := map[string]string{}
	for _, st := range resp.Status {
		byID[st.ID] = st.Status + ":" + st.Code
	}
	if got := byID["pub-cloud"]; got != "failed_closed:"+enterprise.CodeManifestInvalid {
		t.Fatalf("cloud status = %q", got)
	}
	if got := byID["pub-good"]; !strings.HasPrefix(got, "ok:") {
		t.Fatalf("good status = %q", got)
	}
}

func TestEnterpriseSkillResolveTenantIsolation(t *testing.T) {
	if testHandler == nil || testPool == nil {
		t.Skip("database not available")
	}
	f := newEnterpriseFixture(t)
	dbfx.Exec(t, `UPDATE enterprise_workspace_link SET platform_tenant = 'tenant-a' WHERE workspace_id = $1`, f.workspaceID)

	fake := &fakeSkillPlatform{}
	body, pin := buildEntSkillPackage(t, "pub-deploy", validEntSkillSpec())
	fake.pkgs = map[string][]byte{"pub-deploy|" + strings.TrimPrefix(pin, "sha256:"): body}
	withEnterpriseSkillPlatform(t, fake)
	dispatchEnterpriseTask(t, f.taskID)
	issueEnterpriseSkillRefs(t, f.taskID, resolveSkillBundleRef{ID: "pub-deploy", Source: enterprise.Source, Hash: pin})

	ref := resolveSkillBundleRef{ID: "pub-deploy", Source: enterprise.Source, Hash: pin}
	var resp entResolveResponse
	enterpriseResolve(t, f, ref).Want(http.StatusOK).JSON(&resp)
	if fake.callCount() != 1 {
		t.Fatalf("platform calls = %d, want 1", fake.callCount())
	}

	// Same workspace, same publish_id and pin, but the link's tenant moved
	// (a re-exchange refresh): the cache key's tenant segment changed, so
	// the platform is consulted again instead of the other tenant's entry
	// being served.
	dbfx.Exec(t, `UPDATE enterprise_workspace_link SET platform_tenant = 'tenant-b' WHERE workspace_id = $1`, f.workspaceID)
	enterpriseResolve(t, f, ref).Want(http.StatusOK).JSON(&resp)
	if fake.callCount() != 2 {
		t.Fatalf("platform calls = %d, want 2 after the tenant segment changed", fake.callCount())
	}
}

func TestEnterpriseSkillResolvePersonalTaskFailsClosed(t *testing.T) {
	if testHandler == nil || testPool == nil {
		t.Skip("database not available")
	}
	// A personal workspace (no enterprise link) keeps the historical
	// behavior: an enterprise ref has no server-side producer and resolves
	// to nothing, even when a platform client is configured.
	ctx := context.Background()
	runtimeID := createClaimReclaimRuntime(t, ctx, "entskillpersonal runtime")
	agentID, issueID := createClaimReclaimAgentAndIssue(t, ctx, runtimeID, "entskillpersonal agent")
	taskID := dbfx.Task(t, agentID, testutil.Cols{
		"runtime_id": runtimeID, "issue_id": issueID, "status": "dispatched",
		"dispatched_at": testutil.Raw("now()"),
	})

	fake := &fakeSkillPlatform{}
	body, pin := buildEntSkillPackage(t, "pub-deploy", validEntSkillSpec())
	fake.pkgs = map[string][]byte{"pub-deploy|" + strings.TrimPrefix(pin, "sha256:"): body}
	withEnterpriseSkillPlatform(t, fake)

	req := newDaemonTokenRequest("POST",
		fmt.Sprintf("/api/daemon/runtimes/%s/tasks/%s/skill-bundles/resolve", runtimeID, taskID),
		resolveSkillBundlesRequest{Skills: []resolveSkillBundleRef{{ID: "pub-deploy", Source: enterprise.Source, Hash: pin}}},
		testWorkspaceID, "claimreclaim-daemon")
	req = withURLParams(req, "runtimeId", runtimeID, "taskId", taskID)
	rec := testutil.Call(t, testHandler.ResolveTaskSkillBundles, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404 (%s)", rec.Code, rec.Body.String())
	}
	if fake.callCount() != 0 {
		t.Fatalf("personal task must not reach the platform, calls = %d", fake.callCount())
	}
}

// TestEnterpriseSkillResolveRejectsUnissuedRefs pins M-5: the resolve endpoint
// intersects requested enterprise refs against the set the task's claim
// actually issued. A ref the claim never handed out — an unknown publish_id,
// or an issued id re-pinned at a different hash — is refused per-skill
// (failed_closed + enterprise_skill_not_issued) and never reaches the
// platform, while an issued ref on the same request still resolves.
func TestEnterpriseSkillResolveRejectsUnissuedRefs(t *testing.T) {
	if testHandler == nil || testPool == nil {
		t.Skip("database not available")
	}
	f := newEnterpriseFixture(t)
	fake := &fakeSkillPlatform{}
	body, pin := buildEntSkillPackage(t, "pub-deploy", validEntSkillSpec())
	fake.pkgs = map[string][]byte{"pub-deploy|" + strings.TrimPrefix(pin, "sha256:"): body}
	withEnterpriseSkillPlatform(t, fake)
	dispatchEnterpriseTask(t, f.taskID)
	// The claim issued only pub-deploy at its pinned hash.
	issueEnterpriseSkillRefs(t, f.taskID, resolveSkillBundleRef{ID: "pub-deploy", Source: enterprise.Source, Hash: pin})

	var resp entResolveResponse
	enterpriseResolve(t, f,
		resolveSkillBundleRef{ID: "pub-deploy", Source: enterprise.Source, Hash: pin},
		// Same publish id but a hash the claim never attested.
		resolveSkillBundleRef{ID: "pub-deploy", Source: enterprise.Source, Hash: "sha256:deadbeef"},
		// A publish id the claim never handed out at all.
		resolveSkillBundleRef{ID: "pub-other", Source: enterprise.Source, Hash: pin},
	).Want(http.StatusOK).JSON(&resp)

	if len(resp.Bundles) != 1 || resp.Bundles[0].ID != "pub-deploy" {
		t.Fatalf("bundles = %+v", resp.Bundles)
	}
	if len(resp.Status) != 3 {
		t.Fatalf("status = %+v", resp.Status)
	}
	byKey := map[string]string{}
	for _, st := range resp.Status {
		byKey[st.ID+":"+st.PinnedSHA256+":"+st.Code] = st.Status
	}
	if got := byKey["pub-deploy:"+strings.TrimPrefix(pin, "sha256:")+":"]; got != "ok" {
		t.Fatalf("issued ref status = %q (%+v)", got, resp.Status)
	}
	notIssued := 0
	for _, st := range resp.Status {
		if st.Code == enterprise.CodeNotIssued {
			notIssued++
			if st.Status != "failed_closed" {
				t.Fatalf("not-issued status = %q", st.Status)
			}
		}
	}
	if notIssued != 2 {
		t.Fatalf("expected 2 not-issued refusals, got %+v", resp.Status)
	}
	// Neither refused ref may reach the platform: the only download call is
	// the issued one.
	if fake.callCount() != 1 {
		t.Fatalf("platform calls = %d, want 1 (unissued refs must never reach the platform)", fake.callCount())
	}
}
