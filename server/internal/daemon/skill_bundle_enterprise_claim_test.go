package daemon

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/multica-ai/multica/server/internal/enterprise"
)

// Claim-issued enterprise_skills (TASK-C06): the refs the server hands the
// daemon at claim time fold into the task's resolve set and travel the same
// per-skill resolve path as agent skill refs, with the enterprise
// failed-closed semantics when the pinned revision is gone.

func TestWithEnterpriseSkillRefs(t *testing.T) {
	agentRefs := []SkillRefData{{ID: "skill-1", Source: "workspace", Hash: "sha256:aa"}}

	if got := withEnterpriseSkillRefs(agentRefs, nil); len(got) != 1 || got[0].ID != "skill-1" {
		t.Fatalf("nil enterprise skills must leave refs untouched, got %+v", got)
	}

	got := withEnterpriseSkillRefs(agentRefs, []EnterpriseSkillRefData{
		{Source: enterprise.Source, ID: "pub-1", Name: "deploy", Version: "1.0.0", Hash: "sha256:bb"},
		// Malformed entries never reach the resolve request.
		{Source: "workspace", ID: "not-enterprise", Hash: "sha256:cc"},
		{Source: enterprise.Source, ID: "", Hash: "sha256:dd"},
		{Source: enterprise.Source, ID: "no-hash", Hash: " "},
	})
	if len(got) != 2 {
		t.Fatalf("refs = %+v, want agent ref + one enterprise ref", got)
	}
	ent := got[1]
	if ent.ID != "pub-1" || ent.Source != enterprise.Source || ent.Hash != "sha256:bb" || ent.Name != "deploy" {
		t.Fatalf("folded ref = %+v", ent)
	}
	if ent.SizeBytes != 0 || ent.FileCount != 0 {
		t.Fatalf("claim refs carry no size metadata, got %+v", ent)
	}
}

// makeResolvableEnterpriseBundle builds a self-consistent source-enterprise
// bundle the daemon-side validator accepts.
func makeResolvableEnterpriseBundle(id string) SkillData {
	b := SkillData{
		ID:      id,
		Source:  enterprise.Source,
		Name:    id,
		Content: "content-of-" + id,
		Files:   []SkillFileData{{Path: "rules.md", Content: "rules-" + id}},
	}
	ref := skillRefFromBundle(b)
	b.Hash = ref.Hash
	b.SizeBytes = ref.SizeBytes
	b.Files[0].SHA256 = ref.Files[0].SHA256
	b.Files[0].SizeBytes = ref.Files[0].SizeBytes
	return b
}

func TestEnsureTaskSkillBundlesResolvesClaimIssuedEnterpriseSkills(t *testing.T) {
	defer noSleepRetry(t)()

	bundle := makeResolvableEnterpriseBundle("pub-1")
	var mu sync.Mutex
	requests := 0
	var gotRef SkillRefData
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Skills []SkillRefData `json:"skills"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Errorf("decode request: %v", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if len(req.Skills) != 1 {
			t.Errorf("expected exactly 1 skill per request, got %d", len(req.Skills))
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		mu.Lock()
		requests++
		gotRef = req.Skills[0]
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"bundles": []SkillData{bundle}})
	}))
	defer srv.Close()

	d := &Daemon{
		client:     NewClient(srv.URL),
		skillCache: NewSkillBundleCache(t.TempDir()),
	}
	issued := EnterpriseSkillRefData{
		Source:  enterprise.Source,
		ID:      "pub-1",
		Name:    "pub-1",
		Version: "1.0.0",
		Hash:    bundle.Hash,
	}
	task := &Task{
		ID:               "task-ent",
		RuntimeID:        "rt-1",
		WorkspaceID:      "ws-1",
		Enterprise:       true,
		Agent:            &AgentData{ID: "agent-1"},
		EnterpriseSkills: []EnterpriseSkillRefData{issued},
	}
	if err := d.ensureTaskSkillBundles(context.Background(), task); err != nil {
		t.Fatalf("claim-issued enterprise skill must resolve: %v", err)
	}
	mu.Lock()
	resolvedRef := gotRef
	mu.Unlock()
	if resolvedRef.ID != issued.ID || resolvedRef.Source != enterprise.Source || resolvedRef.Hash != issued.Hash {
		t.Fatalf("resolve request ref = %+v, want the issued ref %+v", resolvedRef, issued)
	}
	if len(task.Agent.Skills) != 1 || task.Agent.Skills[0].ID != "pub-1" || task.Agent.Skills[0].Source != enterprise.Source {
		t.Fatalf("resolved skills = %+v", task.Agent.Skills)
	}

	// A second dispatch serves the ref from the daemon-side cache: no new
	// resolve request.
	if err := d.ensureTaskSkillBundles(context.Background(), task); err != nil {
		t.Fatalf("cached enterprise skill must resolve: %v", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if requests != 1 {
		t.Fatalf("resolve requests = %d, want 1 (cache must absorb the retry)", requests)
	}
}

func TestEnsureTaskSkillBundlesClaimIssuedEnterpriseFailedClosed(t *testing.T) {
	defer noSleepRetry(t)()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnprocessableEntity)
		_ = json.NewEncoder(w).Encode(map[string]any{"code": enterprise.CodeHashMismatch, "message": "pinned revision gone"})
	}))
	defer srv.Close()

	d := &Daemon{
		client:     NewClient(srv.URL),
		skillCache: NewSkillBundleCache(t.TempDir()),
	}
	issued := EnterpriseSkillRefData{
		Source:  enterprise.Source,
		ID:      "pub-gone",
		Name:    "pub-gone",
		Version: "1.0.0",
		Hash:    "sha256:deadbeef",
	}
	task := &Task{
		ID:               "task-ent",
		RuntimeID:        "rt-1",
		WorkspaceID:      "ws-1",
		Enterprise:       true,
		Agent:            &AgentData{ID: "agent-1"},
		EnterpriseSkills: []EnterpriseSkillRefData{issued},
	}
	// BND-142 failed-closed: the pinned revision is gone, so the skill is
	// dropped and the enterprise task continues with no skills.
	if err := d.ensureTaskSkillBundles(context.Background(), task); err != nil {
		t.Fatalf("failed-closed enterprise resolve must not fail the task: %v", err)
	}
	if len(task.Agent.Skills) != 0 {
		t.Fatalf("failed-closed skill must be omitted, got %+v", task.Agent.Skills)
	}
}
