package enterprise

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/multica-ai/multica/server/internal/platform"
	"github.com/multica-ai/multica/server/pkg/skillbundle"
)

// skillPackageSpec describes one synthetic platform package for tests.
type skillPackageSpec struct {
	name     string
	content  string
	execMode string
	clients  []string
	files    []File
}

// buildSkillPackage renders the zip archive (opc-client.json + skill.json)
// and returns the bytes plus the BND-142 pin: the skill manifest hash, the
// same sha256:<hex> vocabulary workspace and builtin skills use.
func buildSkillPackage(t *testing.T, publishID string, spec skillPackageSpec) ([]byte, string) {
	t.Helper()
	payload, err := json.Marshal(map[string]any{
		"name":        spec.name,
		"description": spec.name + " description",
		"content":     spec.content,
		"files":       spec.files,
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
		clientManifestName: string(manifest),
		skillPayloadName:   string(payload),
	} {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatalf("zip create %s: %v", name, err)
		}
		if _, err := w.Write([]byte(body)); err != nil {
			t.Fatalf("zip write %s: %v", name, err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("zip close: %v", err)
	}

	skill := skillbundle.Skill{ID: publishID, Source: Source, Name: spec.name, Description: spec.name + " description", Content: spec.content}
	for _, f := range spec.files {
		skill.Files = append(skill.Files, skillbundle.File{Path: f.Path, Content: f.Content})
	}
	return buf.Bytes(), skillbundle.BuildManifest(skill).Hash
}

// attested wraps package bytes with a correct X-SHA256 attestation header.
func attested(body []byte) platform.SkillPackage {
	digest := sha256.Sum256(body)
	return platform.SkillPackage{Body: body, SHA256Header: hex.EncodeToString(digest[:])}
}

type downloadCall struct {
	publishID string
	sha256    string
}

// fakeDownloader serves canned packages keyed by publishID+"|"+sha256 and
// records every call. latest optionally maps publishID to the revision a
// pin-oblivious platform serves for ANY sha256 query — the "request old
// hash, receive new package" behavior the pin protects against.
type fakeDownloader struct {
	mu     sync.Mutex
	pkgs   map[string]platform.SkillPackage
	latest map[string]platform.SkillPackage
	err    error
	issuer string
	calls  []downloadCall
}

func (f *fakeDownloader) DownloadSkill(_ context.Context, publishID, sha256 string) (platform.SkillPackage, error) {
	f.mu.Lock()
	f.calls = append(f.calls, downloadCall{publishID: publishID, sha256: sha256})
	f.mu.Unlock()
	if f.err != nil {
		return platform.SkillPackage{}, f.err
	}
	// Resolve normalizes the pin (bare hex) before downloading; canned
	// packages may be keyed by either form.
	stripped := strings.TrimPrefix(strings.ToLower(strings.TrimSpace(sha256)), "sha256:")
	pkg, ok := f.pkgs[publishID+"|"+sha256]
	if !ok {
		pkg, ok = f.pkgs[publishID+"|"+stripped]
	}
	if !ok {
		pkg, ok = f.pkgs[publishID+"|sha256:"+stripped]
	}
	if !ok && f.latest != nil {
		pkg, ok = f.latest[publishID]
	}
	if !ok {
		return platform.SkillPackage{}, &platform.APIError{StatusCode: http.StatusNotFound, Code: "REVISION_NOT_FOUND", Message: "pinned revision gone"}
	}
	return pkg, nil
}

func (f *fakeDownloader) Issuer() string {
	if f.issuer == "" {
		return platform.DefaultIssuer
	}
	return f.issuer
}

func (f *fakeDownloader) callCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.calls)
}

func newTestResolver(t *testing.T, d Downloader) *Resolver {
	t.Helper()
	r, err := NewResolver(d, t.TempDir())
	if err != nil {
		t.Fatalf("NewResolver: %v", err)
	}
	return r
}

func testRef(publishID, pin string) Ref {
	return Ref{Issuer: "issuer-1", Subject: "sub-1", Tenant: "tenant-1", PublishID: publishID, SHA256: pin}
}

func validSpec() skillPackageSpec {
	return skillPackageSpec{
		name:     "deploy",
		content:  "deploy instructions",
		execMode: ExecModeLocalInstruction,
		clients:  []string{"code"},
		files:    []File{{Path: "rules.md", Content: "deploy rules"}},
	}
}

// normalizedRef returns the ref the way Resolve computes cache keys: pin
// canonicalized to bare hex.
func normalizedRef(ref Ref) Ref {
	if pin, err := NormalizeSHA256(ref.SHA256); err == nil {
		ref.SHA256 = pin
	}
	return ref
}

func TestResolverFakePlatformRoundTrip(t *testing.T) {
	body, pin := buildSkillPackage(t, "pub-1", validSpec())

	// The fake platform speaks the INT-142 contract over HTTP so this test
	// exercises the platform client and the resolver together: path shape,
	// sha256 query param, service-token auth, and the X-SHA256 attestation.
	var gotPath, gotQuery, gotAuth string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotQuery = r.URL.Query().Get("sha256")
		gotAuth = r.Header.Get("Authorization")
		digest := sha256.Sum256(body)
		w.Header().Set("X-SHA256", hex.EncodeToString(digest[:]))
		_, _ = w.Write(body)
	}))
	t.Cleanup(server.Close)

	client, err := platform.New(platform.Config{BaseURL: server.URL, ServiceToken: "svc", Issuer: "issuer-1"})
	if err != nil {
		t.Fatalf("platform.New: %v", err)
	}
	resolver := newTestResolver(t, client)

	bundle, err := resolver.Resolve(context.Background(), testRef("pub-1", pin))
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if gotPath != "/integration/v1/skills/pub-1/download" {
		t.Fatalf("platform path = %q", gotPath)
	}
	if want := strings.TrimPrefix(pin, "sha256:"); gotQuery != want {
		t.Fatalf("sha256 query = %q, want normalized pin %q", gotQuery, want)
	}
	if gotAuth != "Bearer svc" {
		t.Fatalf("Authorization = %q", gotAuth)
	}
	if bundle.PublishID != "pub-1" || bundle.Name != "deploy" || bundle.Content != "deploy instructions" {
		t.Fatalf("bundle = %+v", bundle)
	}
	if len(bundle.Files) != 1 || bundle.Files[0].Path != "rules.md" {
		t.Fatalf("bundle files = %+v", bundle.Files)
	}
	if bundle.ExecMode != ExecModeLocalInstruction {
		t.Fatalf("exec mode = %q", bundle.ExecMode)
	}

	// Second resolve is served from the validated on-disk cache: no second
	// HTTP request reaches the platform.
	bundle2, err := resolver.Resolve(context.Background(), testRef("pub-1", pin))
	if err != nil {
		t.Fatalf("cached Resolve: %v", err)
	}
	if bundle2.Name != "deploy" {
		t.Fatalf("cached bundle = %+v", bundle2)
	}
}

func TestResolverPinnedVersionSurvivesPlatformSwap(t *testing.T) {
	bodyV1, pinV1 := buildSkillPackage(t, "pub-1", validSpec())
	specV2 := validSpec()
	specV2.content = "deploy instructions v2"
	bodyV2, pinV2 := buildSkillPackage(t, "pub-1", specV2)

	fd := &fakeDownloader{pkgs: map[string]platform.SkillPackage{
		"pub-1|" + pinV1: attested(bodyV1),
		"pub-1|" + pinV2: attested(bodyV2),
	}}
	resolver := newTestResolver(t, fd)

	first, err := resolver.Resolve(context.Background(), testRef("pub-1", pinV1))
	if err != nil {
		t.Fatalf("Resolve v1: %v", err)
	}
	if first.Content != "deploy instructions" {
		t.Fatalf("v1 content = %q", first.Content)
	}

	// The platform now serves v2 for the same publish_id. The old pin must
	// keep resolving the OLD fixed version from cache — never the new package.
	again, err := resolver.Resolve(context.Background(), testRef("pub-1", pinV1))
	if err != nil {
		t.Fatalf("Resolve v1 again: %v", err)
	}
	if again.Content != "deploy instructions" {
		t.Fatalf("old pin received new package: %q", again.Content)
	}
	if fd.callCount() != 1 {
		t.Fatalf("platform calls = %d, want 1 (cache must serve the old pin)", fd.callCount())
	}

	// The new pin resolves the new fixed version.
	second, err := resolver.Resolve(context.Background(), testRef("pub-1", pinV2))
	if err != nil {
		t.Fatalf("Resolve v2: %v", err)
	}
	if second.Content != "deploy instructions v2" {
		t.Fatalf("v2 content = %q", second.Content)
	}
	if fd.callCount() != 2 {
		t.Fatalf("platform calls = %d, want 2", fd.callCount())
	}
}

func TestResolverColdOldPinNeverReceivesNewPackage(t *testing.T) {
	specV2 := validSpec()
	specV2.content = "deploy instructions v2"
	bodyV2, _ := buildSkillPackage(t, "pub-1", specV2)
	_, pinV1 := buildSkillPackage(t, "pub-1", validSpec())

	// The platform ignores the pin and serves the current revision for any
	// sha256 query — the exact behavior that must never put a new package
	// under an old pin.
	fd := &fakeDownloader{latest: map[string]platform.SkillPackage{
		"pub-1": attested(bodyV2),
	}}
	resolver := newTestResolver(t, fd)

	_, err := resolver.Resolve(context.Background(), testRef("pub-1", pinV1))
	if !IsCode(err, CodeHashMismatch) {
		t.Fatalf("err = %v, want CodeHashMismatch", err)
	}
	// The rejected bytes were not cached: the key directory is gone.
	if _, statErr := os.Stat(filepath.Join(resolver.cacheDir(normalizedRef(testRef("pub-1", pinV1))), packageFileName)); !os.IsNotExist(statErr) {
		t.Fatalf("mismatched package was cached (stat err = %v)", statErr)
	}
}

func TestResolverHashMismatchEvictsPoisonedCacheAndPreservesOldVersions(t *testing.T) {
	bodyV1, pinV1 := buildSkillPackage(t, "pub-1", validSpec())
	specV2 := validSpec()
	specV2.content = "deploy instructions v2"
	bodyV2, pinV2 := buildSkillPackage(t, "pub-1", specV2)

	fd := &fakeDownloader{pkgs: map[string]platform.SkillPackage{
		"pub-1|" + pinV1: attested(bodyV1),
		"pub-1|" + pinV2: attested(bodyV2),
	}}
	resolver := newTestResolver(t, fd)

	if _, err := resolver.Resolve(context.Background(), testRef("pub-1", pinV1)); err != nil {
		t.Fatalf("Resolve v1: %v", err)
	}
	if _, err := resolver.Resolve(context.Background(), testRef("pub-1", pinV2)); err != nil {
		t.Fatalf("Resolve v2: %v", err)
	}

	// Poison the v2 cache entry with bytes that fail the pin, and flip the
	// platform back to serving v2 bytes (as it would after a rollback).
	v2Dir := resolver.cacheDir(normalizedRef(testRef("pub-1", pinV2)))
	if err := os.WriteFile(filepath.Join(v2Dir, packageFileName), []byte("garbage"), 0o644); err != nil {
		t.Fatalf("poison cache: %v", err)
	}

	bundle, err := resolver.Resolve(context.Background(), testRef("pub-1", pinV2))
	if err != nil {
		t.Fatalf("Resolve after poison: %v", err)
	}
	if bundle.Content != "deploy instructions v2" {
		t.Fatalf("content = %q", bundle.Content)
	}

	// The old version under the same publish_id survived untouched.
	v1Bundle, err := resolver.Resolve(context.Background(), testRef("pub-1", pinV1))
	if err != nil {
		t.Fatalf("Resolve v1 after eviction: %v", err)
	}
	if v1Bundle.Content != "deploy instructions" {
		t.Fatalf("v1 content = %q", v1Bundle.Content)
	}
}

func TestResolverRejectsMismatchedAttestationHeader(t *testing.T) {
	body, pin := buildSkillPackage(t, "pub-1", validSpec())
	// A well-formed 64-hex attestation that does not match the served bytes.
	wrong := strings.Repeat("0123456789abcdef", 4)
	fd := &fakeDownloader{pkgs: map[string]platform.SkillPackage{
		"pub-1|" + pin: {Body: body, SHA256Header: wrong},
	}}
	resolver := newTestResolver(t, fd)

	_, err := resolver.Resolve(context.Background(), testRef("pub-1", pin))
	if !IsCode(err, CodeHashMismatch) {
		t.Fatalf("err = %v, want CodeHashMismatch", err)
	}
	if _, statErr := os.Stat(resolver.cacheDir(normalizedRef(testRef("pub-1", pin)))); !os.IsNotExist(statErr) {
		t.Fatalf("mismatching attested package was cached (stat err = %v)", statErr)
	}
}

func TestResolverCacheKeyIsolationBySubjectAndTenant(t *testing.T) {
	body, pin := buildSkillPackage(t, "pub-1", validSpec())
	fd := &fakeDownloader{pkgs: map[string]platform.SkillPackage{
		"pub-1|" + pin: attested(body),
	}}
	resolver := newTestResolver(t, fd)

	base := testRef("pub-1", pin)
	for _, ref := range []Ref{
		base,
		{Issuer: base.Issuer, Subject: "sub-2", Tenant: base.Tenant, PublishID: "pub-1", SHA256: pin},
		{Issuer: base.Issuer, Subject: base.Subject, Tenant: "tenant-2", PublishID: "pub-1", SHA256: pin},
		{Issuer: "issuer-2", Subject: base.Subject, Tenant: base.Tenant, PublishID: "pub-1", SHA256: pin},
	} {
		if _, err := resolver.Resolve(context.Background(), ref); err != nil {
			t.Fatalf("Resolve %+v: %v", ref, err)
		}
	}
	if fd.callCount() != 4 {
		t.Fatalf("platform calls = %d, want 4 (one per five-tuple)", fd.callCount())
	}
	// Same key resolves from cache: no fifth download.
	if _, err := resolver.Resolve(context.Background(), base); err != nil {
		t.Fatalf("Resolve base again: %v", err)
	}
	if fd.callCount() != 4 {
		t.Fatalf("platform calls = %d, want 4 after cache hits", fd.callCount())
	}

	// The cache directory layout is exactly the BND-142 five-tuple, with the
	// pin normalized to bare hex.
	barePin := strings.TrimPrefix(pin, "sha256:")
	wantDir := filepath.Join(resolver.root, "enterprise", "issuer-1", "sub-1", "tenant-1", "pub-1", barePin)
	if _, err := os.Stat(filepath.Join(wantDir, packageFileName)); err != nil {
		t.Fatalf("cache entry at %s: %v", wantDir, err)
	}
}

func TestResolverCloudOnlyRejected(t *testing.T) {
	spec := validSpec()
	spec.execMode = ExecModeCloudOnly
	body, pin := buildSkillPackage(t, "pub-1", spec)
	fd := &fakeDownloader{pkgs: map[string]platform.SkillPackage{
		"pub-1|" + pin: attested(body),
	}}
	resolver := newTestResolver(t, fd)

	_, err := resolver.Resolve(context.Background(), testRef("pub-1", pin))
	if !IsCode(err, CodeManifestInvalid) {
		t.Fatalf("err = %v, want CodeManifestInvalid", err)
	}
	if _, statErr := os.Stat(resolver.cacheDir(normalizedRef(testRef("pub-1", pin)))); !os.IsNotExist(statErr) {
		t.Fatalf("cloud_only package was cached (stat err = %v)", statErr)
	}
}

func TestResolverManifestViolationsFailedClosed(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*skillPackageSpec)
	}{
		{name: "missing code client", mutate: func(s *skillPackageSpec) { s.clients = []string{"web"} }},
		{name: "empty clients", mutate: func(s *skillPackageSpec) { s.clients = nil }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			spec := validSpec()
			tc.mutate(&spec)
			body, pin := buildSkillPackage(t, "pub-1", spec)
			fd := &fakeDownloader{pkgs: map[string]platform.SkillPackage{
				"pub-1|" + pin: attested(body),
			}}
			resolver := newTestResolver(t, fd)
			if _, err := resolver.Resolve(context.Background(), testRef("pub-1", pin)); !IsCode(err, CodeManifestInvalid) {
				t.Fatalf("err = %v, want CodeManifestInvalid", err)
			}
		})
	}
}

func TestResolverPayloadDigestMismatchFailedClosed(t *testing.T) {
	spec := validSpec()
	_, pin := buildSkillPackage(t, "pub-1", spec)
	rawPayload, err := json.Marshal(map[string]any{
		"name": spec.name, "description": spec.name + " description", "content": spec.content, "files": spec.files,
	})
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}
	// Manifest lies about the payload bytes: the digest field points at
	// zeros while skill.json carries the real content.
	manifest, err := json.Marshal(map[string]any{
		"exec_mode":      spec.execMode,
		"clients":        spec.clients,
		"payload_digest": "sha256:" + strings.Repeat("0", 64),
	})
	if err != nil {
		t.Fatalf("marshal manifest: %v", err)
	}
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for name, content := range map[string]string{
		clientManifestName: string(manifest),
		skillPayloadName:   string(rawPayload),
	} {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatalf("zip create: %v", err)
		}
		if _, err := w.Write([]byte(content)); err != nil {
			t.Fatalf("zip write: %v", err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("zip close: %v", err)
	}

	fd := &fakeDownloader{pkgs: map[string]platform.SkillPackage{
		"pub-1|" + pin: attested(buf.Bytes()),
	}}
	resolver := newTestResolver(t, fd)
	if _, err := resolver.Resolve(context.Background(), testRef("pub-1", pin)); !IsCode(err, CodeManifestInvalid) {
		t.Fatalf("err = %v, want CodeManifestInvalid", err)
	}
}

func TestResolverUnsupportedExecModeFailedClosed(t *testing.T) {
	spec := validSpec()
	spec.execMode = "teleport"
	body, pin := buildSkillPackage(t, "pub-1", spec)
	fd := &fakeDownloader{pkgs: map[string]platform.SkillPackage{
		"pub-1|" + pin: attested(body),
	}}
	resolver := newTestResolver(t, fd)
	if _, err := resolver.Resolve(context.Background(), testRef("pub-1", pin)); !IsCode(err, CodeManifestInvalid) {
		t.Fatalf("err = %v, want CodeManifestInvalid", err)
	}
}

func TestResolverLocalSandboxAccepted(t *testing.T) {
	spec := validSpec()
	spec.execMode = ExecModeLocalSandbox
	body, pin := buildSkillPackage(t, "pub-1", spec)
	fd := &fakeDownloader{pkgs: map[string]platform.SkillPackage{
		"pub-1|" + pin: attested(body),
	}}
	resolver := newTestResolver(t, fd)
	bundle, err := resolver.Resolve(context.Background(), testRef("pub-1", pin))
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if bundle.ExecMode != ExecModeLocalSandbox {
		t.Fatalf("exec mode = %q", bundle.ExecMode)
	}
}

func TestResolverBadPinRejectedBeforeIO(t *testing.T) {
	fd := &fakeDownloader{}
	resolver := newTestResolver(t, fd)
	for _, pin := range []string{"", "xyz", "sha256:xyz", strings.Repeat("g", 64)} {
		if _, err := resolver.Resolve(context.Background(), testRef("pub-1", pin)); !IsCode(err, CodePackageInvalid) {
			t.Fatalf("pin %q: err = %v, want CodePackageInvalid", pin, err)
		}
	}
	if fd.callCount() != 0 {
		t.Fatalf("platform calls = %d, want 0 for malformed pins", fd.callCount())
	}
}

func TestResolverPlatformErrorPropagates(t *testing.T) {
	fd := &fakeDownloader{err: errors.New("platform unreachable")}
	resolver := newTestResolver(t, fd)
	_, pin := buildSkillPackage(t, "pub-1", validSpec())
	if _, err := resolver.Resolve(context.Background(), testRef("pub-1", pin)); err == nil || IsCode(err, CodeHashMismatch) {
		t.Fatalf("err = %v, want the platform error wrapped", err)
	}
}

func TestNewResolverValidatesInputs(t *testing.T) {
	if _, err := NewResolver(nil, t.TempDir()); err == nil {
		t.Fatal("nil downloader accepted")
	}
	fd := &fakeDownloader{}
	if _, err := NewResolver(fd, ""); err == nil {
		t.Fatal("empty root accepted")
	}
	if _, err := NewResolver(fd, "  "); err == nil {
		t.Fatal("blank root accepted")
	}
}

func TestResolverIssuerDefaultsFromDownloader(t *testing.T) {
	spec := validSpec()
	body, pin := buildSkillPackage(t, "pub-1", spec)
	fd := &fakeDownloader{issuer: "platform-b", pkgs: map[string]platform.SkillPackage{
		"pub-1|" + pin: attested(body),
	}}
	resolver := newTestResolver(t, fd)
	ref := testRef("pub-1", pin)
	ref.Issuer = ""
	if _, err := resolver.Resolve(context.Background(), ref); err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	wantDir := filepath.Join(resolver.root, "enterprise", "platform-b", "sub-1", "tenant-1", "pub-1", strings.TrimPrefix(pin, "sha256:"))
	if _, err := os.Stat(filepath.Join(wantDir, packageFileName)); err != nil {
		t.Fatalf("cache entry under downloader issuer missing: %v", err)
	}
}
