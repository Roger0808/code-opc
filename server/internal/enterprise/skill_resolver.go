// Package enterprise implements the server side of the OPC enterprise
// integration: resolving platform-published skill bundles pinned to an exact
// version. Personal-task flows never touch this package; every entry point
// fails closed when the platform side is unavailable or inconsistent.
package enterprise

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/multica-ai/multica/server/internal/platform"
	"github.com/multica-ai/multica/server/pkg/skillbundle"
)

// Source is the skill-bundle source marker for platform-published enterprise
// skills. Daemons request refs with this source for enterprise tasks; the
// server resolves them here instead of the workspace/builtin/plugin paths.
const Source = "enterprise"

// Supported exec_mode values from opc-client.json. cloud_only skills must
// never be installed as enterprise local skills: an enterprise task runs on
// the daemon host, so a skill that only executes in the platform cloud has
// no legal local runtime and is rejected failed-closed.
const (
	ExecModeLocalInstruction = "local_instruction"
	ExecModeLocalSandbox     = "local_sandbox"
	ExecModeCloudOnly        = "cloud_only"
)

// Ref is the BND-142 pinned skill identity. The five fields together are the
// cache key: a cached package satisfies a request only when every segment
// matches, so packages pinned for one subject or tenant never satisfy
// another. SHA256 is the pinned skill manifest hash (bare 64-char hex or
// "sha256:"-prefixed).
type Ref struct {
	Issuer    string
	Subject   string
	Tenant    string
	PublishID string
	SHA256    string
}

// File is one supporting file shipped inside a skill package.
type File struct {
	Path    string `json:"path"`
	Content string `json:"content"`
}

// Bundle is a resolved, fixed-version enterprise skill package.
type Bundle struct {
	PublishID   string
	Name        string
	Description string
	Content     string
	Files       []File
	ExecMode    string
}

// Downloader fetches pinned skill packages from the platform. *platform.Client
// satisfies it; tests substitute a fake.
type Downloader interface {
	DownloadSkill(ctx context.Context, publishID, sha256 string) (platform.SkillPackage, error)
	Issuer() string
}

// Resolve error codes surfaced to the HTTP layer. HashMismatch maps to 422:
// the platform no longer serves the pinned revision, so the request can never
// be satisfied and retrying as-is is pointless. ManifestInvalid also maps to
// 422: the package exists but is not legal to install as an enterprise local
// skill.
const (
	CodeNotConfigured   = "enterprise_skill_not_configured"
	CodeHashMismatch    = "enterprise_skill_hash_mismatch"
	CodeManifestInvalid = "enterprise_skill_manifest_invalid"
	CodePackageInvalid  = "enterprise_skill_package_invalid"
	// CodeNotIssued marks a ref the task's claim never issued (M-5): the
	// resolve endpoint refuses it without touching the platform.
	CodeNotIssued = "enterprise_skill_not_issued"
)

// ResolveError is a typed resolver failure carrying a stable machine code.
type ResolveError struct {
	Code    string
	Message string
}

func (e *ResolveError) Error() string { return e.Message }

// IsCode reports whether err is a ResolveError carrying the given code.
func IsCode(err error, code string) bool {
	var re *ResolveError
	return errors.As(err, &re) && re.Code == code
}

// packageFileName is the on-disk name of the cached package bytes inside a
// cache key directory.
const packageFileName = "package.zip"

// skillPayloadName and clientManifestName are the two required members of a
// skill package archive.
const (
	clientManifestName = "opc-client.json"
	skillPayloadName   = "skill.json"
)

// maxPackageBytes mirrors the platform client download bound; a cache entry
// larger than this is poison and is evicted rather than served.
const maxPackageBytes = 32 << 20

// Resolver resolves enterprise skill refs against the platform, caching
// validated package bytes under root. The zero value is unusable; NewResolver
// validates the minimum configuration.
type Resolver struct {
	downloader Downloader
	root       string

	mu    sync.Mutex
	locks map[string]*sync.Mutex
}

// NewResolver builds a Resolver. downloader must be non-nil; root is the
// cache root under which the BND-142 five-tuple directories are created.
func NewResolver(downloader Downloader, root string) (*Resolver, error) {
	if downloader == nil {
		return nil, errors.New("enterprise skill resolver requires a platform downloader")
	}
	root = strings.TrimSpace(root)
	if root == "" {
		return nil, errors.New("enterprise skill resolver requires a cache root")
	}
	return &Resolver{downloader: downloader, root: root, locks: make(map[string]*sync.Mutex)}, nil
}

// Resolve returns the fixed-version bundle for ref. A cached entry is served
// only after it still validates against the pin; otherwise the entry is
// evicted and the platform is re-fetched. The pin (ref.SHA256, bare or
// "sha256:"-prefixed hex) is the skill manifest hash, the same sha256:<hex>
// vocabulary workspace and builtin skills use — so the resolved bundle's
// Hash field can carry it verbatim. A platform response whose payload no
// longer hashes to the pin — or whose attested X-SHA256 header disagrees
// with its own bytes — is never cached: the new entry is deleted and a
// CodeHashMismatch error reports that the pinned revision is gone. Entries
// pinned to other hashes are untouched, so a rejected refresh never
// destroys an old version.
func (r *Resolver) Resolve(ctx context.Context, ref Ref) (*Bundle, error) {
	normalized, err := NormalizeSHA256(ref.SHA256)
	if err != nil {
		return nil, err
	}
	ref.SHA256 = normalized
	if strings.TrimSpace(ref.PublishID) == "" {
		return nil, &ResolveError{Code: CodePackageInvalid, Message: "enterprise skill ref requires a publish_id"}
	}
	if strings.TrimSpace(ref.Issuer) == "" {
		ref.Issuer = r.downloader.Issuer()
	}

	unlock := r.lock(ref)
	defer unlock()

	dir := r.cacheDir(ref)
	if data, err := os.ReadFile(filepath.Join(dir, packageFileName)); err == nil {
		if bundle, err := r.bundleFromPackage(ref, data); err == nil {
			return bundle, nil
		}
		// A cache hit that no longer validates (corruption, poisoned entry,
		// truncated copy) is evicted so the fresh download below starts clean.
		_ = os.RemoveAll(dir)
	}

	pkg, err := r.downloader.DownloadSkill(ctx, ref.PublishID, ref.SHA256)
	if err != nil {
		return nil, err
	}
	if len(pkg.Body) == 0 || len(pkg.Body) > maxPackageBytes {
		_ = os.RemoveAll(dir)
		return nil, &ResolveError{Code: CodePackageInvalid, Message: "platform skill package is empty or oversize"}
	}
	if header := normalizeAttestedDigest(pkg.SHA256Header); header != "" {
		digest := sha256.Sum256(pkg.Body)
		if header != hex.EncodeToString(digest[:]) {
			// The platform attests a digest its own bytes do not hash to.
			// Never cache, and evict any partial entry for this key; other
			// sha256 directories under the same publish_id keep their
			// validated old versions.
			_ = os.RemoveAll(dir)
			return nil, &ResolveError{
				Code:    CodeHashMismatch,
				Message: "platform skill package X-SHA256 header does not match the served bytes",
			}
		}
	}

	bundle, err := r.bundleFromPackage(ref, pkg.Body)
	if err != nil {
		// A payload that no longer hashes to the pin means the platform now
		// serves a different revision of this skill; manifest/policy failures
		// are failed-closed as well. Neither is cached, so a later fix on the
		// platform can still land cleanly and old pinned versions survive.
		_ = os.RemoveAll(dir)
		return nil, err
	}
	if err := r.store(dir, pkg.Body); err != nil {
		// A cache write failure must not fail the resolve: the validated
		// bundle is returned and the next request re-downloads it.
		return bundle, nil
	}
	return bundle, nil
}

// bundleFromPackage parses and fully validates package bytes against the
// ref: archive shape, opc-client.json manifest (exec_mode, clients, payload
// digest) and the skill payload, whose manifest hash must equal the pinned
// sha256. It performs no IO.
func (r *Resolver) bundleFromPackage(ref Ref, data []byte) (*Bundle, error) {
	if len(data) == 0 || len(data) > maxPackageBytes {
		return nil, &ResolveError{Code: CodePackageInvalid, Message: "enterprise skill package is empty or oversize"}
	}
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return nil, &ResolveError{Code: CodePackageInvalid, Message: "enterprise skill package is not a valid archive"}
	}

	var manifestRaw, payloadRaw []byte
	for _, f := range zr.File {
		switch f.Name {
		case clientManifestName:
			manifestRaw, err = readZipFile(f, 1<<20)
			if err != nil {
				return nil, &ResolveError{Code: CodePackageInvalid, Message: "enterprise skill manifest unreadable"}
			}
		case skillPayloadName:
			payloadRaw, err = readZipFile(f, maxPackageBytes)
			if err != nil {
				return nil, &ResolveError{Code: CodePackageInvalid, Message: "enterprise skill payload unreadable"}
			}
		}
	}
	if manifestRaw == nil || payloadRaw == nil {
		return nil, &ResolveError{Code: CodePackageInvalid, Message: "enterprise skill package misses opc-client.json or skill.json"}
	}

	var manifest struct {
		ExecMode      string   `json:"exec_mode"`
		Clients       []string `json:"clients"`
		PayloadDigest string   `json:"payload_digest"`
	}
	if err := json.Unmarshal(manifestRaw, &manifest); err != nil {
		return nil, &ResolveError{Code: CodeManifestInvalid, Message: "enterprise skill manifest is not valid JSON"}
	}
	switch strings.TrimSpace(manifest.ExecMode) {
	case ExecModeLocalInstruction, ExecModeLocalSandbox:
	case ExecModeCloudOnly:
		return nil, &ResolveError{Code: CodeManifestInvalid, Message: "cloud_only skills cannot be installed as enterprise local skills"}
	default:
		return nil, &ResolveError{Code: CodeManifestInvalid, Message: "enterprise skill manifest declares an unsupported exec_mode"}
	}
	if !containsString(manifest.Clients, "code") {
		return nil, &ResolveError{Code: CodeManifestInvalid, Message: "enterprise skill manifest does not list the code client"}
	}
	payloadDigest := sha256.Sum256(payloadRaw)
	if normalizeAttestedDigest(manifest.PayloadDigest) != hex.EncodeToString(payloadDigest[:]) {
		return nil, &ResolveError{Code: CodeManifestInvalid, Message: "enterprise skill manifest payload digest does not match the payload bytes"}
	}

	var payload struct {
		Name        string `json:"name"`
		Description string `json:"description"`
		Content     string `json:"content"`
		Files       []File `json:"files"`
	}
	if err := json.Unmarshal(payloadRaw, &payload); err != nil {
		return nil, &ResolveError{Code: CodePackageInvalid, Message: "enterprise skill payload is not valid JSON"}
	}
	if strings.TrimSpace(payload.Name) == "" || strings.TrimSpace(payload.Content) == "" {
		return nil, &ResolveError{Code: CodePackageInvalid, Message: "enterprise skill payload requires name and content"}
	}
	for _, file := range payload.Files {
		if !safePackagePath(file.Path) {
			return nil, &ResolveError{Code: CodePackageInvalid, Message: "enterprise skill payload declares an unsafe file path"}
		}
	}

	// The pin is the skill manifest hash (the same sha256:<hex> vocabulary
	// workspace and builtin skills use), so a platform that swapped in a new
	// revision after this pin was minted fails here: the pinned version no
	// longer exists and the request must be answered 422, never with the new
	// package.
	skill := skillbundle.Skill{
		ID:          ref.PublishID,
		Source:      Source,
		Name:        payload.Name,
		Description: payload.Description,
		Content:     payload.Content,
	}
	for _, file := range payload.Files {
		skill.Files = append(skill.Files, skillbundle.File{Path: file.Path, Content: file.Content})
	}
	if manifest := skillbundle.BuildManifest(skill); manifest.Hash != "sha256:"+ref.SHA256 {
		return nil, &ResolveError{
			Code:    CodeHashMismatch,
			Message: "enterprise skill payload hash does not match the pinned sha256",
		}
	}
	return &Bundle{
		PublishID:   ref.PublishID,
		Name:        payload.Name,
		Description: payload.Description,
		Content:     payload.Content,
		Files:       payload.Files,
		ExecMode:    strings.TrimSpace(manifest.ExecMode),
	}, nil
}

// store writes package bytes into dir atomically: the bytes land under a
// sibling temp directory and are renamed over the key directory, so a reader
// never observes a partial package.zip.
func (r *Resolver) store(dir string, data []byte) error {
	parent := filepath.Dir(dir)
	if err := os.MkdirAll(parent, 0o755); err != nil {
		return err
	}
	tmp, err := os.MkdirTemp(parent, ".skill-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tmp)
	if err := os.WriteFile(filepath.Join(tmp, packageFileName), data, 0o644); err != nil {
		return err
	}
	if err := os.RemoveAll(dir); err != nil {
		return err
	}
	return os.Rename(tmp, dir)
}

// cacheDir maps a ref onto its BND-142 five-tuple directory. Every segment is
// sanitized so a hostile or malformed ref cannot escape the cache root.
func (r *Resolver) cacheDir(ref Ref) string {
	return filepath.Join(
		r.root,
		"enterprise",
		safeSegment(ref.Issuer),
		safeSegment(ref.Subject),
		safeSegment(ref.Tenant),
		safeSegment(ref.PublishID),
		safeSegment(ref.SHA256),
	)
}

// lock serializes resolves per cache key, matching the daemon-side
// SkillBundleCache.WithRefLock semantics.
func (r *Resolver) lock(ref Ref) func() {
	key := strings.Join([]string{ref.Issuer, ref.Subject, ref.Tenant, ref.PublishID, ref.SHA256}, "\x00")
	r.mu.Lock()
	l, ok := r.locks[key]
	if !ok {
		l = &sync.Mutex{}
		r.locks[key] = l
	}
	r.mu.Unlock()
	l.Lock()
	return l.Unlock
}

// NormalizeSHA256 validates and canonicalizes a pin: bare 64-char lowercase
// hex or a "sha256:"-prefixed digest. Anything else is rejected before any
// network or disk work happens.
func NormalizeSHA256(pin string) (string, error) {
	v := strings.TrimSpace(strings.ToLower(pin))
	v = strings.TrimPrefix(v, "sha256:")
	if len(v) != 64 {
		return "", &ResolveError{Code: CodePackageInvalid, Message: "enterprise skill sha256 pin must be 64 hex characters"}
	}
	for _, c := range v {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return "", &ResolveError{Code: CodePackageInvalid, Message: "enterprise skill sha256 pin must be 64 hex characters"}
		}
	}
	return v, nil
}

// normalizeAttestedDigest canonicalizes an attested digest from an X-SHA256
// header or manifest field. An empty attestation normalizes to "" and is
// treated as "not attested" by callers.
func normalizeAttestedDigest(v string) string {
	v = strings.TrimSpace(strings.ToLower(v))
	v = strings.TrimPrefix(v, "sha256:")
	if len(v) != 64 {
		return ""
	}
	for _, c := range v {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return ""
		}
	}
	return v
}

func containsString(list []string, want string) bool {
	for _, item := range list {
		if strings.TrimSpace(item) == want {
			return true
		}
	}
	return false
}

func safeSegment(s string) string {
	if s == "" {
		return "_"
	}
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_', r == '.':
			b.WriteRune(r)
		default:
			b.WriteByte('_')
		}
	}
	out := b.String()
	if out == "." || out == ".." {
		return "_" + out
	}
	return out
}

func safePackagePath(p string) bool {
	if p == "" || strings.Contains(p, "\x00") || strings.HasPrefix(p, "/") || strings.Contains(p, "\\") {
		return false
	}
	clean := filepath.ToSlash(filepath.Clean(p))
	return clean != "." && clean == filepath.ToSlash(p) && !strings.HasPrefix(clean, "../")
}

func readZipFile(f *zip.File, limit int64) ([]byte, error) {
	rc, err := f.Open()
	if err != nil {
		return nil, err
	}
	defer rc.Close()
	return io.ReadAll(io.LimitReader(rc, limit+1))
}
