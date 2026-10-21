package handler

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strings"

	"github.com/multica-ai/multica/server/internal/enterprise"
	"github.com/multica-ai/multica/server/internal/platform"
	"github.com/multica-ai/multica/server/internal/service"
)

// Enterprise skill bundle resolution (TASK-C03, BND-142).
//
// Daemons request enterprise skills by publish_id + pinned sha256 (source
// "enterprise"); the server resolves them through the platform-backed
// pinned-version resolver instead of the workspace/builtin/plugin paths.
// Two failure shapes matter:
//
//   - The pinned revision is gone (payload hash mismatch, platform 4xx): the
//     request is answered 422. Serving the platform's current package under
//     an old pin is never allowed.
//   - The package is real but not installable as an enterprise local skill
//     (opc-client.json manifest violations, archive problems): failed-closed
//     per skill — the skill is dropped, its status is recorded in
//     enterprise_skill_status, and the task's remaining skills still resolve.
//
// Personal tasks never reach this path: enterprise refs resolve against no
// workspace row and keep the historical not-found behavior.

// enterpriseSkillStatus is the per-skill outcome annotation stamped on
// enterprise resolve responses.
type enterpriseSkillStatus struct {
	ID           string `json:"id"`
	Status       string `json:"status"`
	Code         string `json:"code,omitempty"`
	PinnedSHA256 string `json:"pinned_sha256,omitempty"`
}

const (
	enterpriseSkillStatusOK           = "ok"
	enterpriseSkillStatusFailedClosed = "failed_closed"
)

// enterpriseSkillsStatus values stamped on enterprise claim responses.
const (
	enterpriseSkillsStatusOK          = "ok"
	enterpriseSkillsStatusEmpty       = "empty"
	enterpriseSkillsStatusUnavailable = "unavailable"
)

// EnterpriseSkillRef is one platform-published skill handed to the daemon at
// claim time (TASK-C06). It is a daemon skill ref in the BND-142 pinned
// vocabulary: id is the platform publish_id, hash is the pinned skill
// manifest digest (sha256:<hex>, exactly what agent skill refs carry), so
// the daemon resolves it through the same pinned-version enterprise path.
type EnterpriseSkillRef struct {
	Source  string `json:"source"`
	ID      string `json:"id"`
	Name    string `json:"name"`
	Version string `json:"version"`
	Hash    string `json:"hash"`
}

// enterpriseSkillContext carries the BND-142 identity segments for the
// task's enterprise workspace. They come from the workspace link row and
// its user's live enterprise identity, never from daemon-supplied input.
type enterpriseSkillContext struct {
	issuer  string
	subject string
	tenant  string
}

// hasEnterpriseRefs reports whether the resolve request asks for any
// platform-published enterprise skill.
func hasEnterpriseRefs(skills []resolveSkillBundleRef) bool {
	for _, ref := range skills {
		if ref.Source == enterprise.Source {
			return true
		}
	}
	return false
}

// loadEnterpriseSkillContext resolves the cache-key identity segments for an
// enterprise workspace. A missing link row or an unlinked user is a 500: the
// claim checkpoint already proved both exist, so reaching the resolve
// endpoint without them means state changed underneath the task.
func (h *Handler) loadEnterpriseSkillContext(r *http.Request, workspaceID string) (*enterpriseSkillContext, error) {
	link, err := h.Queries.GetEnterpriseWorkspaceLinkByWorkspace(r.Context(), parseUUID(workspaceID))
	if err != nil {
		return nil, err
	}
	user, err := h.Queries.GetUser(r.Context(), link.UserID)
	if err != nil {
		return nil, err
	}
	if !user.EnterpriseSubject.Valid {
		return nil, errors.New("enterprise workspace link has no enterprise subject")
	}
	issuer := platform.DefaultIssuer
	if h.Platform != nil {
		issuer = h.Platform.Issuer()
	}
	return &enterpriseSkillContext{
		issuer:  issuer,
		subject: user.EnterpriseSubject.String,
		tenant:  link.PlatformTenant,
	}, nil
}

// resolveEnterpriseSkillBundle resolves one pinned enterprise skill. A nil
// error with a nil bundle means failed-closed: the caller records the
// returned status and continues with the remaining skills. A non-nil error
// is a request-level failure whose status/code the caller must write.
func (h *Handler) resolveEnterpriseSkillBundle(r *http.Request, entCtx *enterpriseSkillContext, ref resolveSkillBundleRef) (*service.AgentSkillData, *enterpriseSkillStatus, error) {
	pin, err := enterprise.NormalizeSHA256(ref.Hash)
	if err != nil {
		return nil, nil, err
	}
	if h.EnterpriseSkillResolver == nil {
		return nil, nil, &enterprise.ResolveError{Code: enterprise.CodeNotConfigured, Message: "enterprise skill resolver is not configured"}
	}
	bundle, err := h.EnterpriseSkillResolver.Resolve(r.Context(), enterprise.Ref{
		Issuer:    entCtx.issuer,
		Subject:   entCtx.subject,
		Tenant:    entCtx.tenant,
		PublishID: ref.ID,
		SHA256:    pin,
	})
	if err != nil {
		return nil, nil, err
	}
	data := &service.AgentSkillData{
		ID:          bundle.PublishID,
		Source:      enterprise.Source,
		Name:        bundle.Name,
		Description: bundle.Description,
		Hash:        "sha256:" + pin,
		Content:     bundle.Content,
	}
	for _, file := range bundle.Files {
		data.Files = append(data.Files, service.AgentSkillFileData{Path: file.Path, Content: file.Content})
	}
	return data, &enterpriseSkillStatus{
		ID:           ref.ID,
		Status:       enterpriseSkillStatusOK,
		PinnedSHA256: pin,
	}, nil
}

// writeEnterpriseResolveFailure maps a resolver failure onto the HTTP
// response. Hash mismatches and platform 4xx (the pinned revision is gone)
// are 422; a missing resolver is a deployment error (500); everything
// upstream-transient is 502. Manifest and package violations never reach
// this function — they are failed-closed per skill.
func writeEnterpriseResolveFailure(w http.ResponseWriter, err error) {
	var resolveErr *enterprise.ResolveError
	if errors.As(err, &resolveErr) {
		switch resolveErr.Code {
		case enterprise.CodeNotConfigured:
			writeErrorCode(w, http.StatusInternalServerError, resolveErr.Code, resolveErr.Message)
		case enterprise.CodePackageInvalid:
			// A malformed pin from the daemon is a client error, not a
			// missing revision.
			writeErrorCode(w, http.StatusBadRequest, resolveErr.Code, resolveErr.Message)
		default:
			writeErrorCode(w, http.StatusUnprocessableEntity, resolveErr.Code, resolveErr.Message)
		}
		return
	}
	var apiErr *platform.APIError
	if errors.As(err, &apiErr) {
		if apiErr.StatusCode >= 400 && apiErr.StatusCode < 500 {
			code := apiErr.Code
			if code == "" {
				code = enterprise.CodeHashMismatch
			}
			writeErrorCode(w, http.StatusUnprocessableEntity, code, apiErr.Message)
			return
		}
		writeErrorCode(w, http.StatusBadGateway, "enterprise_skill_platform_error", "failed to reach identity platform for enterprise skill")
		return
	}
	writeErrorCode(w, http.StatusBadGateway, "enterprise_skill_platform_error", "failed to reach identity platform for enterprise skill")
}

// enterpriseFailedClosedStatus builds the per-skill failed-closed annotation
// for a resolver error that permits the rest of the task to continue.
func enterpriseFailedClosedStatus(ref resolveSkillBundleRef, err error) *enterpriseSkillStatus {
	status := &enterpriseSkillStatus{ID: ref.ID, Status: enterpriseSkillStatusFailedClosed}
	var resolveErr *enterprise.ResolveError
	if errors.As(err, &resolveErr) {
		status.Code = resolveErr.Code
		return status
	}
	var apiErr *platform.APIError
	if errors.As(err, &apiErr) && apiErr.Code != "" {
		status.Code = apiErr.Code
		return status
	}
	status.Code = enterprise.CodePackageInvalid
	return status
}

// isEnterpriseFailedClosed reports whether a resolver error is a per-skill
// failed-closed condition (the skill is dropped, the task continues) rather
// than a request-level 422/5xx.
func isEnterpriseFailedClosed(err error) bool {
	return enterprise.IsCode(err, enterprise.CodeManifestInvalid) ||
		enterprise.IsCode(err, enterprise.CodePackageInvalid)
}

// enterpriseSkillsIssuedPayload encodes the claim-issued enterprise skill set
// for persistence via FinalizeTaskClaim (M-5). Personal claims return nil (no
// write); enterprise claims always encode — including the empty set, which
// replaces whatever an earlier claim generation issued so ResolveTaskSkillBundles
// intersects against exactly what THIS claim handed out.
func enterpriseSkillsIssuedPayload(resp *AgentTaskResponse) []byte {
	if resp == nil || !resp.Enterprise {
		return nil
	}
	refs := make([]struct {
		ID   string `json:"id"`
		Hash string `json:"hash"`
	}, 0, len(resp.EnterpriseSkills))
	for _, ref := range resp.EnterpriseSkills {
		refs = append(refs, struct {
			ID   string `json:"id"`
			Hash string `json:"hash"`
		}{ID: ref.ID, Hash: ref.Hash})
	}
	payload, err := json.Marshal(refs)
	if err != nil {
		// Strings cannot fail json.Marshal; this is only a linter-proof guard.
		return json.RawMessage("[]")
	}
	return payload
}

// enterpriseIssuedSkillKey builds the set key for one issued/requested
// enterprise ref. Both sides of the intersection must match on publish_id AND
// pinned hash: an id-only match would let a daemon re-pin an issued id at a
// revision the claim never attested.
func enterpriseIssuedSkillKey(id, hash string) string {
	return id + "\x1f" + hash
}

// issuedEnterpriseSkillSet extracts the claim-issued enterprise skill set
// from the task row's context JSON (written by SetTaskEnterpriseSkillsIssued
// at finalize time). A missing or undecodable set yields an empty map: on an
// enterprise task that means "nothing was issued", which fails closed at
// resolve.
func issuedEnterpriseSkillSet(contextJSON []byte) map[string]struct{} {
	out := make(map[string]struct{})
	if len(contextJSON) == 0 {
		return out
	}
	var ctx struct {
		Issued []struct {
			ID   string `json:"id"`
			Hash string `json:"hash"`
		} `json:"enterprise_skills_issued"`
	}
	if err := json.Unmarshal(contextJSON, &ctx); err != nil {
		return out
	}
	for _, ref := range ctx.Issued {
		if ref.ID == "" || ref.Hash == "" {
			continue
		}
		out[enterpriseIssuedSkillKey(ref.ID, ref.Hash)] = struct{}{}
	}
	return out
}

// enterpriseClaimSkills lists the platform-published skills the enterprise
// task's originating user is entitled to and maps them onto daemon refs.
// It fails closed per claim: a missing link, an unlinked user, a platform
// error or nothing pinnable all yield (nil, "unavailable") and never block
// the claim; an entitled-but-empty listing is "empty". The listing is
// narrowed to the workspace link's platform tenant — the issuance source is
// the link row, so the narrow key comes from it and not from any
// daemon-presented material.
func (h *Handler) enterpriseClaimSkills(r *http.Request, workspaceID string) ([]EnterpriseSkillRef, string) {
	if h.Platform == nil || h.Queries == nil {
		return nil, enterpriseSkillsStatusUnavailable
	}
	link, err := h.Queries.GetEnterpriseWorkspaceLinkByWorkspace(r.Context(), parseUUID(workspaceID))
	if err != nil {
		slog.Warn("daemon claim: enterprise skills workspace link unavailable",
			"workspace_id", workspaceID, "error", err)
		return nil, enterpriseSkillsStatusUnavailable
	}
	user, err := h.Queries.GetUser(r.Context(), link.UserID)
	if err != nil || !user.EnterpriseSubject.Valid {
		slog.Warn("daemon claim: enterprise skills originating user unavailable",
			"workspace_id", workspaceID, "error", err)
		return nil, enterpriseSkillsStatusUnavailable
	}

	listings, err := h.Platform.ListInternalSkills(r.Context(), user.EnterpriseSubject.String, link.PlatformTenant)
	if err != nil {
		slog.Warn("daemon claim: platform skill listing failed",
			"subject", user.EnterpriseSubject.String, "tenant", link.PlatformTenant, "error", err)
		return nil, enterpriseSkillsStatusUnavailable
	}
	refs := make([]EnterpriseSkillRef, 0, len(listings))
	for _, listing := range listings {
		if strings.TrimSpace(listing.PublishID) == "" {
			continue
		}
		pin, err := enterprise.NormalizeSHA256(listing.Pin())
		if err != nil {
			slog.Warn("daemon claim: skipping enterprise skill with unpinnable manifest digest",
				"publish_id", listing.PublishID, "error", err)
			continue
		}
		name := strings.TrimSpace(listing.Name)
		if name == "" {
			name = strings.TrimSpace(listing.SkillID)
		}
		if name == "" {
			name = listing.PublishID
		}
		refs = append(refs, EnterpriseSkillRef{
			Source:  enterprise.Source,
			ID:      listing.PublishID,
			Name:    name,
			Version: strings.TrimSpace(listing.Version),
			Hash:    "sha256:" + pin,
		})
	}
	if len(refs) == 0 {
		if len(listings) > 0 {
			slog.Warn("daemon claim: platform listed skills but none pinned cleanly",
				"subject", user.EnterpriseSubject.String, "tenant", link.PlatformTenant, "listed", len(listings))
			return nil, enterpriseSkillsStatusUnavailable
		}
		return nil, enterpriseSkillsStatusEmpty
	}
	return refs, enterpriseSkillsStatusOK
}
