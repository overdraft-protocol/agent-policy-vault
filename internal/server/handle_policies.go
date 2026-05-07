package server

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/Infisical/agent-vault/internal/policy"
	"github.com/Infisical/agent-vault/internal/store"
)

// PolicyService is the persistence surface used by the policy/grant
// HTTP handlers. Decoupled from the main Store interface so the server
// stays compilable in environments that don't enable the policy
// engine; the cmd/server.go bootstrap wires it from the SQLite store.
type PolicyService interface {
	store.PolicyStore
}

// AttachPolicyService binds the SQLite-backed policy persistence to
// this server. Must be called once before Start. nil disables the
// policy/grant management endpoints (they will return 503).
func (s *Server) AttachPolicyService(p PolicyService) { s.policyStore = p }

// policy management endpoints — registered when policyStore is set.

// handlePolicyCreate persists a new policy version. Body is the
// canonical YAML (or JSON) source of the Policy. Version is assigned
// server-side as max(version)+1; parent_hash is the previous version's
// content_hash. Only users with vault member or admin role may call.
func (s *Server) handlePolicyCreate(w http.ResponseWriter, r *http.Request) {
	if s.policyStore == nil {
		jsonError(w, http.StatusServiceUnavailable, "Policy engine not enabled")
		return
	}
	ctx := r.Context()
	vaultName := r.PathValue("vault")
	ns, err := s.store.GetVault(ctx, vaultName)
	if err != nil || ns == nil {
		jsonError(w, http.StatusNotFound, fmt.Sprintf("Vault %q not found", vaultName))
		return
	}
	actor, err := s.requirePolicyAuthor(w, r, ns.ID)
	if err != nil {
		return
	}

	src, err := io.ReadAll(r.Body)
	if err != nil {
		jsonError(w, http.StatusBadRequest, "Read body failed")
		return
	}
	p, err := policy.LoadPolicy(src)
	if err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	if p.Metadata.Vault != "" && p.Metadata.Vault != vaultName {
		jsonError(w, http.StatusBadRequest, "policy metadata.vault does not match URL vault")
		return
	}

	nextVer, parentHash, err := s.policyStore.NextPolicyVersion(ctx, ns.ID, p.Metadata.ID)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "Failed to allocate policy version")
		return
	}
	p.Metadata.Version = nextVer
	p.Metadata.ParentHash = parentHash

	hash, err := policy.CanonicalHash(p)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "Failed to hash policy: "+err.Error())
		return
	}

	sess := sessionFromContext(ctx)
	sessID := ""
	if sess != nil {
		sessID = sess.ID
	}

	row := store.PolicyRow{
		VaultID:         ns.ID,
		PolicyID:        p.Metadata.ID,
		Version:         nextVer,
		Enabled:         true,
		YAMLSource:      string(src),
		ContentHash:     hash,
		ParentHash:      parentHash,
		Description:     p.Metadata.Description,
		AuthoredBy:      actor.ID,
		AuthoredSession: sessID,
	}
	saved, err := s.policyStore.InsertPolicyVersion(ctx, row)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "Failed to insert policy: "+err.Error())
		return
	}
	_ = s.policyStore.InsertPolicyAudit(ctx, store.PolicyAuditRow{
		VaultID:   ns.ID,
		EventType: "policy.create",
		PolicyRef: fmt.Sprintf("%s@%d", saved.PolicyID, saved.Version),
		Decision:  "",
		ActorID:   actor.ID,
		ActorType: actor.Type,
		SessionID: sessID,
	})
	jsonCreated(w, policyResponse(saved))
}

func (s *Server) handlePolicyList(w http.ResponseWriter, r *http.Request) {
	if s.policyStore == nil {
		jsonError(w, http.StatusServiceUnavailable, "Policy engine not enabled")
		return
	}
	ctx := r.Context()
	ns, ok := s.lookupVault(w, r)
	if !ok {
		return
	}
	if _, err := s.requireVaultAccess(w, r, ns.ID); err != nil {
		return
	}
	rows, err := s.policyStore.ListPolicies(ctx, ns.ID)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "Failed to list policies")
		return
	}
	out := make([]map[string]any, 0, len(rows))
	for _, p := range rows {
		out = append(out, policyResponse(p))
	}
	jsonOK(w, map[string]any{"policies": out})
}

func (s *Server) handlePolicyGet(w http.ResponseWriter, r *http.Request) {
	if s.policyStore == nil {
		jsonError(w, http.StatusServiceUnavailable, "Policy engine not enabled")
		return
	}
	ctx := r.Context()
	ns, ok := s.lookupVault(w, r)
	if !ok {
		return
	}
	if _, err := s.requireVaultAccess(w, r, ns.ID); err != nil {
		return
	}
	id := r.PathValue("id")
	row, err := s.policyStore.GetLatestPolicy(ctx, ns.ID, id)
	if err != nil || row == nil {
		jsonError(w, http.StatusNotFound, fmt.Sprintf("Policy %q not found", id))
		return
	}
	jsonOK(w, policyResponse(*row))
}

func (s *Server) handlePolicyVersions(w http.ResponseWriter, r *http.Request) {
	if s.policyStore == nil {
		jsonError(w, http.StatusServiceUnavailable, "Policy engine not enabled")
		return
	}
	ctx := r.Context()
	ns, ok := s.lookupVault(w, r)
	if !ok {
		return
	}
	if _, err := s.requireVaultAccess(w, r, ns.ID); err != nil {
		return
	}
	id := r.PathValue("id")
	rows, err := s.policyStore.ListPolicyVersions(ctx, ns.ID, id)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "Failed to list policy versions")
		return
	}
	out := make([]map[string]any, 0, len(rows))
	for _, p := range rows {
		out = append(out, policyResponse(p))
	}
	jsonOK(w, map[string]any{"versions": out})
}

func (s *Server) handlePolicyDisable(w http.ResponseWriter, r *http.Request) {
	if s.policyStore == nil {
		jsonError(w, http.StatusServiceUnavailable, "Policy engine not enabled")
		return
	}
	ctx := r.Context()
	ns, ok := s.lookupVault(w, r)
	if !ok {
		return
	}
	actor, err := s.requirePolicyAuthor(w, r, ns.ID)
	if err != nil {
		return
	}
	id := r.PathValue("id")
	if err := s.policyStore.DisablePolicy(ctx, ns.ID, id); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			jsonError(w, http.StatusNotFound, fmt.Sprintf("Policy %q not found or already disabled", id))
			return
		}
		jsonError(w, http.StatusInternalServerError, "Failed to disable policy: "+err.Error())
		return
	}
	sess := sessionFromContext(ctx)
	sessID := ""
	if sess != nil {
		sessID = sess.ID
	}
	_ = s.policyStore.InsertPolicyAudit(ctx, store.PolicyAuditRow{
		VaultID:   ns.ID,
		EventType: "policy.disable",
		PolicyRef: id,
		ActorID:   actor.ID,
		ActorType: actor.Type,
		SessionID: sessID,
	})
	jsonOK(w, map[string]any{"id": id, "status": "disabled"})
}

// handlePolicyAudit lists recent policy audit rows for a vault.
func (s *Server) handlePolicyAudit(w http.ResponseWriter, r *http.Request) {
	if s.policyStore == nil {
		jsonError(w, http.StatusServiceUnavailable, "Policy engine not enabled")
		return
	}
	ctx := r.Context()
	ns, ok := s.lookupVault(w, r)
	if !ok {
		return
	}
	if _, err := s.requireVaultAccess(w, r, ns.ID); err != nil {
		return
	}
	opts := store.ListPolicyAuditOpts{
		VaultID:   ns.ID,
		Subject:   r.URL.Query().Get("subject"),
		EventType: r.URL.Query().Get("event_type"),
	}
	rows, err := s.policyStore.ListPolicyAudit(ctx, opts)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "Failed to list policy audit")
		return
	}
	out := make([]map[string]any, 0, len(rows))
	for _, a := range rows {
		out = append(out, map[string]any{
			"id":          a.ID,
			"event_type":  a.EventType,
			"subject":     a.Subject,
			"policy_ref":  a.PolicyRef,
			"grant_id":    a.GrantID,
			"rule_id":     a.RuleID,
			"decision":    a.Decision,
			"reason":      a.Reason,
			"detail":      json.RawMessage(a.Detail),
			"actor_id":    a.ActorID,
			"actor_type":  a.ActorType,
			"session_id":  a.SessionID,
			"occurred_at": a.OccurredAt.Format(time.RFC3339),
		})
	}
	jsonOK(w, map[string]any{"events": out})
}

// requirePolicyAuthor enforces "users with member+ vault role only".
// Agents (proxy or otherwise) are forbidden from mutating policies and
// grants — this is the trust boundary between principals and agents.
func (s *Server) requirePolicyAuthor(w http.ResponseWriter, r *http.Request, vaultID string) (*Actor, error) {
	actor, err := s.requireVaultMember(w, r, vaultID)
	if err != nil {
		return nil, err
	}
	if actor == nil {
		// Scoped session path: require admin role and reject proxy
		// scope by virtue of requireVaultMember already enforcing
		// member-or-better; but a scoped agent with role=member should
		// still not author policies. Cross-check:
		sess := sessionFromContext(r.Context())
		if sess != nil && sess.AgentID != "" {
			jsonError(w, http.StatusForbidden, "Agents cannot author policies")
			return nil, fmt.Errorf("agent in scoped session")
		}
		return nil, nil
	}
	if actor.Type != "user" {
		jsonError(w, http.StatusForbidden, "Only users can author policies")
		return nil, fmt.Errorf("not a user")
	}
	return actor, nil
}

func (s *Server) lookupVault(w http.ResponseWriter, r *http.Request) (*store.Vault, bool) {
	ctx := r.Context()
	vaultName := r.PathValue("vault")
	ns, err := s.store.GetVault(ctx, vaultName)
	if err != nil || ns == nil {
		jsonError(w, http.StatusNotFound, fmt.Sprintf("Vault %q not found", vaultName))
		return nil, false
	}
	return ns, true
}

func policyResponse(p store.PolicyRow) map[string]any {
	return map[string]any{
		"id":           p.PolicyID,
		"version":      p.Version,
		"enabled":      p.Enabled,
		"description":  p.Description,
		"yaml_source":  p.YAMLSource,
		"content_hash": p.ContentHash,
		"parent_hash":  p.ParentHash,
		"authored_by":  p.AuthoredBy,
		"authored_at":  p.AuthoredAt.Format(time.RFC3339),
	}
}

