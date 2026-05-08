package server

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/Infisical/agent-vault/internal/policy"
	"github.com/Infisical/agent-vault/internal/store"
)

type grantCreateRequest struct {
	// Either Source (a YAML/JSON Grant document) or the structured
	// fields below. The structured form is preferred for the API; the
	// YAML form is convenient for the CLI.
	Source string `json:"source,omitempty"`

	SubjectType   string `json:"subject_type,omitempty"` // "agent" | "user"
	SubjectID     string `json:"subject_id,omitempty"`   // agent/user id
	SubjectName   string `json:"subject_name,omitempty"` // resolved server-side if SubjectID empty
	PolicyID      string `json:"policy_id,omitempty"`
	PolicyVersion int    `json:"policy_version,omitempty"` // 0 = always-latest
	ExpiresAt     string `json:"expires_at,omitempty"`     // RFC3339; "" = no expiry

	Conditions map[string]any `json:"conditions,omitempty"`
}

func (s *Server) handleGrantCreate(w http.ResponseWriter, r *http.Request) {
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

	var req grantCreateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	if req.Source != "" {
		g, err := policy.LoadGrant([]byte(req.Source))
		if err != nil {
			jsonError(w, http.StatusBadRequest, err.Error())
			return
		}
		if g.Metadata.Vault != "" && g.Metadata.Vault != ns.Name {
			jsonError(w, http.StatusBadRequest, "grant metadata.vault does not match URL vault")
			return
		}
		req.SubjectType = string(g.Spec.Subject.ActorType)
		req.SubjectID = g.Spec.Subject.ActorID
		req.PolicyID = g.Spec.PolicyRef.ID
		req.PolicyVersion = g.Spec.PolicyRef.Version
		if g.Spec.ExpiresAt != nil {
			req.ExpiresAt = g.Spec.ExpiresAt.UTC().Format(time.RFC3339)
		}
		req.Conditions = map[string]any{
			"require_human_approval": g.Spec.Conditions.RequireHumanApproval,
		}
	}

	// Resolve agent name to id if caller supplied a name.
	if req.SubjectID == "" && req.SubjectName != "" && req.SubjectType == "agent" {
		ag, err := s.store.GetAgentByName(ctx, req.SubjectName)
		if err != nil || ag == nil {
			jsonError(w, http.StatusNotFound, fmt.Sprintf("Agent %q not found", req.SubjectName))
			return
		}
		req.SubjectID = ag.ID
	}
	if req.SubjectType == "" || req.SubjectID == "" {
		jsonError(w, http.StatusBadRequest, "subject_type and subject_id (or subject_name for agents) are required")
		return
	}
	if req.PolicyID == "" {
		jsonError(w, http.StatusBadRequest, "policy_id is required")
		return
	}

	// Reject if the subject doesn't actually exist in this vault.
	if req.SubjectType == "agent" {
		if _, err := s.store.GetAgentByID(ctx, req.SubjectID); err != nil {
			jsonError(w, http.StatusBadRequest, "subject agent not found")
			return
		}
	} else if req.SubjectType == "user" {
		if _, err := s.store.GetUserByID(ctx, req.SubjectID); err != nil {
			jsonError(w, http.StatusBadRequest, "subject user not found")
			return
		}
	} else {
		jsonError(w, http.StatusBadRequest, "subject_type must be 'agent' or 'user'")
		return
	}

	// Verify policy exists in this vault.
	prow, err := s.policyStore.GetPolicyVersion(ctx, ns.ID, req.PolicyID, req.PolicyVersion)
	if err != nil || prow == nil {
		jsonError(w, http.StatusBadRequest, fmt.Sprintf("Policy %s@%d not found in vault", req.PolicyID, req.PolicyVersion))
		return
	}

	var expiresAt *time.Time
	if req.ExpiresAt != "" {
		t, err := time.Parse(time.RFC3339, req.ExpiresAt)
		if err != nil {
			jsonError(w, http.StatusBadRequest, "expires_at must be RFC3339")
			return
		}
		expiresAt = &t
	}

	condJSON, err := store.MarshalGrantConditions(req.Conditions)
	if err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}

	row := store.GrantRow{
		VaultID:       ns.ID,
		SubjectType:   req.SubjectType,
		SubjectID:     req.SubjectID,
		PolicyID:      req.PolicyID,
		PolicyVersion: req.PolicyVersion,
		Conditions:    condJSON,
		ExpiresAt:     expiresAt,
		GrantedBy:     actor.ID,
	}
	saved, err := s.policyStore.InsertGrant(ctx, row)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "Failed to create grant: "+err.Error())
		return
	}

	sess := sessionFromContext(ctx)
	sessID := ""
	if sess != nil {
		sessID = sess.ID
	}
	_ = s.policyStore.InsertPolicyAudit(ctx, store.PolicyAuditRow{
		VaultID:   ns.ID,
		EventType: "grant.create",
		Subject:   fmt.Sprintf("%s:%s", saved.SubjectType, saved.SubjectID),
		PolicyRef: fmt.Sprintf("%s@%d", saved.PolicyID, saved.PolicyVersion),
		GrantID:   saved.ID,
		ActorID:   actor.ID,
		ActorType: actor.Type,
		SessionID: sessID,
	})

	subjectNames, err := s.resolveGrantSubjectNames(ctx, []store.GrantRow{saved})
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "Failed to resolve grant subject")
		return
	}
	jsonCreated(w, grantResponse(saved, subjectNames, store.GrantDecisionStat{}))
}

func (s *Server) handleGrantList(w http.ResponseWriter, r *http.Request) {
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

	subject := r.URL.Query().Get("subject")
	var rows []store.GrantRow
	var err error
	if subject != "" {
		typ, id, ok := splitSubject(subject)
		if !ok {
			jsonError(w, http.StatusBadRequest, "subject must be 'agent:<id>' or 'user:<id>'")
			return
		}
		// Allow subject_name lookup for agents.
		if typ == "agent" && !looksLikeAgentID(id) {
			ag, err := s.store.GetAgentByName(ctx, id)
			if err == nil && ag != nil {
				id = ag.ID
			}
		}
		rows, err = s.policyStore.ListActiveGrantsForSubject(ctx, ns.ID, typ, id)
	} else {
		rows, err = s.policyStore.ListGrantsForVault(ctx, ns.ID)
	}
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "Failed to list grants")
		return
	}
	subjectNames, err := s.resolveGrantSubjectNames(ctx, rows)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "Failed to resolve grant subjects")
		return
	}
	decisionCounts, err := s.policyStore.ListGrantDecisionStats(ctx, ns.ID)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "Failed to load grant decision counts")
		return
	}
	decisionByGrantID := make(map[string]store.GrantDecisionStat, len(decisionCounts))
	for _, d := range decisionCounts {
		decisionByGrantID[d.GrantID] = d
	}
	out := make([]map[string]any, 0, len(rows))
	for _, g := range rows {
		out = append(out, grantResponse(g, subjectNames, decisionByGrantID[g.ID]))
	}
	jsonOK(w, map[string]any{"grants": out})
}

func (s *Server) handleGrantGet(w http.ResponseWriter, r *http.Request) {
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
	row, err := s.policyStore.GetGrant(ctx, ns.ID, id)
	if err != nil || row == nil {
		jsonError(w, http.StatusNotFound, fmt.Sprintf("Grant %q not found", id))
		return
	}
	subjectNames, err := s.resolveGrantSubjectNames(ctx, []store.GrantRow{*row})
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "Failed to resolve grant subject")
		return
	}
	decisionCounts, err := s.policyStore.ListGrantDecisionStats(ctx, ns.ID)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "Failed to load grant decision counts")
		return
	}
	var decisionStat store.GrantDecisionStat
	for _, d := range decisionCounts {
		if d.GrantID == row.ID {
			decisionStat = d
			break
		}
	}
	jsonOK(w, grantResponse(*row, subjectNames, decisionStat))
}

func (s *Server) handleGrantRevoke(w http.ResponseWriter, r *http.Request) {
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
	if err := s.policyStore.RevokeGrant(ctx, ns.ID, id, actor.ID); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			jsonError(w, http.StatusNotFound, fmt.Sprintf("Grant %q not found or already revoked", id))
			return
		}
		jsonError(w, http.StatusInternalServerError, "Failed to revoke grant: "+err.Error())
		return
	}
	sess := sessionFromContext(ctx)
	sessID := ""
	if sess != nil {
		sessID = sess.ID
	}
	_ = s.policyStore.InsertPolicyAudit(ctx, store.PolicyAuditRow{
		VaultID:   ns.ID,
		EventType: "grant.revoke",
		GrantID:   id,
		ActorID:   actor.ID,
		ActorType: actor.Type,
		SessionID: sessID,
	})
	jsonOK(w, map[string]any{"id": id, "status": "revoked"})
}

// Body upload variant: POST a YAML grant document directly.
func (s *Server) handleGrantCreateYAML(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		jsonError(w, http.StatusBadRequest, "Read body failed")
		return
	}
	wrapped := struct {
		Source string `json:"source"`
	}{Source: string(body)}
	js, _ := json.Marshal(wrapped)
	r.Body = io.NopCloser(strings.NewReader(string(js)))
	r.Header.Set("Content-Type", "application/json")
	s.handleGrantCreate(w, r)
}

// splitSubject parses "agent:foo" or "user:bar" into (type, id, ok).
func splitSubject(s string) (string, string, bool) {
	idx := strings.IndexByte(s, ':')
	if idx <= 0 || idx == len(s)-1 {
		return "", "", false
	}
	typ := s[:idx]
	id := s[idx+1:]
	if typ != "agent" && typ != "user" {
		return "", "", false
	}
	return typ, id, true
}

// looksLikeAgentID is a heuristic: agent IDs are ULIDs or hex blobs;
// names are lowercase slugs. We prefer name resolution when the input
// doesn't look like an opaque ID.
func looksLikeAgentID(s string) bool {
	if len(s) < 20 {
		return false
	}
	for _, c := range s {
		if !(c >= '0' && c <= '9') && !(c >= 'A' && c <= 'Z') && !(c >= 'a' && c <= 'z') {
			return false
		}
	}
	return true
}

func (s *Server) resolveGrantSubjectNames(ctx context.Context, rows []store.GrantRow) (map[string]string, error) {
	out := make(map[string]string, len(rows))
	for _, g := range rows {
		k := g.SubjectType + ":" + g.SubjectID
		if _, ok := out[k]; ok {
			continue
		}
		switch g.SubjectType {
		case "agent":
			ag, err := s.store.GetAgentByID(ctx, g.SubjectID)
			if err != nil {
				return nil, err
			}
			if ag != nil {
				out[k] = ag.Name
			}
		case "user":
			u, err := s.store.GetUserByID(ctx, g.SubjectID)
			if err != nil {
				return nil, err
			}
			if u != nil {
				out[k] = u.Email
			}
		}
	}
	return out, nil
}

func grantResponse(g store.GrantRow, subjectNames map[string]string, decisionStat store.GrantDecisionStat) map[string]any {
	k := g.SubjectType + ":" + g.SubjectID
	out := map[string]any{
		"id":                   g.ID,
		"subject_type":         g.SubjectType,
		"subject_id":           g.SubjectID,
		"subject_name":         subjectNames[k],
		"policy_id":            g.PolicyID,
		"policy_version":       g.PolicyVersion,
		"conditions":           json.RawMessage(g.Conditions),
		"granted_by":           g.GrantedBy,
		"granted_at":           g.GrantedAt.Format(time.RFC3339),
		"decision_allow_count": decisionStat.AllowCount,
		"decision_deny_count":  decisionStat.DenyCount,
	}
	if g.ExpiresAt != nil {
		out["expires_at"] = g.ExpiresAt.Format(time.RFC3339)
	}
	if g.RevokedAt != nil {
		out["revoked_at"] = g.RevokedAt.Format(time.RFC3339)
		out["revoked_by"] = g.RevokedBy
	}
	return out
}
