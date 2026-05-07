package cmd

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/spf13/cobra"
)

// grantJSON mirrors server.grantResponse so the CLI doesn't depend
// on the store row type directly.
type grantJSON struct {
	ID            string          `json:"id"`
	SubjectType   string          `json:"subject_type"`
	SubjectID     string          `json:"subject_id"`
	PolicyID      string          `json:"policy_id"`
	PolicyVersion int             `json:"policy_version"`
	Conditions    json.RawMessage `json:"conditions"`
	ExpiresAt     string          `json:"expires_at"`
	GrantedBy     string          `json:"granted_by"`
	GrantedAt     string          `json:"granted_at"`
	RevokedAt     string          `json:"revoked_at"`
	RevokedBy     string          `json:"revoked_by"`
}

var grantCmd = &cobra.Command{
	Use:   "grants",
	Short: "Manage permission grants in a vault",
}

var grantCreateCmd = &cobra.Command{
	Use:   "create",
	Short: "Create a permission grant binding a subject to a policy",
	Long: `Create a grant of the form:
  --agent <name|id>      grant to an agent (subject_type=agent)
  --user  <email|id>     grant to a user  (subject_type=user)

Policy reference syntax: --policy <policy_id>[@<version>]
Omitting @<version> creates an "always-latest" grant.

Examples:
  agent-vault vault grants create --agent support-bot --policy stripe-readonly@3 \\
    --vault prod --expires 30d
  agent-vault vault grants create --user me@example.com --policy stripe-readonly \\
    --vault prod`,
	Args: cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		agent, _ := cmd.Flags().GetString("agent")
		user, _ := cmd.Flags().GetString("user")
		policyRef, _ := cmd.Flags().GetString("policy")
		expires, _ := cmd.Flags().GetString("expires")
		conditionsRaw, _ := cmd.Flags().GetString("conditions")

		if agent == "" && user == "" {
			return fmt.Errorf("--agent or --user is required")
		}
		if agent != "" && user != "" {
			return fmt.Errorf("--agent and --user are mutually exclusive")
		}
		if policyRef == "" {
			return fmt.Errorf("--policy <policy_id>[@<version>] is required")
		}
		policyID, ver, err := parsePolicyRef(policyRef)
		if err != nil {
			return err
		}

		// Build the JSON body the server expects (handle_grants.go).
		body := map[string]any{
			"policy_id": policyID,
		}
		if ver > 0 {
			body["policy_version"] = ver
		}
		switch {
		case agent != "":
			body["subject_type"] = "agent"
			// Server accepts either subject_id (raw id) or subject_name
			// (resolved against the agents table). We pass subject_name
			// so users can use either an ID or a friendly name.
			body["subject_name"] = agent
		case user != "":
			body["subject_type"] = "user"
			body["subject_name"] = user
		}
		if expires != "" {
			t, err := parseExpiresAt(expires)
			if err != nil {
				return err
			}
			body["expires_at"] = t.Format(time.RFC3339)
		}
		if conditionsRaw != "" {
			// Validate that --conditions is parseable JSON before sending.
			var probe any
			if err := json.Unmarshal([]byte(conditionsRaw), &probe); err != nil {
				return fmt.Errorf("--conditions must be valid JSON: %w", err)
			}
			body["conditions"] = json.RawMessage(conditionsRaw)
		}
		raw, err := json.Marshal(body)
		if err != nil {
			return err
		}

		vault := resolveVault(cmd)
		sess, err := ensureSession()
		if err != nil {
			return err
		}
		reqURL := fmt.Sprintf("%s/v1/vaults/%s/grants", sess.Address, url.PathEscape(vault))
		respBody, err := doAdminRequestWithBody("POST", reqURL, sess.Token, raw)
		if err != nil {
			return err
		}

		var g grantJSON
		if err := json.Unmarshal(respBody, &g); err != nil {
			return fmt.Errorf("parsing response: %w", err)
		}
		fmt.Fprintf(cmd.OutOrStdout(), "%s Granted %s to %s:%s (%s)\n",
			successText("✓"),
			policyRefDisplay(g.PolicyID, g.PolicyVersion),
			g.SubjectType, g.SubjectID,
			mutedText("id="+g.ID),
		)
		return nil
	},
}

var grantListCmd = &cobra.Command{
	Use:   "list",
	Short: "List grants in a vault",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		agent, _ := cmd.Flags().GetString("agent")
		user, _ := cmd.Flags().GetString("user")
		subject, _ := cmd.Flags().GetString("subject")

		vault := resolveVault(cmd)
		sess, err := ensureSession()
		if err != nil {
			return err
		}

		// --agent/--user are convenience shortcuts; --subject takes the
		// raw "type:id" form expected by the server.
		switch {
		case subject != "":
			// already in correct form
		case agent != "":
			subject = "agent:" + agent
		case user != "":
			subject = "user:" + user
		}

		reqURL := fmt.Sprintf("%s/v1/vaults/%s/grants", sess.Address, url.PathEscape(vault))
		if subject != "" {
			reqURL += "?subject=" + url.QueryEscape(subject)
		}
		respBody, err := doAdminRequestWithBody("GET", reqURL, sess.Token, nil)
		if err != nil {
			return err
		}
		var resp struct {
			Grants []grantJSON `json:"grants"`
		}
		if err := json.Unmarshal(respBody, &resp); err != nil {
			return fmt.Errorf("parsing response: %w", err)
		}
		if len(resp.Grants) == 0 {
			fmt.Fprintf(cmd.OutOrStdout(), "No grants in vault %q.\n", vault)
			return nil
		}
		t := newTable(cmd.OutOrStdout())
		t.AppendHeader(table.Row{"ID", "SUBJECT", "POLICY", "EXPIRES", "STATUS", "GRANTED"})
		for _, g := range resp.Grants {
			subj := fmt.Sprintf("%s:%s", g.SubjectType, g.SubjectID)
			pol := policyRefDisplay(g.PolicyID, g.PolicyVersion)
			expires := formatTime(g.ExpiresAt)
			if expires == "" {
				expires = mutedText("never")
			}
			status := successText("active")
			if g.RevokedAt != "" {
				status = errorText("revoked")
			} else if g.ExpiresAt != "" {
				if exp, err := time.Parse(time.RFC3339, g.ExpiresAt); err == nil && time.Now().After(exp) {
					status = mutedText("expired")
				}
			}
			t.AppendRow(table.Row{g.ID, subj, pol, expires, status, formatTime(g.GrantedAt)})
		}
		t.Render()
		return nil
	},
}

var grantShowCmd = &cobra.Command{
	Use:   "show <id>",
	Short: "Show a grant's full details",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		id := args[0]
		vault := resolveVault(cmd)
		sess, err := ensureSession()
		if err != nil {
			return err
		}
		reqURL := fmt.Sprintf("%s/v1/vaults/%s/grants/%s",
			sess.Address, url.PathEscape(vault), url.PathEscape(id))
		respBody, err := doAdminRequestWithBody("GET", reqURL, sess.Token, nil)
		if err != nil {
			return err
		}
		var g grantJSON
		if err := json.Unmarshal(respBody, &g); err != nil {
			return fmt.Errorf("parsing response: %w", err)
		}
		w := cmd.OutOrStdout()
		fmt.Fprintf(w, "%s\n", boldText("Grant "+g.ID))
		fmt.Fprintf(w, "%s %s:%s\n", fieldLabel("Subject:"), g.SubjectType, g.SubjectID)
		fmt.Fprintf(w, "%s %s\n", fieldLabel("Policy:"), policyRefDisplay(g.PolicyID, g.PolicyVersion))
		if g.ExpiresAt != "" {
			fmt.Fprintf(w, "%s %s\n", fieldLabel("Expires:"), formatTime(g.ExpiresAt))
		} else {
			fmt.Fprintf(w, "%s %s\n", fieldLabel("Expires:"), mutedText("never"))
		}
		fmt.Fprintf(w, "%s %s (%s)\n", fieldLabel("Granted:"), formatTime(g.GrantedAt), g.GrantedBy)
		if g.RevokedAt != "" {
			fmt.Fprintf(w, "%s %s (%s)\n", fieldLabel("Revoked:"), formatTime(g.RevokedAt), g.RevokedBy)
		}
		if len(g.Conditions) > 0 && string(g.Conditions) != "null" && string(g.Conditions) != "{}" {
			fmt.Fprintf(w, "%s\n%s\n", sectionHeader("Conditions:"), string(g.Conditions))
		}
		return nil
	},
}

var grantRevokeCmd = &cobra.Command{
	Use:   "revoke <id>",
	Short: "Revoke a grant (soft-delete; sets revoked_at)",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		id := args[0]
		vault := resolveVault(cmd)
		sess, err := ensureSession()
		if err != nil {
			return err
		}
		reqURL := fmt.Sprintf("%s/v1/vaults/%s/grants/%s",
			sess.Address, url.PathEscape(vault), url.PathEscape(id))
		if err := doAdminRequest("DELETE", reqURL, sess.Token, nil); err != nil {
			return err
		}
		fmt.Fprintf(cmd.OutOrStdout(), "%s Grant %q revoked.\n", successText("✓"), id)
		return nil
	},
}

// parsePolicyRef accepts "stripe-readonly@3" or "stripe-readonly".
// version=0 means "always-latest".
func parsePolicyRef(ref string) (id string, version int, err error) {
	idx := strings.IndexByte(ref, '@')
	if idx < 0 {
		return ref, 0, nil
	}
	id = ref[:idx]
	verStr := ref[idx+1:]
	if id == "" {
		return "", 0, fmt.Errorf("invalid policy ref %q (empty id)", ref)
	}
	if verStr == "" {
		return id, 0, nil
	}
	var v int
	if _, err := fmt.Sscanf(verStr, "%d", &v); err != nil {
		return "", 0, fmt.Errorf("invalid version %q in %q", verStr, ref)
	}
	if v <= 0 {
		return "", 0, fmt.Errorf("version must be > 0 in %q", ref)
	}
	return id, v, nil
}

// policyRefDisplay renders a grant's policy ref for table output.
// version=0 means "always-latest" (the grant pins to whatever the
// current policy version happens to be at evaluation time).
func policyRefDisplay(id string, version int) string {
	if version == 0 {
		return id + "@latest"
	}
	return fmt.Sprintf("%s@%d", id, version)
}

func init() {
	grantCreateCmd.Flags().String("agent", "", "agent subject (name or id)")
	grantCreateCmd.Flags().String("user", "", "user subject (email or id)")
	grantCreateCmd.Flags().String("policy", "", "policy ref: <id>[@<version>]")
	grantCreateCmd.Flags().String("expires", "", "expiry: RFC3339 timestamp or duration (e.g. 30d, 720h)")
	grantCreateCmd.Flags().String("conditions", "", "JSON conditions object (advanced)")

	grantListCmd.Flags().String("agent", "", "filter to grants for this agent (name or id)")
	grantListCmd.Flags().String("user", "", "filter to grants for this user (email or id)")
	grantListCmd.Flags().String("subject", "", "raw subject filter (e.g. agent:support-bot)")

	grantCmd.AddCommand(grantCreateCmd)
	grantCmd.AddCommand(grantListCmd)
	grantCmd.AddCommand(grantShowCmd)
	grantCmd.AddCommand(grantRevokeCmd)

	vaultCmd.AddCommand(grantCmd)
}
