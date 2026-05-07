package cmd

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/spf13/cobra"
)

// policyJSON is the on-the-wire shape returned by /v1/vaults/{vault}/policies/*.
// Mirrors the keys produced by server.policyResponse so the CLI can pretty-print
// without colluding with the persistence layer types.
type policyJSON struct {
	ID          string `json:"id"`
	Version     int    `json:"version"`
	Enabled     bool   `json:"enabled"`
	Description string `json:"description"`
	YAMLSource  string `json:"yaml_source"`
	ContentHash string `json:"content_hash"`
	ParentHash  string `json:"parent_hash"`
	AuthoredBy  string `json:"authored_by"`
	AuthoredAt  string `json:"authored_at"`
}

var policyCmd = &cobra.Command{
	Use:   "policies",
	Short: "Manage authorization policies for a vault",
}

var policyCreateCmd = &cobra.Command{
	Use:   "create",
	Short: "Create a new policy version from a YAML file",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		path, _ := cmd.Flags().GetString("file")
		if path == "" {
			return fmt.Errorf("--file is required")
		}
		yamlBytes, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("reading %s: %w", path, err)
		}

		vault := resolveVault(cmd)
		sess, err := ensureSession()
		if err != nil {
			return err
		}

		reqURL := fmt.Sprintf("%s/v1/vaults/%s/policies", sess.Address, url.PathEscape(vault))
		respBody, err := doYAMLRequestWithBody("POST", reqURL, sess.Token, yamlBytes)
		if err != nil {
			return err
		}

		var p policyJSON
		if err := json.Unmarshal(respBody, &p); err != nil {
			return fmt.Errorf("parsing response: %w", err)
		}
		fmt.Fprintf(cmd.OutOrStdout(), "%s Created policy %s@%d (hash %s)\n",
			successText("✓"), p.ID, p.Version, mutedText(shortHash(p.ContentHash)))
		return nil
	},
}

var policyListCmd = &cobra.Command{
	Use:   "list",
	Short: "List the latest policy version per id",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		vault := resolveVault(cmd)
		sess, err := ensureSession()
		if err != nil {
			return err
		}

		reqURL := fmt.Sprintf("%s/v1/vaults/%s/policies", sess.Address, url.PathEscape(vault))
		respBody, err := doAdminRequestWithBody("GET", reqURL, sess.Token, nil)
		if err != nil {
			return err
		}

		var resp struct {
			Policies []policyJSON `json:"policies"`
		}
		if err := json.Unmarshal(respBody, &resp); err != nil {
			return fmt.Errorf("parsing response: %w", err)
		}
		if len(resp.Policies) == 0 {
			fmt.Fprintf(cmd.OutOrStdout(), "No policies in vault %q.\n", vault)
			return nil
		}
		t := newTable(cmd.OutOrStdout())
		t.AppendHeader(table.Row{"ID", "VER", "ENABLED", "HASH", "AUTHOR", "AUTHORED"})
		for _, p := range resp.Policies {
			t.AppendRow(table.Row{
				p.ID,
				p.Version,
				p.Enabled,
				shortHash(p.ContentHash),
				p.AuthoredBy,
				formatTime(p.AuthoredAt),
			})
		}
		t.Render()
		return nil
	},
}

var policyShowCmd = &cobra.Command{
	Use:   "show <id>",
	Short: "Show the latest policy version (or a specific --version)",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		id := args[0]
		ver, _ := cmd.Flags().GetInt("version")

		vault := resolveVault(cmd)
		sess, err := ensureSession()
		if err != nil {
			return err
		}

		// If --version not given, fetch latest. Otherwise fetch the
		// version list and pick the requested entry locally; the server
		// only exposes /policies/{id} for latest.
		if ver == 0 {
			p, err := fetchPolicyLatest(sess.Address, sess.Token, vault, id)
			if err != nil {
				return err
			}
			printPolicy(cmd.OutOrStdout(), *p)
			return nil
		}

		versions, err := fetchPolicyVersions(sess.Address, sess.Token, vault, id)
		if err != nil {
			return err
		}
		for _, p := range versions {
			if p.Version == ver {
				printPolicy(cmd.OutOrStdout(), p)
				return nil
			}
		}
		return fmt.Errorf("policy %s has no version %d", id, ver)
	},
}

var policyVersionsCmd = &cobra.Command{
	Use:   "versions <id>",
	Short: "List all versions of a policy",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		id := args[0]
		vault := resolveVault(cmd)
		sess, err := ensureSession()
		if err != nil {
			return err
		}

		versions, err := fetchPolicyVersions(sess.Address, sess.Token, vault, id)
		if err != nil {
			return err
		}
		if len(versions) == 0 {
			fmt.Fprintf(cmd.OutOrStdout(), "No versions for %q.\n", id)
			return nil
		}
		t := newTable(cmd.OutOrStdout())
		t.AppendHeader(table.Row{"VER", "ENABLED", "HASH", "PARENT", "AUTHOR", "AUTHORED"})
		for _, p := range versions {
			t.AppendRow(table.Row{
				p.Version,
				p.Enabled,
				shortHash(p.ContentHash),
				shortHash(p.ParentHash),
				p.AuthoredBy,
				formatTime(p.AuthoredAt),
			})
		}
		t.Render()
		return nil
	},
}

var policyDiffCmd = &cobra.Command{
	Use:   "diff <id>",
	Short: "Show a unified-style diff between two versions of a policy",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		id := args[0]
		from, _ := cmd.Flags().GetInt("from")
		to, _ := cmd.Flags().GetInt("to")
		if from <= 0 || to <= 0 {
			return fmt.Errorf("--from and --to are required and must be > 0")
		}

		vault := resolveVault(cmd)
		sess, err := ensureSession()
		if err != nil {
			return err
		}

		versions, err := fetchPolicyVersions(sess.Address, sess.Token, vault, id)
		if err != nil {
			return err
		}
		var fromYAML, toYAML string
		for _, p := range versions {
			if p.Version == from {
				fromYAML = p.YAMLSource
			}
			if p.Version == to {
				toYAML = p.YAMLSource
			}
		}
		if fromYAML == "" {
			return fmt.Errorf("policy %s has no version %d", id, from)
		}
		if toYAML == "" {
			return fmt.Errorf("policy %s has no version %d", id, to)
		}
		printSimpleDiff(cmd.OutOrStdout(), id, from, to, fromYAML, toYAML)
		return nil
	},
}

var policyDisableCmd = &cobra.Command{
	Use:   "disable <id>",
	Short: "Soft-disable all versions of a policy (does not delete history)",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		id := args[0]
		vault := resolveVault(cmd)
		sess, err := ensureSession()
		if err != nil {
			return err
		}

		reqURL := fmt.Sprintf("%s/v1/vaults/%s/policies/%s",
			sess.Address, url.PathEscape(vault), url.PathEscape(id))
		if err := doAdminRequest("DELETE", reqURL, sess.Token, nil); err != nil {
			return err
		}
		fmt.Fprintf(cmd.OutOrStdout(), "%s Policy %q disabled.\n", successText("✓"), id)
		return nil
	},
}

// fetchPolicyLatest queries /v1/vaults/{vault}/policies/{id}.
func fetchPolicyLatest(addr, token, vault, id string) (*policyJSON, error) {
	reqURL := fmt.Sprintf("%s/v1/vaults/%s/policies/%s",
		addr, url.PathEscape(vault), url.PathEscape(id))
	body, err := doAdminRequestWithBody("GET", reqURL, token, nil)
	if err != nil {
		return nil, err
	}
	var p policyJSON
	if err := json.Unmarshal(body, &p); err != nil {
		return nil, fmt.Errorf("parsing response: %w", err)
	}
	return &p, nil
}

// fetchPolicyVersions queries /v1/vaults/{vault}/policies/{id}/versions
// and returns the array (most-recent first as ordered by the server).
func fetchPolicyVersions(addr, token, vault, id string) ([]policyJSON, error) {
	reqURL := fmt.Sprintf("%s/v1/vaults/%s/policies/%s/versions",
		addr, url.PathEscape(vault), url.PathEscape(id))
	body, err := doAdminRequestWithBody("GET", reqURL, token, nil)
	if err != nil {
		return nil, err
	}
	var resp struct {
		Versions []policyJSON `json:"versions"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("parsing response: %w", err)
	}
	return resp.Versions, nil
}

// printPolicy renders a single policy in human form: header + YAML body.
func printPolicy(w io.Writer, p policyJSON) {
	fmt.Fprintf(w, "%s\n", boldText(fmt.Sprintf("%s @ v%d", p.ID, p.Version)))
	fmt.Fprintf(w, "%s %s\n", fieldLabel("Enabled:"), boolText(p.Enabled))
	fmt.Fprintf(w, "%s %s\n", fieldLabel("Hash:"), p.ContentHash)
	if p.ParentHash != "" {
		fmt.Fprintf(w, "%s %s\n", fieldLabel("Parent:"), p.ParentHash)
	}
	fmt.Fprintf(w, "%s %s\n", fieldLabel("Author:"), p.AuthoredBy)
	fmt.Fprintf(w, "%s %s\n", fieldLabel("Created:"), formatTime(p.AuthoredAt))
	if p.Description != "" {
		fmt.Fprintf(w, "%s %s\n", fieldLabel("Description:"), p.Description)
	}
	fmt.Fprintf(w, "\n%s\n", sectionHeader("YAML source:"))
	fmt.Fprintf(w, "%s\n", p.YAMLSource)
}

// printSimpleDiff is a *deliberately* minimal line-by-line comparison —
// not a full Myers diff. The CLI is for operator-facing review; if a
// richer view is required, callers can pipe two `policy show` invocations
// to an external diff(1).
func printSimpleDiff(w io.Writer, id string, from, to int, a, b string) {
	fmt.Fprintf(w, "%s\n", boldText(fmt.Sprintf("--- %s @ v%d", id, from)))
	fmt.Fprintf(w, "%s\n", boldText(fmt.Sprintf("+++ %s @ v%d", id, to)))
	la := strings.Split(a, "\n")
	lb := strings.Split(b, "\n")
	n := len(la)
	if len(lb) > n {
		n = len(lb)
	}
	for i := 0; i < n; i++ {
		var av, bv string
		if i < len(la) {
			av = la[i]
		}
		if i < len(lb) {
			bv = lb[i]
		}
		switch {
		case av == bv:
			fmt.Fprintf(w, "  %s\n", av)
		case av != "" && bv == "":
			fmt.Fprintf(w, "%s %s\n", errorText("-"), av)
		case av == "" && bv != "":
			fmt.Fprintf(w, "%s %s\n", successText("+"), bv)
		default:
			fmt.Fprintf(w, "%s %s\n", errorText("-"), av)
			fmt.Fprintf(w, "%s %s\n", successText("+"), bv)
		}
	}
}

// doYAMLRequestWithBody is the YAML-Content-Type variant of
// doAdminRequestWithBody. Policy create accepts text/yaml because the
// canonical hash chain is over the raw YAML the user authored — JSON
// re-serialization would change the hash.
func doYAMLRequestWithBody(method, reqURL, token string, body []byte) ([]byte, error) {
	req, err := http.NewRequest(method, reqURL, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/x-yaml")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("could not reach server: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading response: %w", err)
	}
	if resp.StatusCode >= 400 {
		var errResp struct {
			Error string `json:"error"`
		}
		_ = json.Unmarshal(respBody, &errResp)
		msg := errResp.Error
		if msg == "" {
			msg = fmt.Sprintf("server returned status %d", resp.StatusCode)
		}
		if resp.StatusCode == http.StatusUnauthorized {
			return nil, &sessionExpiredError{msg: msg}
		}
		return nil, fmt.Errorf("%s", msg)
	}
	return respBody, nil
}

// boolText renders a Go bool as a colored "yes"/"no" using the existing palette.
func boolText(b bool) string {
	if b {
		return successText("yes")
	}
	return mutedText("no")
}

// shortHash truncates a 64-char sha256 hex to 12 chars for table output.
// Empty input passes through unchanged so "no parent" rows render cleanly.
func shortHash(h string) string {
	if h == "" {
		return mutedText("(none)")
	}
	if len(h) <= 16 {
		return h
	}
	return h[:12] + "…"
}

// formatTime parses an RFC3339 string and returns "2006-01-02 15:04:05".
// Falls back to the raw value when parsing fails.
func formatTime(s string) string {
	if s == "" {
		return ""
	}
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return s
	}
	return t.Format("2006-01-02 15:04:05")
}

// expiresAtFlag parses --expires either as an RFC3339 instant or a
// duration ("720h", "30d") relative to now. "30d" is non-standard for
// time.ParseDuration so we expand it manually before parsing.
func parseExpiresAt(raw string) (time.Time, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return time.Time{}, nil
	}
	if t, err := time.Parse(time.RFC3339, raw); err == nil {
		return t, nil
	}
	// Allow "30d" / "2w" shortcuts.
	if n := len(raw); n >= 2 {
		unit := raw[n-1]
		num, err := strconv.Atoi(raw[:n-1])
		if err == nil {
			switch unit {
			case 'd':
				return time.Now().Add(time.Duration(num) * 24 * time.Hour), nil
			case 'w':
				return time.Now().Add(time.Duration(num) * 7 * 24 * time.Hour), nil
			}
		}
	}
	d, err := time.ParseDuration(raw)
	if err != nil {
		return time.Time{}, fmt.Errorf("invalid --expires %q (use RFC3339 or duration like 720h / 30d)", raw)
	}
	return time.Now().Add(d), nil
}

func init() {
	policyCreateCmd.Flags().StringP("file", "f", "", "path to policy YAML file")

	policyShowCmd.Flags().Int("version", 0, "show a specific version (default: latest)")

	policyDiffCmd.Flags().Int("from", 0, "older version number")
	policyDiffCmd.Flags().Int("to", 0, "newer version number")

	policyCmd.AddCommand(policyCreateCmd)
	policyCmd.AddCommand(policyListCmd)
	policyCmd.AddCommand(policyShowCmd)
	policyCmd.AddCommand(policyVersionsCmd)
	policyCmd.AddCommand(policyDiffCmd)
	policyCmd.AddCommand(policyDisableCmd)

	vaultCmd.AddCommand(policyCmd)
}
