package catalog

import (
	"fmt"
	"strings"
)

// PolicyInstallEntry is a built-in policy template for the policy registry
// (local catalog today; remote publish/install is a future extension).
// Clients substitute {{VAULT}}, {{POLICY_ID}}, {{SERVICE_HOST}}, and
// {{CREDENTIAL_KEY}} into YamlTemplate before POSTing to
// /v1/vaults/{vault}/policies. ServiceHost and SuggestedCredentialKey are
// resolved from the linked service catalog entry for display and defaults.
type PolicyInstallEntry struct {
	ID                     string `json:"id"`
	Name                   string `json:"name"`
	Description            string `json:"description"`
	ServiceCatalogID       string `json:"service_catalog_id"`
	DefaultPolicyID        string `json:"default_policy_id"`
	ServiceHost            string `json:"service_host"`
	SuggestedCredentialKey string `json:"suggested_credential_key"`
	YamlTemplate           string `json:"yaml_template"`
}

// policyInstallCatalog is the embedded registry of installable policy templates.
var policyInstallCatalog = []PolicyInstallEntry{
	mustPolicyEntry("stripe-readonly", "Stripe (read-only)", "Allow GET/HEAD only for Stripe API traffic.", "stripe", "stripe-api-readonly", readOnlyYAML()),
	mustPolicyEntry("github-readonly", "GitHub (read-only)", "Allow GET/HEAD for GitHub REST API.", "github", "github-api-readonly", readOnlyYAML()),
	mustPolicyEntry("openai-readonly", "OpenAI (read-only)", "Allow GET/HEAD for OpenAI API.", "openai", "openai-api-readonly", readOnlyYAML()),
	mustPolicyEntry("anthropic-readonly", "Anthropic (read-only)", "Allow GET/HEAD for Anthropic API.", "anthropic", "anthropic-api-readonly", readOnlyYAML()),
	mustPolicyEntry("slack-readonly", "Slack (read-only)", "Allow GET/HEAD for Slack Web API.", "slack", "slack-api-readonly", readOnlyYAML()),
}

func readOnlyYAML() string {
	return `apiVersion: policy.agentvault/v1
kind: Policy
metadata:
  id: {{POLICY_ID}}
  vault: {{VAULT}}
  description: ""
spec:
  resources:
    - credential_key: {{CREDENTIAL_KEY}}
      service_host: {{SERVICE_HOST}}
  rules:
    - id: allow-read
      effect: allow
      methods: [GET, HEAD]
      path_patterns: ["/**"]
`
}

func mustPolicyEntry(id, name, desc, serviceCatalogID, defaultPolicyID, yaml string) PolicyInstallEntry {
	t := GetByID(serviceCatalogID)
	if t == nil {
		panic("catalog: policy template " + id + " references unknown service_catalog_id " + serviceCatalogID)
	}
	return PolicyInstallEntry{
		ID:                     id,
		Name:                   name,
		Description:            desc,
		ServiceCatalogID:       serviceCatalogID,
		DefaultPolicyID:        defaultPolicyID,
		ServiceHost:            t.Host,
		SuggestedCredentialKey: t.SuggestedCredentialKey,
		YamlTemplate:           yaml,
	}
}

// GetPolicyInstallCatalog returns installable policy templates with resolved
// host and credential key names from the service catalog.
func GetPolicyInstallCatalog() []PolicyInstallEntry {
	out := make([]PolicyInstallEntry, len(policyInstallCatalog))
	copy(out, policyInstallCatalog)
	return out
}

// GetPolicyInstallByID returns a template by id, or nil.
func GetPolicyInstallByID(id string) *PolicyInstallEntry {
	for i := range policyInstallCatalog {
		if policyInstallCatalog[i].ID == id {
			e := policyInstallCatalog[i]
			return &e
		}
	}
	return nil
}

// RenderPolicyInstallYAML replaces placeholders. policyID may be empty to use
// the entry's DefaultPolicyID.
func RenderPolicyInstallYAML(entry *PolicyInstallEntry, vault, policyID string) (string, error) {
	if entry == nil {
		return "", fmt.Errorf("nil policy install entry")
	}
	if vault == "" {
		return "", fmt.Errorf("vault is required")
	}
	pid := strings.TrimSpace(policyID)
	if pid == "" {
		pid = entry.DefaultPolicyID
	}
	s := entry.YamlTemplate
	s = strings.ReplaceAll(s, "{{VAULT}}", vault)
	s = strings.ReplaceAll(s, "{{POLICY_ID}}", pid)
	s = strings.ReplaceAll(s, "{{SERVICE_HOST}}", entry.ServiceHost)
	s = strings.ReplaceAll(s, "{{CREDENTIAL_KEY}}", entry.SuggestedCredentialKey)
	return s, nil
}
