package catalog

import (
	"strings"
	"testing"
)

func TestGetPolicyInstallCatalog(t *testing.T) {
	entries := GetPolicyInstallCatalog()
	if len(entries) == 0 {
		t.Fatal("expected policy install catalog")
	}
	for _, e := range entries {
		if e.ID == "" || e.YamlTemplate == "" {
			t.Fatalf("invalid entry: %+v", e)
		}
		if e.ServiceHost == "" || e.SuggestedCredentialKey == "" {
			t.Fatalf("entry %q missing resolved host/key", e.ID)
		}
	}
}

func TestRenderPolicyInstallYAML(t *testing.T) {
	e := GetPolicyInstallByID("stripe-readonly")
	if e == nil {
		t.Fatal("missing stripe-readonly template")
	}
	y, err := RenderPolicyInstallYAML(e, "default", "")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(y, "vault: default") {
		t.Fatalf("vault not substituted: %s", y)
	}
	if !strings.Contains(y, "id: stripe-api-readonly") {
		t.Fatalf("default policy id: %s", y)
	}
	if !strings.Contains(y, "api.stripe.com") {
		t.Fatalf("host: %s", y)
	}
	if !strings.Contains(y, "STRIPE_KEY") {
		t.Fatalf("credential key: %s", y)
	}
}
