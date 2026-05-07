package server

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Infisical/agent-vault/internal/store"
)

func TestPolicyCreateForbiddenForAgentToken(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(":memory:")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	ns, err := st.GetVault(ctx, "default")
	if err != nil || ns == nil {
		t.Fatalf("GetVault(default): %v, ns=%v", err, ns)
	}

	ag, err := st.CreateAgent(ctx, "policy-bot", "creator", "member")
	if err != nil {
		t.Fatalf("CreateAgent: %v", err)
	}
	if err := st.GrantVaultRole(ctx, ag.ID, "agent", ns.ID, "member"); err != nil {
		t.Fatalf("GrantVaultRole: %v", err)
	}
	sess, err := st.CreateAgentToken(ctx, ag.ID, tp(time.Now().Add(time.Hour)))
	if err != nil {
		t.Fatalf("CreateAgentToken: %v", err)
	}

	body := `apiVersion: policy.agentvault/v1
kind: Policy
metadata:
  id: agent-denied-pol
  vault: default
spec:
  resources:
    - credential_key: k
      service_host: api.example.com
  rules:
    - id: r1
      effect: allow
      methods: [GET]
      path_patterns: ["/**"]
`
	srv := newTestServer(withStore(st), withPolicyStore(st))
	req := httptest.NewRequest(http.MethodPost, "/v1/vaults/default/policies", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+sess.ID)
	req.Header.Set("Content-Type", "application/yaml")
	rec := httptest.NewRecorder()
	srv.httpServer.Handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		b, _ := io.ReadAll(rec.Body)
		t.Fatalf("status = %d, want 403, body=%s", rec.Code, b)
	}
}
