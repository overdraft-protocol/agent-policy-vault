package policy

import "testing"

func FuzzPolicyLoader(f *testing.F) {
	f.Add([]byte(`apiVersion: policy.agentvault/v1
kind: Policy
metadata:
  id: fuzz-base
  vault: prod
spec:
  resources:
    - credential_key: KEY
      service_host: api.example.com
  rules:
    - id: r1
      effect: allow
      methods: [GET]
      path_patterns: ["/v1/**"]
`))
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 256*1024 {
			t.Skip()
		}
		_, _ = LoadPolicy(data)
	})
}
