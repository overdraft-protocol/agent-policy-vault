package policy

import (
	"bytes"
	"encoding/json"
	"strings"
)

// inspectBody applies a BodyConstraint. The first violation produces
// (deniedPath, true). The body is parsed as JSON when it looks like
// JSON; otherwise forbidden_json_paths is a no-op (we never claim a
// payload "doesn't contain X" when we can't see structure).
func inspectBody(c *BodyConstraint, body []byte) (string, bool) {
	if c == nil {
		return "", false
	}
	if c.MaxBytes > 0 && int64(len(body)) > c.MaxBytes {
		return "max_bytes_exceeded", true
	}
	if len(c.ForbiddenJSONPaths) == 0 || len(body) == 0 {
		return "", false
	}
	trimmed := bytes.TrimSpace(body)
	if len(trimmed) == 0 {
		return "", false
	}
	if trimmed[0] != '{' && trimmed[0] != '[' {
		return "", false
	}
	var v any
	if err := json.Unmarshal(body, &v); err != nil {
		// Unparseable JSON — fail closed: treat as if all forbidden
		// paths could be present. This prevents an attacker from
		// hiding a forbidden field behind deliberate parse breakage.
		return "json_parse_error", true
	}
	for _, path := range c.ForbiddenJSONPaths {
		if jsonPathExists(v, path) {
			return path, true
		}
	}
	return "", false
}

// jsonPathExists reports whether a (very limited) JSON path resolves
// to a non-null value in v. Supported syntax:
//
//   - "$.foo.bar"        nested field
//   - "$.items.0.price"  numeric index into an array
//   - "foo.bar"          $-prefix optional
//
// We deliberately avoid pulling in a heavy JSONPath dependency for
// this narrow use case; the syntax we support covers the common
// "forbid field X" rule.
func jsonPathExists(v any, path string) bool {
	tokens := tokenizePath(path)
	cur := v
	for _, tok := range tokens {
		switch c := cur.(type) {
		case map[string]any:
			next, ok := c[tok]
			if !ok {
				return false
			}
			cur = next
		case []any:
			idx := -1
			if _, err := fmtSscanInt(tok); err == nil {
				idx, _ = fmtSscanInt(tok)
			}
			if idx < 0 || idx >= len(c) {
				return false
			}
			cur = c[idx]
		default:
			return false
		}
	}
	return cur != nil
}

func tokenizePath(p string) []string {
	p = strings.TrimPrefix(p, "$")
	p = strings.TrimPrefix(p, ".")
	if p == "" {
		return nil
	}
	return strings.Split(p, ".")
}

// fmtSscanInt is a tiny strconv-free integer parse helper to avoid
// dragging strconv into a path that has nothing else to do with it.
func fmtSscanInt(s string) (int, error) {
	var n int
	for _, r := range s {
		if r < '0' || r > '9' {
			return 0, errNotInt
		}
		n = n*10 + int(r-'0')
	}
	return n, nil
}

var errNotInt = &parseErr{"not an integer"}

type parseErr struct{ msg string }

func (e *parseErr) Error() string { return e.msg }
