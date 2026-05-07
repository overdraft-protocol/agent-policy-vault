package policy

import (
	"strings"
)

// matchMethod reports whether method is in the rule's method list.
// Empty list = match-any. "*" entry also matches any.
func matchMethod(rule Rule, method string) bool {
	if len(rule.Methods) == 0 {
		return true
	}
	up := strings.ToUpper(method)
	for _, m := range rule.Methods {
		if m == "*" {
			return true
		}
		if strings.EqualFold(m, up) {
			return true
		}
	}
	return false
}

// matchPath reports whether path matches any of the rule's path
// patterns. Empty list = match-any.
//
// Pattern syntax (deliberately limited — paths are part of the
// security boundary):
//
//   - "/literal/path"     exact match
//   - "/v1/users/*"       single path segment
//   - "/v1/users/**"      any subpath including empty
//   - "/v1/*/comments"    single segment in middle
//
// "*" never matches "/". "**" is allowed only as the trailing token.
func matchPath(rule Rule, path string) bool {
	if len(rule.PathPatterns) == 0 {
		return true
	}
	for _, pat := range rule.PathPatterns {
		if matchGlob(pat, path) {
			return true
		}
	}
	return false
}

// matchGlob implements the limited path glob described above.
func matchGlob(pattern, s string) bool {
	if pattern == s {
		return true
	}
	pSegs := strings.Split(strings.TrimPrefix(pattern, "/"), "/")
	sSegs := strings.Split(strings.TrimPrefix(s, "/"), "/")
	return matchSegs(pSegs, sSegs)
}

func matchSegs(p, s []string) bool {
	for i := 0; i < len(p); i++ {
		if p[i] == "**" {
			// Trailing-only by validation, but be defensive: any
			// remainder of s matches.
			return true
		}
		if i >= len(s) {
			return false
		}
		if p[i] == "*" {
			// Single segment, must be non-empty.
			if s[i] == "" {
				return false
			}
			continue
		}
		if p[i] != s[i] {
			return false
		}
	}
	return len(p) == len(s)
}

// matchHostPattern reports whether host matches a service_host pattern.
// Supports leading "*." for one-level subdomain wildcards, mirroring
// internal/broker.MatchHost semantics so policy resources line up with
// the broker's view of services.
func matchHostPattern(pattern, host string) bool {
	pattern = strings.ToLower(pattern)
	host = strings.ToLower(host)
	if pattern == host {
		return true
	}
	if strings.HasPrefix(pattern, "*.") {
		suffix := pattern[1:] // ".example.com"
		if !strings.HasSuffix(host, suffix) {
			return false
		}
		// Must have exactly one extra label.
		prefix := strings.TrimSuffix(host, suffix)
		if prefix == "" || strings.Contains(prefix, ".") {
			return false
		}
		return true
	}
	return false
}

// resourceMatches returns true iff the policy declares a resource
// covering this credential + host pair.
func resourceMatches(p *Policy, credentialKey, host string) bool {
	for _, r := range p.Spec.Resources {
		if r.CredentialKey != credentialKey && r.CredentialKey != "*" {
			continue
		}
		if matchHostPattern(r.ServiceHost, host) {
			return true
		}
	}
	return false
}
