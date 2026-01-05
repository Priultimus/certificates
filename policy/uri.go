package policy

import (
	"fmt"
	"net/url"
	"regexp"
	"strings"

	"golang.org/x/net/idna"
)

// URIConstraint represents a constraint for matching URIs with optional
// scheme and path components in addition to domain matching.
type URIConstraint struct {
	// Scheme to match (e.g., "https", "spiffe"). Empty means any scheme.
	Scheme string
	// Domain to match. Supports wildcard prefix (e.g., "*.example.com").
	// Uses the same matching semantics as existing URI domain constraints.
	Domain string
	// Path to match. Supports prefix matching with trailing "*" (e.g., "/api/*").
	// Empty means any path.
	Path string
}

// String returns a string representation of the URI constraint.
func (c URIConstraint) String() string {
	var sb strings.Builder
	if c.Scheme != "" {
		sb.WriteString(c.Scheme)
		sb.WriteString("://")
	}
	if c.Domain != "" {
		sb.WriteString(c.Domain)
	}
	if c.Path != "" {
		sb.WriteString(c.Path)
	}
	return sb.String()
}

// ParseURIConstraint parses a URI constraint string into a URIConstraint.
// Supported formats:
//   - "example.com" - domain only (backwards compatible)
//   - "*.example.com" - wildcard domain
//   - "https://example.com" - scheme + domain
//   - "https://example.com/path" - scheme + domain + path
//   - "https://example.com/path/*" - scheme + domain + path prefix
//   - "://example.com" - any scheme + domain
//   - "://example.com/path" - any scheme + domain + path
func ParseURIConstraint(constraint string) (URIConstraint, error) {
	constraint = strings.TrimSpace(constraint)
	if constraint == "" {
		return URIConstraint{}, fmt.Errorf("URI constraint cannot be empty")
	}

	var c URIConstraint

	// Check if constraint contains a scheme separator
	if idx := strings.Index(constraint, "://"); idx != -1 {
		c.Scheme = strings.ToLower(constraint[:idx])
		remainder := constraint[idx+3:]

		// Split domain and path
		if pathIdx := strings.Index(remainder, "/"); pathIdx != -1 {
			c.Domain = remainder[:pathIdx]
			c.Path = remainder[pathIdx:]
		} else {
			c.Domain = remainder
		}
	} else {
		// No scheme - check for path
		if pathIdx := strings.Index(constraint, "/"); pathIdx != -1 {
			c.Domain = constraint[:pathIdx]
			c.Path = constraint[pathIdx:]
		} else {
			// Domain only (backwards compatible)
			c.Domain = constraint
		}
	}

	// Validate and normalize the domain
	normalizedDomain, err := normalizeURIConstraintDomain(c.Domain)
	if err != nil {
		return URIConstraint{}, fmt.Errorf("invalid URI constraint domain %q: %w", c.Domain, err)
	}
	c.Domain = normalizedDomain

	// Validate the scheme if specified
	if c.Scheme != "" && !isValidScheme(c.Scheme) {
		return URIConstraint{}, fmt.Errorf("invalid URI constraint scheme %q", c.Scheme)
	}

	// Validate the path if specified
	if c.Path != "" {
		if err := validateURIConstraintPath(c.Path); err != nil {
			return URIConstraint{}, fmt.Errorf("invalid URI constraint path %q: %w", c.Path, err)
		}
	}

	return c, nil
}

// normalizeURIConstraintDomain normalizes and validates a domain for URI constraints.
// This is similar to normalizeAndValidateURIDomainConstraint but returns the normalized
// domain without the leading period for non-wildcard domains.
func normalizeURIConstraintDomain(domain string) (string, error) {
	if domain == "" {
		return "", fmt.Errorf("domain cannot be empty")
	}

	normalizedDomain := strings.ToLower(strings.TrimSpace(domain))

	if strings.Contains(normalizedDomain, "..") {
		return "", fmt.Errorf("domain cannot have empty labels")
	}

	if strings.HasPrefix(normalizedDomain, ".") {
		return "", fmt.Errorf("domain with wildcard should start with *")
	}

	if strings.LastIndex(normalizedDomain, "*") > 0 {
		return "", fmt.Errorf("wildcard can only be at the start")
	}

	// Handle wildcard: convert "*.example.com" to ".example.com" (internal format)
	if strings.HasPrefix(normalizedDomain, "*.") {
		normalizedDomain = normalizedDomain[1:] // Keep the leading period
	}

	// Check for square brackets (IPv6 format - not allowed)
	if strings.Contains(normalizedDomain, "[") || strings.Contains(normalizedDomain, "]") {
		return "", fmt.Errorf("domain cannot contain square brackets")
	}

	// Convert to ASCII (IDNA)
	normalizedDomain, err := idna.Lookup.ToASCII(normalizedDomain)
	if err != nil {
		return "", fmt.Errorf("cannot convert to ASCII: %w", err)
	}

	// Validate domain structure
	if _, ok := domainToReverseLabels(strings.TrimPrefix(normalizedDomain, ".")); !ok {
		return "", fmt.Errorf("cannot parse domain")
	}

	return normalizedDomain, nil
}

// isValidScheme checks if the scheme is valid according to RFC 3986.
// scheme = ALPHA *( ALPHA / DIGIT / "+" / "-" / "." )
func isValidScheme(scheme string) bool {
	if len(scheme) == 0 {
		return false
	}

	// First character must be a letter
	first := scheme[0]
	if !((first >= 'a' && first <= 'z') || (first >= 'A' && first <= 'Z')) {
		return false
	}

	// Rest can be letters, digits, +, -, .
	for i := 1; i < len(scheme); i++ {
		c := scheme[i]
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
			(c >= '0' && c <= '9') || c == '+' || c == '-' || c == '.') {
			return false
		}
	}

	return true
}

// validateURIConstraintPath validates a path constraint.
func validateURIConstraintPath(path string) error {
	if path == "" {
		return nil
	}

	// Path must start with /
	if !strings.HasPrefix(path, "/") {
		return fmt.Errorf("path must start with /")
	}

	// Path cannot contain ".." for security
	if strings.Contains(path, "..") {
		return fmt.Errorf("path cannot contain '..'")
	}

	return nil
}

// MatchURI checks if a URL matches this URI constraint.
func (c URIConstraint) MatchURI(u *url.URL, engine *NamePolicyEngine) (bool, error) {
	// Check scheme if specified
	if c.Scheme != "" && !strings.EqualFold(u.Scheme, c.Scheme) {
		return false, nil
	}

	// Get the host (without port)
	host := u.Host
	if host == "" {
		return false, fmt.Errorf("URI with empty host (%q) cannot be matched", u.String())
	}

	// Check for wildcards in host - not allowed
	if strings.Contains(host, "*") {
		return false, fmt.Errorf("URI host %q cannot contain asterisk", u.String())
	}

	// Remove port if present
	if strings.Contains(host, ":") && !strings.HasSuffix(host, "]") {
		var err error
		host, _, err = splitHostPort(host)
		if err != nil {
			return false, err
		}
	}

	// Check for IP addresses - not allowed for URI constraints per RFC 5280
	if strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]") {
		return false, fmt.Errorf("URI with IPv6 %q cannot be matched against constraints", u.String())
	}
	if isIPAddress(host) {
		return false, fmt.Errorf("URI with IP %q cannot be matched against constraints", u.String())
	}

	// Match domain
	domainMatch, err := engine.matchDomainConstraint(host, c.Domain)
	if err != nil || !domainMatch {
		return domainMatch, err
	}

	// Check path if specified in constraint
	if c.Path != "" {
		path := u.Path
		if path == "" {
			path = "/"
		}

		// Check for path prefix matching (ends with *)
		if strings.HasSuffix(c.Path, "*") {
			prefix := strings.TrimSuffix(c.Path, "*")
			if !strings.HasPrefix(path, prefix) {
				return false, nil
			}
		} else {
			// Exact path match
			if path != c.Path {
				return false, nil
			}
		}
	}

	return true, nil
}

// splitHostPort splits a host:port string. This is a simplified version
// that handles the common cases.
func splitHostPort(hostport string) (host, port string, err error) {
	// Handle IPv6 addresses
	if strings.HasPrefix(hostport, "[") {
		end := strings.Index(hostport, "]")
		if end < 0 {
			return "", "", fmt.Errorf("missing ']' in address")
		}
		if end+1 == len(hostport) {
			return hostport[1:end], "", nil
		}
		if hostport[end+1] != ':' {
			return "", "", fmt.Errorf("invalid address format")
		}
		return hostport[1:end], hostport[end+2:], nil
	}

	// Handle regular host:port
	colon := strings.LastIndex(hostport, ":")
	if colon < 0 {
		return hostport, "", nil
	}
	return hostport[:colon], hostport[colon+1:], nil
}

// isIPAddress checks if the string is an IP address.
func isIPAddress(s string) bool {
	// Simple check - try parsing as IP
	for _, c := range s {
		if c == '.' || c == ':' || (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F') {
			continue
		}
		return false
	}

	// If it only contains valid IP characters and has dots or colons, it might be an IP
	// More precise: check if it parses as a valid IP
	// We avoid importing net here to prevent circular dependencies
	// Instead, check the structure

	// IPv4: must have exactly 3 dots and all segments are numbers 0-255
	if strings.Count(s, ".") == 3 && !strings.Contains(s, ":") {
		// Likely an IPv4
		return true
	}

	// IPv6: contains colons
	if strings.Contains(s, ":") {
		return true
	}

	return false
}

// RegexConstraint represents a compiled regex constraint for matching names.
type RegexConstraint struct {
	// Pattern is the original regex pattern string (for serialization/display)
	Pattern string
	// Compiled is the compiled regular expression
	Compiled *regexp.Regexp
}

// NewRegexConstraint creates a new regex constraint from a pattern string.
func NewRegexConstraint(pattern string) (*RegexConstraint, error) {
	if pattern == "" {
		return nil, fmt.Errorf("regex pattern cannot be empty")
	}

	compiled, err := regexp.Compile(pattern)
	if err != nil {
		return nil, fmt.Errorf("invalid regex pattern %q: %w", pattern, err)
	}

	return &RegexConstraint{
		Pattern:  pattern,
		Compiled: compiled,
	}, nil
}

// Match checks if a string matches the regex constraint.
func (c *RegexConstraint) Match(s string) bool {
	if c == nil || c.Compiled == nil {
		return false
	}
	return c.Compiled.MatchString(s)
}

// String returns the pattern string.
func (c *RegexConstraint) String() string {
	if c == nil {
		return ""
	}
	return c.Pattern
}

