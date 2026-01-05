package policy

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
)

func TestParseURIConstraint(t *testing.T) {
	tests := []struct {
		name       string
		constraint string
		wantScheme string
		wantDomain string
		wantPath   string
		wantErr    bool
	}{
		{
			name:       "ok/domain-only",
			constraint: "example.com",
			wantScheme: "",
			wantDomain: "example.com",
			wantPath:   "",
			wantErr:    false,
		},
		{
			name:       "ok/wildcard-domain",
			constraint: "*.example.com",
			wantScheme: "",
			wantDomain: ".example.com", // internally converted to period prefix
			wantPath:   "",
			wantErr:    false,
		},
		{
			name:       "ok/full-uri",
			constraint: "https://example.com/api",
			wantScheme: "https",
			wantDomain: "example.com",
			wantPath:   "/api",
			wantErr:    false,
		},
		{
			name:       "ok/scheme-and-domain",
			constraint: "https://example.com",
			wantScheme: "https",
			wantDomain: "example.com",
			wantPath:   "",
			wantErr:    false,
		},
		{
			name:       "ok/spiffe-uri",
			constraint: "spiffe://trust.domain/workload",
			wantScheme: "spiffe",
			wantDomain: "trust.domain",
			wantPath:   "/workload",
			wantErr:    false,
		},
		{
			name:       "ok/path-prefix",
			constraint: "https://example.com/api/*",
			wantScheme: "https",
			wantDomain: "example.com",
			wantPath:   "/api/*",
			wantErr:    false,
		},
		{
			name:       "fail/empty",
			constraint: "",
			wantErr:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, err := ParseURIConstraint(tt.constraint)
			if tt.wantErr {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.wantScheme, c.Scheme)
			assert.Equal(t, tt.wantDomain, c.Domain)
			assert.Equal(t, tt.wantPath, c.Path)
		})
	}
}

func TestURIConstraint_String(t *testing.T) {
	tests := []struct {
		name       string
		constraint URIConstraint
		want       string
	}{
		{
			name: "domain-only",
			constraint: URIConstraint{
				Domain: "example.com",
			},
			want: "example.com",
		},
		{
			name: "scheme-and-domain",
			constraint: URIConstraint{
				Scheme: "https",
				Domain: "example.com",
			},
			want: "https://example.com",
		},
		{
			name: "full",
			constraint: URIConstraint{
				Scheme: "https",
				Domain: "example.com",
				Path:   "/api",
			},
			want: "https://example.com/api",
		},
		{
			name: "wildcard",
			constraint: URIConstraint{
				Domain: ".example.com",
			},
			want: ".example.com",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.constraint.String()
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestURIConstraint_MatchURI(t *testing.T) {
	tests := []struct {
		name       string
		constraint URIConstraint
		uri        string
		want       bool
		wantErr    bool
	}{
		// Domain-only matching (backwards compatible)
		{
			name: "ok/domain-match",
			constraint: URIConstraint{
				Domain: "example.com",
			},
			uri:  "https://example.com/api/v1",
			want: true,
		},
		{
			name: "fail/domain-mismatch",
			constraint: URIConstraint{
				Domain: "example.com",
			},
			uri:  "https://other.com/api/v1",
			want: false,
		},
		// Wildcard domain matching
		{
			name: "ok/wildcard-domain-match",
			constraint: URIConstraint{
				Domain: ".example.com",
			},
			uri:  "https://api.example.com/v1",
			want: true,
		},
		{
			name: "fail/wildcard-domain-root",
			constraint: URIConstraint{
				Domain: ".example.com",
			},
			uri:  "https://example.com/v1",
			want: false,
		},
		// Scheme matching
		{
			name: "ok/scheme-match",
			constraint: URIConstraint{
				Scheme: "https",
				Domain: "example.com",
			},
			uri:  "https://example.com/api/v1",
			want: true,
		},
		{
			name: "fail/scheme-mismatch",
			constraint: URIConstraint{
				Scheme: "https",
				Domain: "example.com",
			},
			uri:  "http://example.com/api/v1",
			want: false,
		},
		// Path matching
		{
			name: "ok/path-exact-match",
			constraint: URIConstraint{
				Domain: "example.com",
				Path:   "/api",
			},
			uri:  "https://example.com/api",
			want: true,
		},
		{
			name: "fail/path-exact-mismatch",
			constraint: URIConstraint{
				Domain: "example.com",
				Path:   "/api",
			},
			uri:  "https://example.com/web",
			want: false,
		},
		// Path prefix matching
		{
			name: "ok/path-prefix-match",
			constraint: URIConstraint{
				Domain: "example.com",
				Path:   "/api/*",
			},
			uri:  "https://example.com/api/v1/users",
			want: true,
		},
		{
			name: "fail/path-prefix-mismatch",
			constraint: URIConstraint{
				Domain: "example.com",
				Path:   "/api/*",
			},
			uri:  "https://example.com/web/users",
			want: false,
		},
		// SPIFFE URI matching
		{
			name: "ok/spiffe-match",
			constraint: URIConstraint{
				Scheme: "spiffe",
				Domain: "trust.domain",
			},
			uri:  "spiffe://trust.domain/workload",
			want: true,
		},
		{
			name: "fail/spiffe-wrong-trust-domain",
			constraint: URIConstraint{
				Scheme: "spiffe",
				Domain: "trust.domain",
			},
			uri:  "spiffe://other.domain/workload",
			want: false,
		},
		// Full constraint matching
		{
			name: "ok/full-constraint-match",
			constraint: URIConstraint{
				Scheme: "https",
				Domain: "example.com",
				Path:   "/api/*",
			},
			uri:  "https://example.com/api/v1",
			want: true,
		},
		{
			name: "fail/full-constraint-wrong-scheme",
			constraint: URIConstraint{
				Scheme: "https",
				Domain: "example.com",
				Path:   "/api/*",
			},
			uri:  "http://example.com/api/v1",
			want: false,
		},
		// Error cases
		{
			name: "error/empty-host",
			constraint: URIConstraint{
				Domain: "example.com",
			},
			uri:     "https:///api/v1",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a minimal engine for domain matching
			engine, err := New()
			require.NoError(t, err)

			u, err := url.Parse(tt.uri)
			require.NoError(t, err)

			got, err := tt.constraint.MatchURI(u, engine)
			if tt.wantErr {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestNewRegexConstraint(t *testing.T) {
	tests := []struct {
		name    string
		pattern string
		wantErr bool
	}{
		{
			name:    "ok/simple-pattern",
			pattern: "^test$",
			wantErr: false,
		},
		{
			name:    "ok/domain-pattern",
			pattern: "^.*\\.example\\.com$",
			wantErr: false,
		},
		{
			name:    "ok/complex-pattern",
			pattern: "^https://[a-z]+\\.example\\.com/api/v[0-9]+/.*$",
			wantErr: false,
		},
		{
			name:    "fail/invalid-pattern",
			pattern: "[invalid",
			wantErr: true,
		},
		{
			name:    "fail/empty-pattern",
			pattern: "",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rc, err := NewRegexConstraint(tt.pattern)
			if tt.wantErr {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.pattern, rc.Pattern)
			assert.NotNil(t, rc.Compiled)
		})
	}
}

func TestRegexConstraint_Match(t *testing.T) {
	tests := []struct {
		name    string
		pattern string
		input   string
		want    bool
	}{
		{
			name:    "ok/exact-match",
			pattern: "^test$",
			input:   "test",
			want:    true,
		},
		{
			name:    "fail/exact-match",
			pattern: "^test$",
			input:   "testing",
			want:    false,
		},
		{
			name:    "ok/domain-match",
			pattern: "^.*\\.example\\.com$",
			input:   "api.example.com",
			want:    true,
		},
		{
			name:    "ok/subdomain-match",
			pattern: "^.*\\.example\\.com$",
			input:   "deep.api.example.com",
			want:    true,
		},
		{
			name:    "fail/domain-match",
			pattern: "^.*\\.example\\.com$",
			input:   "example.com",
			want:    false,
		},
		{
			name:    "ok/uri-pattern",
			pattern: "^https://.*\\.example\\.com/api/.*$",
			input:   "https://api.example.com/api/v1/users",
			want:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rc, err := NewRegexConstraint(tt.pattern)
			require.NoError(t, err)

			got := rc.Match(tt.input)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestNamePolicyEngine_URIConstraints(t *testing.T) {
	tests := []struct {
		name                    string
		permittedURIConstraints []string
		excludedURIConstraints  []string
		uri                     string
		wantErr                 bool
		wantValidationErr       bool
	}{
		{
			name:                    "ok/permitted-scheme-and-host",
			permittedURIConstraints: []string{"https://example.com"},
			uri:                     "https://example.com/api/v1",
			wantErr:                 false,
		},
		{
			name:                    "ok/permitted-with-path",
			permittedURIConstraints: []string{"https://example.com/api"},
			uri:                     "https://example.com/api",
			wantErr:                 false,
		},
		{
			name:                    "ok/permitted-path-prefix",
			permittedURIConstraints: []string{"https://example.com/api/*"},
			uri:                     "https://example.com/api/v1/users",
			wantErr:                 false,
		},
		{
			name:                    "ok/excluded-scheme",
			excludedURIConstraints:  []string{"http://example.com"},
			permittedURIConstraints: []string{"example.com"}, // Need a permitted constraint
			uri:                     "https://example.com/api",
			wantErr:                 false,
		},
		{
			name:                   "fail/excluded-matches",
			excludedURIConstraints: []string{"https://example.com"},
			uri:                    "https://example.com/api",
			wantValidationErr:      true,
		},
		{
			name:                    "ok/spiffe-constraint",
			permittedURIConstraints: []string{"spiffe://trust.domain"},
			uri:                     "spiffe://trust.domain/workload",
			wantErr:                 false,
		},
		{
			name:                    "ok/wildcard-subdomain",
			permittedURIConstraints: []string{"*.example.com"},
			uri:                     "https://api.example.com/v1",
			wantErr:                 false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			options := []NamePolicyOption{}
			if len(tt.permittedURIConstraints) > 0 {
				options = append(options, WithPermittedURIConstraints(tt.permittedURIConstraints...))
			}
			if len(tt.excludedURIConstraints) > 0 {
				options = append(options, WithExcludedURIConstraints(tt.excludedURIConstraints...))
			}

			engine, err := New(options...)
			if tt.wantErr {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)

			u, err := url.Parse(tt.uri)
			require.NoError(t, err)

			err = engine.IsX509CertificateAllowed(&x509.Certificate{
				URIs: []*url.URL{u},
			})

			if tt.wantValidationErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestNamePolicyEngine_DNSRegexConstraints(t *testing.T) {
	tests := []struct {
		name                string
		permittedDNSRegexes []string
		excludedDNSRegexes  []string
		dnsNames            []string
		wantErr             bool
		wantValidationErr   bool
	}{
		{
			name:                "ok/permitted-dns-regex-match",
			permittedDNSRegexes: []string{"^.*\\.example\\.com$"},
			dnsNames:            []string{"api.example.com"},
			wantErr:             false,
		},
		{
			name:                "fail/permitted-dns-regex-no-match",
			permittedDNSRegexes: []string{"^.*\\.example\\.com$"},
			dnsNames:            []string{"api.other.com"},
			wantValidationErr:   true, // Should be denied when regex-only and no match
		},
		{
			name:               "ok/excluded-dns-regex-no-match",
			excludedDNSRegexes: []string{"^internal\\..*$"},
			dnsNames:           []string{"api.example.com"},
			wantErr:            false,
		},
		{
			name:               "fail/excluded-dns-regex-match",
			excludedDNSRegexes: []string{"^internal\\..*$"},
			dnsNames:           []string{"internal.example.com"},
			wantValidationErr:  true,
		},
		{
			name:                "ok/multiple-regex-patterns",
			permittedDNSRegexes: []string{"^.*\\.example\\.com$", "^.*\\.test\\.com$"},
			dnsNames:            []string{"api.test.com"},
			wantErr:             false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			options := []NamePolicyOption{}
			if len(tt.permittedDNSRegexes) > 0 {
				options = append(options, WithPermittedDNSRegexes(tt.permittedDNSRegexes...))
			}
			if len(tt.excludedDNSRegexes) > 0 {
				options = append(options, WithExcludedDNSRegexes(tt.excludedDNSRegexes...))
			}

			engine, err := New(options...)
			if tt.wantErr {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)

			err = engine.IsX509CertificateAllowed(&x509.Certificate{
				DNSNames: tt.dnsNames,
			})

			if tt.wantValidationErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestNamePolicyEngine_URIRegexConstraints(t *testing.T) {
	tests := []struct {
		name                string
		permittedURIRegexes []string
		excludedURIRegexes  []string
		uri                 string
		wantErr             bool
		wantValidationErr   bool
	}{
		{
			name:                "ok/permitted-uri-regex-match",
			permittedURIRegexes: []string{"^https://.*\\.example\\.com/api/.*$"},
			uri:                 "https://api.example.com/api/v1/users",
			wantErr:             false,
		},
		{
			name:                "fail/permitted-uri-regex-no-match",
			permittedURIRegexes: []string{"^https://.*\\.example\\.com/api/.*$"},
			uri:                 "https://api.other.com/api/v1/users",
			wantValidationErr:   true, // Should be denied when regex-only and no match
		},
		{
			name:               "ok/excluded-uri-regex-no-match",
			excludedURIRegexes: []string{"^http://.*$"},
			uri:                "https://example.com/api/v1",
			wantErr:            false,
		},
		{
			name:               "fail/excluded-uri-regex-match",
			excludedURIRegexes: []string{"^http://.*$"},
			uri:                "http://example.com/api/v1",
			wantValidationErr:  true,
		},
		{
			name:                "ok/spiffe-regex",
			permittedURIRegexes: []string{"^spiffe://trust\\.domain/.*$"},
			uri:                 "spiffe://trust.domain/workload/service",
			wantErr:             false,
		},
		{
			name:                "fail/spiffe-regex-wrong-domain",
			permittedURIRegexes: []string{"^spiffe://trust\\.domain/.*$"},
			uri:                 "spiffe://other.domain/workload/service",
			wantValidationErr:   true, // Should be denied when regex-only and no match
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			options := []NamePolicyOption{}
			if len(tt.permittedURIRegexes) > 0 {
				options = append(options, WithPermittedURIRegexes(tt.permittedURIRegexes...))
			}
			if len(tt.excludedURIRegexes) > 0 {
				options = append(options, WithExcludedURIRegexes(tt.excludedURIRegexes...))
			}

			engine, err := New(options...)
			if tt.wantErr {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)

			u, err := url.Parse(tt.uri)
			require.NoError(t, err)

			err = engine.IsX509CertificateAllowed(&x509.Certificate{
				URIs: []*url.URL{u},
			})

			if tt.wantValidationErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestNamePolicyEngine_EmailRegexConstraints(t *testing.T) {
	tests := []struct {
		name                  string
		permittedEmailRegexes []string
		excludedEmailRegexes  []string
		emails                []string
		wantErr               bool
		wantValidationErr     bool
	}{
		{
			name:                  "ok/permitted-email-regex-match",
			permittedEmailRegexes: []string{"^.*@example\\.com$"},
			emails:                []string{"user@example.com"},
			wantErr:               false,
		},
		{
			name:                 "ok/excluded-email-regex-no-match",
			excludedEmailRegexes: []string{"^admin@.*$"},
			emails:               []string{"user@example.com"},
			wantErr:              false,
		},
		{
			name:                 "fail/excluded-email-regex-match",
			excludedEmailRegexes: []string{"^admin@.*$"},
			emails:               []string{"admin@example.com"},
			wantValidationErr:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			options := []NamePolicyOption{}
			if len(tt.permittedEmailRegexes) > 0 {
				options = append(options, WithPermittedEmailRegexes(tt.permittedEmailRegexes...))
			}
			if len(tt.excludedEmailRegexes) > 0 {
				options = append(options, WithExcludedEmailRegexes(tt.excludedEmailRegexes...))
			}

			engine, err := New(options...)
			if tt.wantErr {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)

			err = engine.IsX509CertificateAllowed(&x509.Certificate{
				EmailAddresses: tt.emails,
			})

			if tt.wantValidationErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestNamePolicyEngine_CommonNameRegexConstraints(t *testing.T) {
	tests := []struct {
		name                       string
		permittedCommonNameRegexes []string
		excludedCommonNameRegexes  []string
		commonName                 string
		wantErr                    bool
		wantValidationErr          bool
	}{
		{
			name:                       "ok/permitted-cn-regex-match",
			permittedCommonNameRegexes: []string{"^.*\\.example\\.com$"},
			commonName:                 "server.example.com",
			wantErr:                    false,
		},
		{
			name:                       "fail/permitted-cn-regex-no-match",
			permittedCommonNameRegexes: []string{"^.*\\.example\\.com$"},
			commonName:                 "server.other.com",
			wantValidationErr:          true,
		},
		{
			name:                      "ok/excluded-cn-regex-no-match",
			excludedCommonNameRegexes: []string{"^test-.*$"},
			commonName:                "server.example.com",
			wantErr:                   false,
		},
		{
			name:                      "fail/excluded-cn-regex-match",
			excludedCommonNameRegexes: []string{"^test-.*$"},
			commonName:                "test-server",
			wantValidationErr:         true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			options := []NamePolicyOption{
				WithSubjectCommonNameVerification(),
			}
			if len(tt.permittedCommonNameRegexes) > 0 {
				options = append(options, WithPermittedCommonNameRegexes(tt.permittedCommonNameRegexes...))
			}
			if len(tt.excludedCommonNameRegexes) > 0 {
				options = append(options, WithExcludedCommonNameRegexes(tt.excludedCommonNameRegexes...))
			}

			engine, err := New(options...)
			if tt.wantErr {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)

			err = engine.IsX509CertificateAllowed(&x509.Certificate{
				Subject: pkix.Name{
					CommonName: tt.commonName,
				},
			})

			if tt.wantValidationErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestNamePolicyEngine_SSHPrincipalRegexConstraints(t *testing.T) {
	tests := []struct {
		name                      string
		permittedPrincipalRegexes []string
		excludedPrincipalRegexes  []string
		principals                []string
		wantErr                   bool
		wantValidationErr         bool
	}{
		{
			name:                      "ok/permitted-principal-regex-match",
			permittedPrincipalRegexes: []string{"^user-.*$"},
			principals:                []string{"user-john"},
			wantErr:                   false,
		},
		{
			name:                     "ok/excluded-principal-regex-no-match",
			excludedPrincipalRegexes: []string{"^root$"},
			principals:               []string{"user-john"},
			wantErr:                  false,
		},
		{
			name:                     "fail/excluded-principal-regex-match",
			excludedPrincipalRegexes: []string{"^root$"},
			principals:               []string{"root"},
			wantValidationErr:        true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			options := []NamePolicyOption{}
			if len(tt.permittedPrincipalRegexes) > 0 {
				options = append(options, WithPermittedPrincipalRegexes(tt.permittedPrincipalRegexes...))
			}
			if len(tt.excludedPrincipalRegexes) > 0 {
				options = append(options, WithExcludedPrincipalRegexes(tt.excludedPrincipalRegexes...))
			}

			engine, err := New(options...)
			if tt.wantErr {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)

			err = engine.IsSSHCertificateAllowed(&ssh.Certificate{
				CertType:        ssh.UserCert, // Need to specify cert type
				ValidPrincipals: tt.principals,
			})

			if tt.wantValidationErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
