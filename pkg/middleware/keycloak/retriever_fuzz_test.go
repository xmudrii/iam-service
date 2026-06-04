package keycloak

import (
	"strings"
	"testing"
)

// FuzzGetIDMTenant fuzzes the parsing of the JWT issuer claim into an IDM
// tenant (Keycloak realm). The issuer is attacker-influenced token input, and
// GetIDMTenant runs it through a regex and then indexes the submatch, so the
// invariant under test is that no input can make it panic. When parsing
// succeeds, the returned realm must be a substring of the issuer (the regex
// only ever captures part of the input, never synthesizes content).
func FuzzGetIDMTenant(f *testing.F) {
	seeds := []string{
		// Valid issuers.
		"https://auth.example.com/realms/my-realm",
		"https://auth.example.com/realms/my-realm/",
		"https://auth.example.com:8443/realms/production",
		"http://localhost:8080/realms/development",
		"https://example.com/auth/realms/master",
		"https://auth.example.com/realms/realm.with.dots",
		"https://auth.example.com/realms/first/realms/second",
		// Invalid / degenerate issuers.
		"",
		"not-a-url",
		"https://",
		"https://auth.example.com/auth",
		"https://auth.example.com/REALMS/test",
		"https://auth.example.com/realms/",
		"https://auth.example.com/realms//",
		"/realms/",
		"realms/realms/realms/",
		// Adversarial: control chars, unicode, repetition.
		"https://x/realms/\x00\n\t",
		"https://x/realms/üñïçødé-rëälm",
		"https://x/realms/" + string(rune(0x10FFFF)),
	}
	for _, s := range seeds {
		f.Add(s)
	}

	retriever := &KeycloakIDMRetriever{}

	f.Fuzz(func(t *testing.T, issuer string) {
		realm, err := retriever.GetIDMTenant(issuer)
		if err != nil {
			// On error the realm must be empty.
			if realm != "" {
				t.Fatalf("non-empty realm %q returned alongside error %v", realm, err)
			}
			return
		}
		// On success the captured realm must originate from the issuer.
		if !strings.Contains(issuer, realm) {
			t.Fatalf("realm %q is not contained in issuer %q", realm, issuer)
		}
	})
}
