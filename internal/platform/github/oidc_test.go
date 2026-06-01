package github

import "testing"

func TestOIDCSubject(t *testing.T) {
	cases := []struct {
		name      string
		sub       oidcSub
		overBroad bool
	}{
		{"default is scoped", oidcSub{UseDefault: true}, false},
		{"repo-only is over-broad", oidcSub{IncludeClaimKeys: []string{"repo"}}, true},
		{"repo+context is scoped", oidcSub{IncludeClaimKeys: []string{"repo", "context"}}, false},
		{"repo+environment is scoped", oidcSub{IncludeClaimKeys: []string{"repo", "environment"}}, false},
		{"owner+actor is over-broad", oidcSub{IncludeClaimKeys: []string{"repository_owner", "actor"}}, true},
		{"empty customization is over-broad", oidcSub{UseDefault: false}, true},
		{"ref scoping is fine", oidcSub{IncludeClaimKeys: []string{"repo", "ref"}}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, got, _ := oidcSubject("acme/widgets", c.sub)
			if got != c.overBroad {
				t.Errorf("oidcSubject(%v) over-broad = %v, want %v", c.sub.IncludeClaimKeys, got, c.overBroad)
			}
		})
	}
}
