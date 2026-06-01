package gitlab

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/Su1ph3r/caminus/internal/platform"
)

// captureRT records outgoing requests and optionally returns a Link header
// pointing off-host on the first response.
type captureRT struct {
	reqs     []*http.Request
	offHost  bool
	returned bool
}

func (c *captureRT) RoundTrip(req *http.Request) (*http.Response, error) {
	c.reqs = append(c.reqs, req)
	h := http.Header{}
	if c.offHost && !c.returned {
		c.returned = true
		h.Set("Link", `<https://attacker.example/exfil>; rel="next"`)
	}
	return &http.Response{
		StatusCode: 200, Header: h,
		Body: io.NopCloser(strings.NewReader("[]")), Request: req,
	}, nil
}

func TestGetListRefusesOffHostNext(t *testing.T) {
	rt := &captureRT{offHost: true}
	c := NewClient(platform.Credentials{Token: "SECRET", BaseURL: "https://gitlab.com"},
		&http.Client{Transport: rt})

	err := c.getList(context.Background(), "/groups/x/projects", func([]byte) error { return nil })
	if err == nil || !strings.Contains(err.Error(), "off-host") {
		t.Fatalf("expected off-host pagination refusal, got %v", err)
	}
	if len(rt.reqs) != 1 {
		t.Fatalf("expected exactly 1 request (off-host next refused), got %d", len(rt.reqs))
	}
	// The same-host request DID carry the token (proves the gate is host-based).
	if got := rt.reqs[0].Header.Get("PRIVATE-TOKEN"); got != "SECRET" {
		t.Errorf("same-host PRIVATE-TOKEN = %q, want SECRET", got)
	}
}

func TestRawDropsTokenOffHost(t *testing.T) {
	rt := &captureRT{}
	c := NewClient(platform.Credentials{Token: "SECRET", BaseURL: "https://gitlab.com"},
		&http.Client{Transport: rt})

	_, _, _ = c.raw(context.Background(), "https://attacker.example/x")
	if len(rt.reqs) != 1 {
		t.Fatalf("expected 1 request, got %d", len(rt.reqs))
	}
	if got := rt.reqs[0].Header.Get("PRIVATE-TOKEN"); got != "" {
		t.Errorf("token leaked to off-host request: PRIVATE-TOKEN=%q", got)
	}
}

func TestBaseURLNormalization(t *testing.T) {
	cases := map[string]string{
		"":                                  "https://gitlab.com/api/v4",
		"https://gitlab.example.com":        "https://gitlab.example.com/api/v4",
		"https://gitlab.example.com/api/v4": "https://gitlab.example.com/api/v4",
	}
	for in, want := range cases {
		c := NewClient(platform.Credentials{BaseURL: in}, &http.Client{})
		if c.baseURL != want {
			t.Errorf("NewClient(BaseURL=%q).baseURL = %q, want %q", in, c.baseURL, want)
		}
	}
}

func TestNextLink(t *testing.T) {
	link := `<https://gitlab.com/api/v4/x?page=2>; rel="next", <https://gitlab.com/api/v4/x?page=5>; rel="last"`
	if got := nextLink(link); got != "https://gitlab.com/api/v4/x?page=2" {
		t.Errorf("nextLink = %q", got)
	}
	if got := nextLink(""); got != "" {
		t.Errorf("nextLink(empty) = %q", got)
	}
}
