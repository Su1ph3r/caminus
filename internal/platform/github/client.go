// Package github implements read-only enumeration of a GitHub organization or
// repository into the Caminus trust graph. It uses only the standard library
// (net/http); an injectable *http.Client allows record/replay testing without a
// token.
package github

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/Su1ph3r/caminus/internal/platform"
)

const (
	defaultBaseURL = "https://api.github.com"
	apiVersion     = "2022-11-28"
)

// Sentinel errors let the enumerator treat absent or inaccessible resources as
// "skip and continue" rather than fatal — token scopes vary widely.
var (
	ErrNotFound  = errors.New("github: not found")
	ErrForbidden = errors.New("github: forbidden (insufficient scope or rate limited)")
)

// Client is a minimal read-only GitHub REST client.
type Client struct {
	http     *http.Client
	baseURL  string
	baseHost string
	token    string
}

// NewClient builds a client from credentials. hc may be nil (a default client
// is used) or a record/replay-backed client for tests.
func NewClient(creds platform.Credentials, hc *http.Client) *Client {
	base := strings.TrimRight(creds.BaseURL, "/")
	if base == "" {
		base = defaultBaseURL
	}
	if hc == nil {
		hc = &http.Client{}
	}
	c := &Client{http: hc, baseURL: base, token: creds.Token}
	if u, err := url.Parse(base); err == nil {
		c.baseHost = u.Host
	}
	return c
}

// seg escapes a single GitHub API path segment (owner, org, repo, or branch) so
// a value with reserved characters cannot alter the request path structure.
func seg(s string) string { return url.PathEscape(s) }

// repoPath escapes an "owner/repo" full name segment-wise, preserving the "/"
// separator (a wholesale PathEscape would encode the slash and break the path).
func repoPath(fullName string) string {
	parts := strings.SplitN(fullName, "/", 2)
	for i := range parts {
		parts[i] = url.PathEscape(parts[i])
	}
	return strings.Join(parts, "/")
}

// sameHost reports whether rawURL targets the configured API host. Relative
// endpoints (those used internally) are same-host by construction. This gates
// where the token may be sent and which pagination URLs may be followed, so a
// hostile API response cannot redirect an authenticated request off-host.
func (c *Client) sameHost(rawURL string) bool {
	if strings.HasPrefix(rawURL, "/") {
		return true
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		return false
	}
	return strings.EqualFold(u.Host, c.baseHost)
}

// raw issues a GET and returns the response (headers intact) plus the full body.
func (c *Client) raw(ctx context.Context, endpoint string) (*http.Response, []byte, error) {
	u := endpoint
	if strings.HasPrefix(endpoint, "/") {
		u = c.baseURL + endpoint
	}
	u = addPerPage(u)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, nil, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", apiVersion)
	// Attach the token ONLY to the configured API host, so a malicious server
	// (or a Link/redirect pointing off-host) can never receive the PAT.
	if c.token != "" && c.sameHost(u) {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return resp, nil, err
	}

	switch resp.StatusCode {
	case http.StatusOK:
		return resp, body, nil
	case http.StatusNotFound:
		return resp, body, ErrNotFound
	case http.StatusForbidden, http.StatusUnauthorized:
		// Surface rate limiting clearly (it is reported as 403 with the
		// remaining-quota header at zero) while still wrapping ErrForbidden so
		// callers treat it as a skippable access error.
		if resp.Header.Get("X-RateLimit-Remaining") == "0" {
			return resp, body, fmt.Errorf("github: rate limited (resets %s): %w",
				resp.Header.Get("X-RateLimit-Reset"), ErrForbidden)
		}
		return resp, body, ErrForbidden
	default:
		return resp, body, fmt.Errorf("github: GET %s: status %d", endpoint, resp.StatusCode)
	}
}

// getJSON fetches a single object endpoint and decodes it into out.
func (c *Client) getJSON(ctx context.Context, endpoint string, out any) error {
	_, body, err := c.raw(ctx, endpoint)
	if err != nil {
		return err
	}
	if out == nil {
		return nil
	}
	return json.Unmarshal(body, out)
}

// getList walks every page of a list endpoint, invoking decode with each page
// body. Pagination follows the RFC 5988 Link header (rel="next").
func (c *Client) getList(ctx context.Context, endpoint string, decode func([]byte) error) error {
	next := endpoint
	for next != "" {
		resp, body, err := c.raw(ctx, next)
		if err != nil {
			return err
		}
		if err := decode(body); err != nil {
			return err
		}
		next = nextLink(resp.Header.Get("Link"))
		// Refuse to follow a pagination URL onto a different host — a hostile
		// API could otherwise use it to drive enumeration (SSRF) at internal
		// targets. Legitimate GitHub/GHE next URLs are always same-host.
		if next != "" && !c.sameHost(next) {
			return fmt.Errorf("github: refusing off-host pagination URL %q (possible SSRF)", next)
		}
	}
	return nil
}

// addPerPage appends per_page=100 to list requests (idempotent, harmless on
// single-object endpoints).
func addPerPage(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return rawURL
	}
	q := u.Query()
	if q.Get("per_page") == "" {
		q.Set("per_page", "100")
	}
	u.RawQuery = q.Encode()
	return u.String()
}

// nextLink extracts the rel="next" URL from an RFC 5988 Link header, or "".
// It parses the angle-bracketed <URL> delimiters rather than splitting on raw
// commas, so a next URL whose query contains a literal comma is not truncated.
func nextLink(link string) string {
	for link != "" {
		lt := strings.IndexByte(link, '<')
		gt := strings.IndexByte(link, '>')
		if lt < 0 || gt < lt {
			return ""
		}
		url := link[lt+1 : gt]
		rest := link[gt+1:]
		// This entry's params run until the next '<' (start of the next entry).
		params := rest
		if next := strings.IndexByte(rest, '<'); next >= 0 {
			params, link = rest[:next], rest[next:]
		} else {
			link = ""
		}
		if strings.Contains(params, `rel="next"`) {
			return url
		}
	}
	return ""
}
