// Package gitlab implements read-only enumeration of a GitLab group, user, or
// project into the Caminus trust graph. Like the github package it uses only the
// standard library (net/http) and an injectable *http.Client so the same
// record/replay harness drives it without a token.
//
// GitLab's REST API (v4) mirrors GitHub's shape closely enough that the client
// reuses the same defenses: the token is attached only to the configured API
// host, pagination follows the RFC 5988 Link header (GitLab emits it too), and
// off-host next/redirect URLs are refused so a hostile response cannot exfil the
// token or drive SSRF.
package gitlab

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

const defaultBaseURL = "https://gitlab.com/api/v4"

// Sentinel errors let the enumerator treat absent or inaccessible resources as
// "skip and continue" rather than fatal — token scopes vary widely.
var (
	ErrNotFound  = errors.New("gitlab: not found")
	ErrForbidden = errors.New("gitlab: forbidden (insufficient scope or rate limited)")
)

// Client is a minimal read-only GitLab REST client.
type Client struct {
	http     *http.Client
	baseURL  string
	baseHost string
	token    string
}

// NewClient builds a client from credentials. hc may be nil (a default client is
// used) or a record/replay-backed client for tests. A BaseURL without an /api/v4
// suffix (e.g. a self-managed host root) has it appended.
func NewClient(creds platform.Credentials, hc *http.Client) *Client {
	base := strings.TrimRight(creds.BaseURL, "/")
	if base == "" {
		base = defaultBaseURL
	} else if !strings.Contains(base, "/api/") {
		base += "/api/v4"
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

// Host reports the configured API host (used to label the GitLab instance and
// derive the OIDC issuer).
func (c *Client) Host() string { return c.baseHost }

// sameHost reports whether rawURL targets the configured API host. Relative
// endpoints are same-host by construction. This gates where the token may be
// sent and which pagination URLs may be followed.
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
	req.Header.Set("Accept", "application/json")
	// Attach the token ONLY to the configured API host, so a malicious server
	// (or a Link/redirect pointing off-host) can never receive it. GitLab
	// accepts a PAT / project / group access token via the PRIVATE-TOKEN header.
	if c.token != "" && c.sameHost(u) {
		req.Header.Set("PRIVATE-TOKEN", c.token)
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
		return resp, body, ErrForbidden
	case http.StatusTooManyRequests:
		// Rate limiting is a transient transport-class failure, not "absent":
		// surface it clearly so the caller marks the graph incomplete.
		return resp, body, fmt.Errorf("gitlab: rate limited (retry after %s)",
			resp.Header.Get("Retry-After"))
	default:
		return resp, body, fmt.Errorf("gitlab: GET %s: status %d", endpoint, resp.StatusCode)
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
// body. Pagination follows the RFC 5988 Link header (rel="next"); GitLab uses
// keyset/offset pagination behind that header.
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
		if next != "" && !c.sameHost(next) {
			return fmt.Errorf("gitlab: refusing off-host pagination URL %q (possible SSRF)", next)
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

// nextLink extracts the rel="next" URL from an RFC 5988 Link header, or "". It
// parses the angle-bracketed <URL> delimiters rather than splitting on raw
// commas, so a next URL whose query contains a literal comma is not truncated.
func nextLink(link string) string {
	for link != "" {
		lt := strings.IndexByte(link, '<')
		gt := strings.IndexByte(link, '>')
		if lt < 0 || gt < lt {
			return ""
		}
		urlStr := link[lt+1 : gt]
		rest := link[gt+1:]
		params := rest
		if n := strings.IndexByte(rest, '<'); n >= 0 {
			params, link = rest[:n], rest[n:]
		} else {
			link = ""
		}
		if strings.Contains(params, `rel="next"`) {
			return urlStr
		}
	}
	return ""
}

// pathEsc URL-encodes a GitLab id-or-path segment (e.g. "group/project" →
// "group%2Fproject") for use in :id positional parameters.
func pathEsc(s string) string { return url.PathEscape(s) }
