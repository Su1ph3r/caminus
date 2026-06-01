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
	http    *http.Client
	baseURL string
	token   string
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
	return &Client{http: hc, baseURL: base, token: creds.Token}
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
	if c.token != "" {
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

// nextLink extracts the rel="next" URL from a Link header, or "".
func nextLink(link string) string {
	if link == "" {
		return ""
	}
	for _, part := range strings.Split(link, ",") {
		segs := strings.Split(strings.TrimSpace(part), ";")
		if len(segs) < 2 {
			continue
		}
		isNext := false
		for _, s := range segs[1:] {
			if strings.Contains(s, `rel="next"`) {
				isNext = true
			}
		}
		if isNext {
			return strings.Trim(strings.TrimSpace(segs[0]), "<>")
		}
	}
	return ""
}
