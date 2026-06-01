// Package vcr provides a record/replay http.RoundTripper for deterministic,
// token-free testing of API clients — the same pattern Vercelsior uses.
//
// In replay mode the transport serves responses from a JSON cassette and never
// touches the network (no credentials required). In record mode it forwards to
// a real transport and appends each interaction to the cassette so a live run
// can be captured once and replayed forever.
package vcr

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"sync"
)

// Interaction is one recorded request/response pair. Match is a request-body
// discriminator (e.g. "Action=ListRoles") so query-protocol APIs like AWS IAM —
// where every call is POST / with the action in the body — can be told apart.
// It is empty for body-less GET requests (e.g. the GitHub REST client).
type Interaction struct {
	Method  string            `json:"method"`
	Path    string            `json:"path"`
	Query   string            `json:"query,omitempty"`
	Match   string            `json:"match,omitempty"`
	Status  int               `json:"status"`
	Headers map[string]string `json:"headers,omitempty"`
	Body    string            `json:"body"`
}

// Cassette is a sequence of interactions persisted as JSON.
type Cassette struct {
	Interactions []Interaction `json:"interactions"`
}

type mode int

const (
	modeReplay mode = iota
	modeRecord
)

// Transport is an http.RoundTripper backed by a cassette.
type Transport struct {
	mode     mode
	path     string
	cassette *Cassette
	under    http.RoundTripper
	mu       sync.Mutex
}

// Replay loads a cassette and returns a transport that serves from it.
func Replay(path string) (*Transport, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var c Cassette
	if err := json.Unmarshal(data, &c); err != nil {
		return nil, fmt.Errorf("vcr: parse cassette %s: %w", path, err)
	}
	return &Transport{mode: modeReplay, path: path, cassette: &c}, nil
}

// Record returns a transport that forwards to under and captures interactions.
// Call Save to persist the cassette. If under is nil, http.DefaultTransport is
// used.
func Record(path string, under http.RoundTripper) *Transport {
	if under == nil {
		under = http.DefaultTransport
	}
	return &Transport{mode: modeRecord, path: path, cassette: &Cassette{}, under: under}
}

func key(method, path, query, match string) string {
	return method + " " + path + "?" + normalizeQuery(query) + "#" + match
}

// requestDiscriminator returns a stable body discriminator for matching. For
// AWS query-protocol bodies (Action=…&Version=…) it returns "Action=<name>";
// otherwise the raw body (or "" if there is none). It reads and restores
// req.Body so the request remains sendable in record mode.
func requestDiscriminator(req *http.Request) string {
	if req.Body == nil {
		return ""
	}
	b, err := io.ReadAll(req.Body)
	if err != nil {
		return ""
	}
	req.Body = io.NopCloser(bytes.NewReader(b))
	if len(b) == 0 {
		return ""
	}
	if v, err := url.ParseQuery(string(b)); err == nil {
		if a := v.Get("Action"); a != "" {
			return "Action=" + a
		}
	}
	return string(b)
}

// normalizeQuery sorts query params so cassette lookups are order-independent.
func normalizeQuery(raw string) string {
	if raw == "" {
		return ""
	}
	parts := strings.Split(raw, "&")
	sort.Strings(parts)
	return strings.Join(parts, "&")
}

// RoundTrip implements http.RoundTripper.
func (t *Transport) RoundTrip(req *http.Request) (*http.Response, error) {
	if t.mode == modeReplay {
		return t.replay(req)
	}
	return t.record(req)
}

func (t *Transport) replay(req *http.Request) (*http.Response, error) {
	want := key(req.Method, req.URL.Path, req.URL.RawQuery, requestDiscriminator(req))
	for _, in := range t.cassette.Interactions {
		if key(in.Method, in.Path, in.Query, in.Match) == want {
			return buildResponse(req, in), nil
		}
	}
	return nil, fmt.Errorf("vcr: no recorded interaction for %s", want)
}

func (t *Transport) record(req *http.Request) (*http.Response, error) {
	match := requestDiscriminator(req)
	resp, err := t.under.RoundTrip(req)
	if err != nil {
		return nil, err
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()

	in := Interaction{
		Method:  req.Method,
		Path:    req.URL.Path,
		Query:   req.URL.RawQuery,
		Match:   match,
		Status:  resp.StatusCode,
		Headers: map[string]string{},
		Body:    string(body),
	}
	// Preserve pagination so replayed runs page identically.
	if link := resp.Header.Get("Link"); link != "" {
		in.Headers["Link"] = link
	}
	t.mu.Lock()
	t.cassette.Interactions = append(t.cassette.Interactions, in)
	t.mu.Unlock()

	resp.Body = io.NopCloser(bytes.NewReader(body))
	return resp, nil
}

// buildResponse synthesizes an http.Response from a recorded interaction.
func buildResponse(req *http.Request, in Interaction) *http.Response {
	h := http.Header{}
	for k, v := range in.Headers {
		h.Set(k, v)
	}
	return &http.Response{
		StatusCode: in.Status,
		Status:     http.StatusText(in.Status),
		Header:     h,
		Body:       io.NopCloser(strings.NewReader(in.Body)),
		Request:    req,
	}
}

// Save writes the recorded cassette to disk (record mode only).
func (t *Transport) Save() error {
	if t.mode != modeRecord {
		return nil
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	data, err := json.MarshalIndent(t.cassette, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(t.path, data, 0o644)
}
