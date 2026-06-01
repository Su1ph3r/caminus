package vcr

import (
	"errors"
	"net/http"
	"path/filepath"
	"testing"
)

type errBody struct{}

func (errBody) Read([]byte) (int, error) { return 0, errors.New("stream reset") }
func (errBody) Close() error             { return nil }

type errRT struct{}

func (errRT) RoundTrip(*http.Request) (*http.Response, error) {
	return &http.Response{StatusCode: 200, Header: http.Header{}, Body: errBody{}}, nil
}

// A response-body read error during recording must fail loudly, not persist a
// truncated cassette that later breaks replay parsing.
func TestRecordPropagatesBodyReadError(t *testing.T) {
	tr := Record(filepath.Join(t.TempDir(), "c.json"), errRT{})
	req, _ := http.NewRequest(http.MethodGet, "http://example/x", nil)
	if _, err := tr.RoundTrip(req); err == nil {
		t.Fatal("expected record to propagate the body read error")
	}
}
