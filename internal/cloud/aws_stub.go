//go:build !cloud

package cloud

import "context"

// Fetch is the no-op stub used in the dependency-free build. It returns
// ErrNotBuilt (defined in enrich.go) directing the user to rebuild with the
// `cloud` tag.
func Fetch(_ context.Context, _ Options) ([]GitHubTrust, error) {
	return nil, ErrNotBuilt
}
