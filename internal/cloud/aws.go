//go:build cloud

package cloud

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/iam"
)

// Fetch loads IAM roles via the AWS SDK and returns the GitHub-OIDC federations
// among their trust policies. It is compiled only with `-tags cloud`. Read-only:
// it calls iam:ListRoles (which returns each role's AssumeRolePolicyDocument)
// and parses the documents with the dependency-free parser in trust.go.
//
// Options.Transport (record/replay) and Options.Anonymous (static dummy creds
// for replay) make this exercisable in CI without a live account.
func Fetch(ctx context.Context, opts Options) ([]GitHubTrust, error) {
	var loadOpts []func(*config.LoadOptions) error
	if opts.Region != "" {
		loadOpts = append(loadOpts, config.WithRegion(opts.Region))
	}
	if opts.Profile != "" {
		loadOpts = append(loadOpts, config.WithSharedConfigProfile(opts.Profile))
	}
	if opts.Transport != nil {
		loadOpts = append(loadOpts, config.WithHTTPClient(&http.Client{Transport: opts.Transport}))
	}
	if opts.Anonymous {
		loadOpts = append(loadOpts, config.WithCredentialsProvider(
			credentials.NewStaticCredentialsProvider("replay", "replay", "")))
		if opts.Region == "" {
			loadOpts = append(loadOpts, config.WithRegion("us-east-1"))
		}
	}

	cfg, err := config.LoadDefaultConfig(ctx, loadOpts...)
	if err != nil {
		return nil, fmt.Errorf("cloud: load AWS config: %w", err)
	}
	logf := opts.Logf
	if logf == nil {
		logf = func(string, ...any) {}
	}
	return fetchRoles(ctx, iam.NewFromConfig(cfg), logf)
}

// rolePager is the subset of the IAM client fetchRoles needs, so tests can
// drive it through a paginator over a recorded response.
type rolePager interface {
	ListRoles(ctx context.Context, in *iam.ListRolesInput, optFns ...func(*iam.Options)) (*iam.ListRolesOutput, error)
}

func fetchRoles(ctx context.Context, client rolePager, logf func(string, ...any)) ([]GitHubTrust, error) {
	paginator := iam.NewListRolesPaginator(client, &iam.ListRolesInput{})
	var out []GitHubTrust
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("cloud: list IAM roles: %w", err)
		}
		for _, r := range page.Roles {
			if r.AssumeRolePolicyDocument == nil || r.Arn == nil || r.RoleName == nil {
				continue
			}
			doc, err := url.QueryUnescape(*r.AssumeRolePolicyDocument)
			if err != nil {
				// Fall back to the raw document but record that we couldn't
				// decode it, so a parse failure below is attributable.
				logf("role %s: trust document not URL-decodable: %v", *r.Arn, err)
				doc = *r.AssumeRolePolicyDocument
			}
			trusts, err := ParseTrustPolicy(*r.Arn, *r.RoleName, accountFromARN(*r.Arn), doc)
			if err != nil {
				// Surface the skip — a dropped role is a false negative for the
				// "which pipelines can assume which roles" question.
				logf("role %s: skipped, trust policy unparsable: %v", *r.Arn, err)
				continue
			}
			out = append(out, trusts...)
		}
	}
	return out, nil
}

// accountFromARN extracts the account ID from an IAM role ARN
// (arn:aws:iam::<account>:role/<name>).
func accountFromARN(arn string) string {
	parts := strings.Split(arn, ":")
	if len(parts) >= 5 {
		return parts[4]
	}
	return ""
}
