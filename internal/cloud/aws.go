//go:build cloud

package cloud

import (
	"context"
	"fmt"
	"net/url"
	"strings"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/iam"
)

// Fetch loads IAM roles via the AWS SDK and returns the GitHub-OIDC federations
// among their trust policies. It is compiled only with `-tags cloud`. Read-only:
// it calls iam:ListRoles (which returns each role's AssumeRolePolicyDocument)
// and parses the documents with the dependency-free parser in trust.go.
func Fetch(ctx context.Context, opts Options) ([]GitHubTrust, error) {
	loadOpts := []func(*config.LoadOptions) error{}
	if opts.Region != "" {
		loadOpts = append(loadOpts, config.WithRegion(opts.Region))
	}
	if opts.Profile != "" {
		loadOpts = append(loadOpts, config.WithSharedConfigProfile(opts.Profile))
	}
	cfg, err := config.LoadDefaultConfig(ctx, loadOpts...)
	if err != nil {
		return nil, fmt.Errorf("cloud: load AWS config: %w", err)
	}

	client := iam.NewFromConfig(cfg)
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
				doc = *r.AssumeRolePolicyDocument
			}
			trusts, err := ParseTrustPolicy(*r.Arn, *r.RoleName, accountFromARN(*r.Arn), doc)
			if err != nil {
				continue // skip unparsable policies rather than abort the scan
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
