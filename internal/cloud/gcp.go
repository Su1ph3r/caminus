//go:build cloud

package cloud

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	iam "google.golang.org/api/iam/v1"
	"google.golang.org/api/option"
)

// gitHubGCPIssuer is the GitHub Actions OIDC issuer URL as configured on a GCP
// Workload Identity Pool provider (note the https:// prefix, unlike AWS).
const gitHubGCPIssuer = "https://" + GitHubOIDCIssuer

// FetchGCP reads a project's Workload Identity Federation configuration via the
// IAM API and returns the GitHub-OIDC → service-account impersonations it grants.
// Compiled only with `-tags cloud`. Read-only: it lists workload-identity pools
// and providers, service accounts, and each SA's IAM policy, then maps the
// GitHub-pool bindings with the dependency-free parser in gcp_member.go.
//
// Options.Transport (record/replay) + Options.Anonymous (no credentials) make it
// exercisable in CI without a GCP project, mirroring the AWS path.
func FetchGCP(ctx context.Context, opts Options) ([]GitHubTrust, error) {
	if opts.Project == "" {
		return nil, fmt.Errorf("cloud(gcp): a project id is required (--project)")
	}
	logf := opts.Logf
	if logf == nil {
		logf = func(string, ...any) {}
	}

	var clientOpts []option.ClientOption
	switch {
	case opts.Transport != nil:
		// A custom (record/replay) transport serves responses directly, so no
		// credential chain is needed or wanted. WithHTTPClient supersedes auth.
		clientOpts = append(clientOpts, option.WithHTTPClient(&http.Client{Transport: opts.Transport}))
	case opts.Anonymous:
		clientOpts = append(clientOpts, option.WithoutAuthentication())
	}
	svc, err := iam.NewService(ctx, clientOpts...)
	if err != nil {
		return nil, fmt.Errorf("cloud(gcp): init IAM client: %w", err)
	}

	githubPools, err := githubFederatingPools(ctx, svc, opts.Project, logf)
	if err != nil {
		return nil, err
	}
	if len(githubPools) == 0 {
		logf("no workload-identity pool federates GitHub Actions OIDC in project %s", opts.Project)
		return nil, nil
	}

	return gcpServiceAccountTrusts(ctx, svc, opts.Project, githubPools, logf)
}

// githubFederatingPools returns the set of workload-identity-pool resource names
// in the project that have at least one OIDC provider trusting the GitHub Actions
// issuer.
func githubFederatingPools(ctx context.Context, svc *iam.Service, project string, logf func(string, ...any)) (map[string]bool, error) {
	parent := fmt.Sprintf("projects/%s/locations/global", project)
	pools := map[string]bool{}
	err := svc.Projects.Locations.WorkloadIdentityPools.List(parent).Pages(ctx, func(resp *iam.ListWorkloadIdentityPoolsResponse) error {
		for _, pool := range resp.WorkloadIdentityPools {
			if pool.Disabled || pool.State != "ACTIVE" {
				continue
			}
			github, perr := poolFederatesGitHub(ctx, svc, pool.Name)
			if perr != nil {
				logf("pool %s: provider list failed, skipped: %v", pool.Name, perr)
				continue
			}
			if github {
				pools[pool.Name] = true
			}
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("cloud(gcp): list workload-identity pools: %w", err)
	}
	return pools, nil
}

func poolFederatesGitHub(ctx context.Context, svc *iam.Service, poolName string) (bool, error) {
	found := false
	err := svc.Projects.Locations.WorkloadIdentityPools.Providers.List(poolName).Pages(ctx, func(resp *iam.ListWorkloadIdentityPoolProvidersResponse) error {
		for _, p := range resp.WorkloadIdentityPoolProviders {
			if p.Disabled || p.Oidc == nil {
				continue
			}
			if strings.TrimRight(p.Oidc.IssuerUri, "/") == gitHubGCPIssuer {
				found = true
			}
		}
		return nil
	})
	return found, err
}

// gcpServiceAccountTrusts walks every service account's IAM policy and converts
// impersonation bindings that reference a GitHub-federating pool into trusts.
func gcpServiceAccountTrusts(ctx context.Context, svc *iam.Service, project string, githubPools map[string]bool, logf func(string, ...any)) ([]GitHubTrust, error) {
	var out []GitHubTrust
	name := "projects/" + project
	err := svc.Projects.ServiceAccounts.List(name).Pages(ctx, func(resp *iam.ListServiceAccountsResponse) error {
		for _, sa := range resp.Accounts {
			policy, perr := svc.Projects.ServiceAccounts.GetIamPolicy(sa.Name).Context(ctx).Do()
			if perr != nil {
				logf("service account %s: getIamPolicy failed, skipped: %v", sa.Email, perr)
				continue
			}
			out = append(out, trustsFromPolicy(sa, project, policy, githubPools, logf)...)
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("cloud(gcp): list service accounts: %w", err)
	}
	return out, nil
}

func trustsFromPolicy(sa *iam.ServiceAccount, project string, policy *iam.Policy, githubPools map[string]bool, logf func(string, ...any)) []GitHubTrust {
	label := sa.Email
	if sa.DisplayName != "" {
		label = sa.DisplayName
	}
	var out []GitHubTrust
	for _, b := range policy.Bindings {
		if !gcpImpersonationRole(b.Role) {
			continue
		}
		for _, m := range b.Members {
			patterns, hasSub, class := parseGCPMember(m, githubPools)
			switch class {
			case memberNotGitHub:
				continue
			case memberUnmappedAttr:
				logf("service account %s: GitHub pool member %q uses an attribute mapping Caminus can't scope; skipped", sa.Email, m)
				continue
			}
			out = append(out, GitHubTrust{
				Provider:    "gcp",
				RoleARN:     sa.Email,
				RoleName:    label,
				Account:     project,
				SubPatterns: patterns,
				HasSub:      hasSub,
			})
		}
	}
	return out
}
