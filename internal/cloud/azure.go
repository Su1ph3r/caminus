//go:build cloud

package cloud

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	azpolicy "github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/runtime"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
)

// gitHubAzureIssuer is the GitHub Actions OIDC issuer as configured on an Entra
// app-registration federated identity credential (FIC).
const gitHubAzureIssuer = "https://" + GitHubOIDCIssuer

const (
	graphBase  = "https://graph.microsoft.com/v1.0"
	graphScope = "https://graph.microsoft.com/.default"
)

// --- Microsoft Graph response shapes (only the fields Caminus uses) ---------

type graphOrgList struct {
	Value []struct {
		ID string `json:"id"`
	} `json:"value"`
}

type graphApp struct {
	ID          string `json:"id"`
	AppID       string `json:"appId"`
	DisplayName string `json:"displayName"`
}

type graphAppList struct {
	Value    []graphApp `json:"value"`
	NextLink string     `json:"@odata.nextLink"`
}

type graphFIC struct {
	Name      string   `json:"name"`
	Issuer    string   `json:"issuer"`
	Subject   string   `json:"subject"`
	Audiences []string `json:"audiences"`
}

type graphFICList struct {
	Value    []graphFIC `json:"value"`
	NextLink string     `json:"@odata.nextLink"`
}

// FetchAzure reads Entra ID app-registration federated identity credentials via
// Microsoft Graph and returns the GitHub-OIDC → app federations they grant. An
// app whose FIC trusts the GitHub Actions issuer can be assumed (client-assertion
// grant) by any workflow run whose OIDC subject equals the FIC subject. Compiled
// only with `-tags cloud`.
//
// Options.Transport (record/replay) + Options.Anonymous (static token, no real
// credential) make it exercisable in CI without an Azure tenant.
func FetchAzure(ctx context.Context, opts Options) ([]GitHubTrust, error) {
	logf := opts.Logf
	if logf == nil {
		logf = func(string, ...any) {}
	}

	var cred azcore.TokenCredential
	if opts.Anonymous {
		cred = staticToken{}
	} else {
		c, err := azidentity.NewDefaultAzureCredential(nil)
		if err != nil {
			return nil, fmt.Errorf("cloud(azure): credential: %w", err)
		}
		cred = c
	}

	clientOpts := &azcore.ClientOptions{}
	if opts.Transport != nil {
		clientOpts.Transport = rtAdapter{opts.Transport}
	}
	plOpts := runtime.PipelineOptions{
		PerRetry: []azpolicy.Policy{runtime.NewBearerTokenPolicy(cred, []string{graphScope}, nil)},
	}
	client, err := azcore.NewClient("caminus.internal.cloud", "v0.2.0", plOpts, clientOpts)
	if err != nil {
		return nil, fmt.Errorf("cloud(azure): init Graph client: %w", err)
	}
	pl := client.Pipeline()

	tenant := azureTenant(ctx, pl, logf)
	apps, err := azureApps(ctx, pl)
	if err != nil {
		return nil, err
	}

	var out []GitHubTrust
	for _, app := range apps {
		fics, ferr := azureFICs(ctx, pl, app.ID)
		if ferr != nil {
			logf("app %s (%s): federated-credential list failed, skipped: %v", app.DisplayName, app.AppID, ferr)
			continue
		}
		label := app.DisplayName
		if label == "" {
			label = app.AppID
		}
		for _, fic := range fics {
			if !issuerIsGitHub(fic.Issuer) {
				continue
			}
			out = append(out, GitHubTrust{
				Provider:    "azure",
				RoleARN:     app.AppID,
				RoleName:    label,
				Account:     tenant,
				SubPatterns: []string{fic.Subject},
				Audiences:   fic.Audiences,
				HasSub:      fic.Subject != "",
			})
		}
	}
	return out, nil
}

func issuerIsGitHub(issuer string) bool {
	return trimSlash(issuer) == gitHubAzureIssuer
}

func trimSlash(s string) string {
	for len(s) > 0 && s[len(s)-1] == '/' {
		s = s[:len(s)-1]
	}
	return s
}

// azureTenant best-effort reads the tenant id (for finding context). A failure
// is non-fatal — the trusts are still valid without it.
func azureTenant(ctx context.Context, pl runtime.Pipeline, logf func(string, ...any)) string {
	var org graphOrgList
	if err := graphGet(ctx, pl, graphBase+"/organization?$select=id", &org); err != nil {
		logf("tenant lookup failed (non-fatal): %v", err)
		return ""
	}
	if len(org.Value) > 0 {
		return org.Value[0].ID
	}
	return ""
}

func azureApps(ctx context.Context, pl runtime.Pipeline) ([]graphApp, error) {
	var out []graphApp
	url := graphBase + "/applications?$select=id,appId,displayName"
	for url != "" {
		var page graphAppList
		if err := graphGet(ctx, pl, url, &page); err != nil {
			return nil, fmt.Errorf("cloud(azure): list applications: %w", err)
		}
		out = append(out, page.Value...)
		url = page.NextLink
	}
	return out, nil
}

func azureFICs(ctx context.Context, pl runtime.Pipeline, appObjectID string) ([]graphFIC, error) {
	var out []graphFIC
	url := graphBase + "/applications/" + appObjectID + "/federatedIdentityCredentials"
	for url != "" {
		var page graphFICList
		if err := graphGet(ctx, pl, url, &page); err != nil {
			return nil, err
		}
		out = append(out, page.Value...)
		url = page.NextLink
	}
	return out, nil
}

// graphGet issues an authenticated GET through the azcore pipeline and decodes
// the JSON body into out.
func graphGet(ctx context.Context, pl runtime.Pipeline, url string, out any) error {
	req, err := runtime.NewRequest(ctx, http.MethodGet, url)
	if err != nil {
		return err
	}
	resp, err := pl.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("graph GET %s: status %d", url, resp.StatusCode)
	}
	return json.Unmarshal(body, out)
}

// rtAdapter exposes an http.RoundTripper as an azcore policy.Transporter so the
// vcr record/replay transport can drive the Graph client.
type rtAdapter struct{ rt http.RoundTripper }

func (a rtAdapter) Do(req *http.Request) (*http.Response, error) { return a.rt.RoundTrip(req) }

// staticToken is a no-op TokenCredential for replay: the recorded transport
// serves responses regardless of the (ignored) bearer token.
type staticToken struct{}

func (staticToken) GetToken(_ context.Context, _ azpolicy.TokenRequestOptions) (azcore.AccessToken, error) {
	return azcore.AccessToken{Token: "replay", ExpiresOn: time.Now().Add(time.Hour)}, nil
}
