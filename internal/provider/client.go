package provider

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"

	"connectrpc.com/connect"
	"github.com/hashicorp/terraform-plugin-framework/diag"

	client "github.com/pomerium/enterprise-client-go"
	"github.com/pomerium/sdk-go"
	"github.com/pomerium/sdk-go/proto/pomerium"
)

type serverType string

const (
	// serverTypeLegacy indicates that the server is an enterprise server that
	// does not support the consolidated api
	serverTypeLegacy serverType = "legacy"
	// serverTypeEnterprise indicates that the server is an enterprise server
	// that does support the consolidated api
	serverTypeEnterprise serverType = "enterprise"
	// serverTypeCore indicates that the server is a core server
	serverTypeCore serverType = "core"
	// serverTypeZero indicates that the server is a zero server
	serverTypeZero serverType = "zero"
)

type Client struct {
	consolidated sdk.Client
	enterprise   *client.Client
}

func NewClient(apiURL, apiToken string, tlsConfig *tls.Config) (*Client, error) {
	u, err := url.Parse(apiURL)
	if err != nil {
		return nil, fmt.Errorf("error parsing api_url: %w", err)
	}
	host, port := u.Hostname(), u.Port()
	if host == "" {
		return nil, fmt.Errorf("api_url is missing hostname")
	}
	if port == "" {
		port = "443"
	}

	httpTransport := http.DefaultTransport.(*http.Transport).Clone()
	httpTransport.TLSClientConfig = tlsConfig
	httpClient := &http.Client{
		Transport: httpTransport,
	}

	consolidatedClient := sdk.NewClient(
		sdk.WithAPIToken(apiToken),
		sdk.WithHTTPClient(httpClient),
		sdk.WithURL(apiURL),
	)

	enterpriseClient, err := client.NewClient(context.Background(), net.JoinHostPort(host, port), apiToken, client.WithTlsConfig(tlsConfig))
	if err != nil {
		return nil, fmt.Errorf("error creating client: %w", err)
	}

	return &Client{
		consolidated: consolidatedClient,
		enterprise:   enterpriseClient,
	}, nil
}

// ConsolidatedOrLegacy invokes onConsolidated if the server is of type core,
// zero, or enterprise. If its a legacy enterprise server, onLegacy is invoked.
func (c *Client) ConsolidatedOrLegacy(
	ctx context.Context,
	onConsolidated func(client sdk.Client),
	onLegacy func(client *client.Client),
) diag.Diagnostics {
	var diagnostics diag.Diagnostics

	serverType, err := c.getServerType(ctx)
	if err != nil {
		diagnostics.Append(diag.NewErrorDiagnostic("error determining server type", err.Error()))
		return diagnostics
	}

	switch serverType {
	case serverTypeCore, serverTypeEnterprise, serverTypeZero:
		onConsolidated(c.consolidated)
	case serverTypeLegacy:
		onLegacy(c.enterprise)
	default:
		diagnostics.Append(diag.NewErrorDiagnostic("unsupported server type",
			fmt.Sprintf("unsupported server type: %s", serverType)))
	}

	return diagnostics
}

// EnterpriseOnly invokes onEnterprise if the server is not of type zero or
// core.
func (c *Client) EnterpriseOnly(
	ctx context.Context,
	onEnterprise func(client *client.Client),
) diag.Diagnostics {
	var diagnostics diag.Diagnostics

	serverType, err := c.getServerType(ctx)
	if err != nil {
		diagnostics.Append(diag.NewErrorDiagnostic("error determining server type", err.Error()))
		return diagnostics
	}

	switch serverType {
	case serverTypeLegacy, serverTypeEnterprise:
		onEnterprise(c.enterprise)
	case serverTypeCore, serverTypeZero:
		fallthrough
	default:
		diagnostics.Append(diag.NewErrorDiagnostic("unsupported server type",
			fmt.Sprintf("unsupported server type: %s", serverType)))
	}

	return diagnostics
}

func (c *Client) getServerType(ctx context.Context) (serverType, error) {
	res, err := c.consolidated.GetServerInfo(ctx, connect.NewRequest(&pomerium.GetServerInfoRequest{}))
	if err != nil {
		if strings.Contains(err.Error(), "415 Unsupported Media Type") {
			return serverTypeLegacy, nil
		}
		return serverTypeLegacy, err
	}

	switch res.Msg.GetServerType() {
	case pomerium.ServerType_SERVER_TYPE_CORE:
		return serverTypeCore, nil
	case pomerium.ServerType_SERVER_TYPE_ENTERPRISE:
		return serverTypeEnterprise, nil
	case pomerium.ServerType_SERVER_TYPE_ZERO:
		return serverTypeZero, nil
	default:
		return serverTypeLegacy, nil
	}
}
