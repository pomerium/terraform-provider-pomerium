package provider

import (
	"cmp"
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"

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
	apiURL              string
	serviceAccountToken string
	sharedSecretB64     string
	tlsConfig           *tls.Config
	consolidated        sdk.Client

	getCoreClient       func() (sdk.CoreClient, error)
	getEnterpriseClient func() (*client.Client, error)
	getServerType       func() (serverType, error)
	getZeroClient       func() (sdk.ZeroClient, error)
}

func NewClient(apiURL, serviceAccountToken, sharedSecretB64 string, tlsConfig *tls.Config) *Client {
	httpTransport := http.DefaultTransport.(*http.Transport).Clone()
	httpTransport.ForceAttemptHTTP2 = true
	httpTransport.TLSClientConfig = tlsConfig
	httpClient := &http.Client{
		Transport: httpTransport,
	}

	consolidatedClient := sdk.NewClient(
		sdk.WithAPIToken(cmp.Or(serviceAccountToken, sharedSecretB64)),
		sdk.WithHTTPClient(httpClient),
		sdk.WithURL(apiURL),
	)

	return &Client{
		apiURL:              apiURL,
		serviceAccountToken: serviceAccountToken,
		sharedSecretB64:     sharedSecretB64,
		tlsConfig:           tlsConfig,
		consolidated:        consolidatedClient,

		getCoreClient: sync.OnceValues(func() (sdk.CoreClient, error) {
			return sdk.NewCoreClient(
				sdk.WithAPIToken(cmp.Or(serviceAccountToken, sharedSecretB64)),
				sdk.WithHTTPClient(httpClient),
				sdk.WithURL(apiURL),
			)
		}),
		getEnterpriseClient: sync.OnceValues(func() (*client.Client, error) {
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

			token := serviceAccountToken
			if sharedSecretB64 != "" {
				token, err = GenerateBootstrapServiceAccountToken(sharedSecretB64)
				if err != nil {
					return nil, fmt.Errorf("error generating bootstrap service account for enterprise console api: %w", err)
				}
			}

			return client.NewClient(context.Background(), net.JoinHostPort(host, port), token, client.WithTlsConfig(tlsConfig))
		}),
		getServerType: sync.OnceValues(func() (serverType, error) {
			ctx := context.Background()

			res, err := consolidatedClient.GetServerInfo(ctx, connect.NewRequest(&pomerium.GetServerInfoRequest{}))
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
		}),
		getZeroClient: sync.OnceValues(func() (sdk.ZeroClient, error) {
			return sdk.NewZeroClient(
				sdk.WithAPIToken(cmp.Or(serviceAccountToken, sharedSecretB64)),
				sdk.WithHTTPClient(httpClient),
				sdk.WithURL(apiURL),
			)
		}),
	}
}

// ByServerType invokes a handler based on the server type.
func (c *Client) ByServerType(
	onCore func(client sdk.CoreClient),
	onEnterprise func(client *client.Client),
	onZero func(client sdk.ZeroClient),
) diag.Diagnostics {
	var diagnostics diag.Diagnostics

	serverType, err := c.getServerType()
	if err != nil {
		diagnostics.Append(diag.NewErrorDiagnostic("error determining server type", err.Error()))
		return diagnostics
	}

	switch serverType {
	case serverTypeCore:
		coreClient, err := c.getCoreClient()
		if err == nil {
			onCore(coreClient)
		} else {
			diagnostics.Append(diag.NewErrorDiagnostic("error creating core client", err.Error()))
		}
	case serverTypeEnterprise, serverTypeLegacy:
		enterpriseClient, err := c.getEnterpriseClient()
		if err == nil {
			onEnterprise(enterpriseClient)
		} else {
			diagnostics.Append(diag.NewErrorDiagnostic("error creating enterprise client", err.Error()))
		}
	case serverTypeZero:
		zeroClient, err := c.getZeroClient()
		if err == nil {
			onZero(zeroClient)
		} else {
			diagnostics.Append(diag.NewErrorDiagnostic("error creating zero client", err.Error()))
		}
	default:
		diagnostics.Append(diag.NewErrorDiagnostic("unsupported server type",
			fmt.Sprintf("unsupported server type: %s", serverType)))
	}

	return diagnostics
}

// ConsolidatedOrLegacy invokes onConsolidated if the server is of type core,
// zero, or enterprise. If its a legacy enterprise server, onLegacy is invoked.
func (c *Client) ConsolidatedOrLegacy(
	onConsolidated func(client sdk.Client),
	onLegacy func(client *client.Client),
) diag.Diagnostics {
	var diagnostics diag.Diagnostics

	serverType, err := c.getServerType()
	if err != nil {
		diagnostics.Append(diag.NewErrorDiagnostic("error determining server type", err.Error()))
		return diagnostics
	}

	switch serverType {
	case serverTypeCore, serverTypeEnterprise, serverTypeZero:
		onConsolidated(c.consolidated)
	case serverTypeLegacy:
		enterpriseClient, err := c.getEnterpriseClient()
		if err == nil {
			onLegacy(enterpriseClient)
		} else {
			diagnostics.Append(diag.NewErrorDiagnostic("error creating enterprise client", err.Error()))
		}
	default:
		diagnostics.Append(diag.NewErrorDiagnostic("unsupported server type",
			fmt.Sprintf("unsupported server type: %s", serverType)))
	}

	return diagnostics
}
