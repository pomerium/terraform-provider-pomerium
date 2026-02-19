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

	coreClientLock sync.RWMutex
	coreClient     sdk.CoreClient

	enterpriseClientLock sync.RWMutex
	enterpriseClient     *client.Client

	zeroClientLock sync.RWMutex
	zeroClient     sdk.ZeroClient
}

func NewClient(apiURL, serviceAccountToken, sharedSecretB64 string, tlsConfig *tls.Config) *Client {
	httpTransport := http.DefaultTransport.(*http.Transport).Clone()
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
	}
}

// ByServerType invokes a handler based on the server type.
func (c *Client) ByServerType(
	ctx context.Context,
	onCore func(client sdk.CoreClient),
	onEnterprise func(client *client.Client),
	onZero func(client sdk.ZeroClient),
) diag.Diagnostics {
	var diagnostics diag.Diagnostics

	serverType, err := c.getServerType(ctx)
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

func (c *Client) getCoreClient() (sdk.CoreClient, error) {
	c.coreClientLock.RLock()
	if c.coreClient != nil {
		c.coreClientLock.RUnlock()
		return c.coreClient, nil
	}
	c.coreClientLock.RUnlock()

	c.coreClientLock.Lock()
	defer c.coreClientLock.Unlock()
	if c.coreClient != nil {
		return c.coreClient, nil
	}

	httpTransport := http.DefaultTransport.(*http.Transport).Clone()
	httpTransport.TLSClientConfig = c.tlsConfig
	httpClient := &http.Client{
		Transport: httpTransport,
	}
	var err error
	c.coreClient, err = sdk.NewCoreClient(
		sdk.WithAPIToken(cmp.Or(c.serviceAccountToken, c.sharedSecretB64)),
		sdk.WithHTTPClient(httpClient),
		sdk.WithURL(c.apiURL),
	)
	return c.coreClient, err
}

func (c *Client) getEnterpriseClient() (*client.Client, error) {
	c.enterpriseClientLock.RLock()
	if c.enterpriseClient != nil {
		c.enterpriseClientLock.RUnlock()
		return c.enterpriseClient, nil
	}
	c.enterpriseClientLock.RUnlock()

	c.enterpriseClientLock.Lock()
	defer c.enterpriseClientLock.Unlock()
	if c.enterpriseClient != nil {
		return c.enterpriseClient, nil
	}

	u, err := url.Parse(c.apiURL)
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

	token := c.serviceAccountToken
	if c.sharedSecretB64 != "" {
		token, err = GenerateBootstrapServiceAccountToken(c.sharedSecretB64)
		if err != nil {
			return nil, fmt.Errorf("error generating bootstrap service account for enterprise console api: %w", err)
		}
	}

	c.enterpriseClient, err = client.NewClient(context.Background(), net.JoinHostPort(host, port), token, client.WithTlsConfig(c.tlsConfig))
	return c.enterpriseClient, err
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

func (c *Client) getZeroClient() (sdk.ZeroClient, error) {
	c.zeroClientLock.RLock()
	if c.zeroClient != nil {
		c.zeroClientLock.RUnlock()
		return c.zeroClient, nil
	}
	c.zeroClientLock.RUnlock()

	c.zeroClientLock.Lock()
	defer c.zeroClientLock.Unlock()
	if c.zeroClient != nil {
		return c.zeroClient, nil
	}

	httpTransport := http.DefaultTransport.(*http.Transport).Clone()
	httpTransport.TLSClientConfig = c.tlsConfig
	httpClient := &http.Client{
		Transport: httpTransport,
	}
	var err error
	c.zeroClient, err = sdk.NewZeroClient(
		sdk.WithAPIToken(cmp.Or(c.serviceAccountToken, c.sharedSecretB64)),
		sdk.WithHTTPClient(httpClient),
		sdk.WithURL(c.apiURL),
	)
	return c.zeroClient, err
}
