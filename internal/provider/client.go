package provider

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"sync"

	"connectrpc.com/connect"

	client "github.com/pomerium/enterprise-client-go"
	"github.com/pomerium/enterprise-client-go/pb"
	sdk "github.com/pomerium/sdk-go"
	"github.com/pomerium/sdk-go/proto/pomerium"
)

// A Client is a Pomerium API client that supports the open source version of
// Pomerium, the Enterprise Console and Pomerium Zero.
type Client struct {
	apiURL    string
	apiToken  string
	tlsConfig *tls.Config

	shared pomerium.ConfigServiceClient

	mu         sync.RWMutex
	enterprise *client.Client
}

// NewClient creates a new Client.
func NewClient(apiURL, apiToken string, tlsConfig *tls.Config) *Client {
	httpTransport, ok := http.DefaultTransport.(*http.Transport)
	if ok {
		httpTransport = httpTransport.Clone()
	} else {
		httpTransport = &http.Transport{}
	}
	httpTransport.TLSClientConfig = tlsConfig

	httpClient := &http.Client{
		Transport: http.DefaultTransport,
	}

	return &Client{
		apiURL:    apiURL,
		apiToken:  apiToken,
		tlsConfig: tlsConfig,

		shared: sdk.NewClient(
			sdk.WithAPIToken(apiToken),
			sdk.WithHTTPClient(httpClient),
			sdk.WithURL(apiURL),
		),
	}
}

func (c *Client) ListServiceAccounts(
	ctx context.Context,
	req *pb.ListPomeriumServiceAccountsRequest,
) (*pb.ListPomeriumServiceAccountsResponse, error) {
	var res *pb.ListPomeriumServiceAccountsResponse
	err := c.byProduct(ctx,
		func() error { return fmt.Errorf("service accounts are not supported by core") },
		func(enterpriseClient *client.Client) error {
			var err error
			res, err = enterpriseClient.PomeriumServiceAccountService.ListPomeriumServiceAccounts(ctx, req)
			return err
		},
		func() error { return fmt.Errorf("service accounts are not supported by zero") })
	return res, err
}

func (c *Client) getEnterpriseClient() (*client.Client, error) {
	c.mu.RLock()
	enterpriseClient := c.enterprise
	c.mu.RUnlock()

	if enterpriseClient != nil {
		return enterpriseClient, nil
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	if c.enterprise != nil {
		return c.enterprise, nil
	}

	apiURL, err := url.Parse(c.apiURL)
	if err != nil {
		return nil, fmt.Errorf("error parsing api url: %w", err)
	}
	host, port := apiURL.Hostname(), apiURL.Port()
	if host == "" {
		return nil, fmt.Errorf("api url is missing hostname: %s", c.apiURL)
	}
	if port == "" {
		port = "443"
	}

	c.enterprise, err = client.NewClient(context.Background(),
		net.JoinHostPort(host, port),
		c.apiToken,
		client.WithTlsConfig(c.tlsConfig))
	if err != nil {
		return nil, fmt.Errorf("error creating enterprise client: %w", err)
	}

	return c.enterprise, nil
}

func (c *Client) byProduct(ctx context.Context,
	onCore func() error,
	onEnterprise func(enterpriseClient *client.Client) error,
	onZero func() error,
) error {
	res, err := c.shared.GetServerInfo(ctx, connect.NewRequest(&pomerium.GetServerInfoRequest{}))
	if err != nil {
		return fmt.Errorf("error retrieving server info: %w", err)
	}

	switch res.Msg.GetServerType() {
	case pomerium.ServerType_SERVER_TYPE_ENTERPRISE:
		enterpriseClient, err := c.getEnterpriseClient()
		if err != nil {
			return fmt.Errorf("error creating enterprise client: %w", err)
		}
		return onEnterprise(enterpriseClient)
	case pomerium.ServerType_SERVER_TYPE_ZERO:
		return onZero()
	case pomerium.ServerType_SERVER_TYPE_CORE:
		fallthrough
	default:
		return onCore()
	}
}
