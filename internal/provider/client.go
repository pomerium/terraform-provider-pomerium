package provider

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"sync"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/emptypb"

	"github.com/google/uuid"

	client "github.com/pomerium/enterprise-client-go"
	"github.com/pomerium/enterprise-client-go/pb"
	sdk "github.com/pomerium/sdk-go"
	"github.com/pomerium/sdk-go/proto/pomerium"
)

// A Client is a Pomerium API client that supports the open source version of
// Pomerium, the Enterprise Console and Pomerium Zero.
type Client struct {
	apiURL     string
	apiToken   string
	tlsConfig  *tls.Config
	httpClient *http.Client

	shared pomerium.ConfigServiceClient

	mu         sync.RWMutex
	enterprise *client.Client
	zero       sdk.ZeroClient
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
		apiURL:     apiURL,
		apiToken:   apiToken,
		tlsConfig:  tlsConfig,
		httpClient: httpClient,

		shared: sdk.NewClient(
			sdk.WithAPIToken(apiToken),
			sdk.WithHTTPClient(httpClient),
			sdk.WithURL(apiURL),
		),
	}
}

func (c *Client) AddCluster(
	ctx context.Context,
	req *pb.AddClusterRequest,
) (*pb.AddClusterResponse, error) {
	var res *pb.AddClusterResponse
	err := c.byProduct(ctx,
		func() error { return fmt.Errorf("clusters are not supported by core") },
		func(enterpriseClient *client.Client) error {
			var err error
			res, err = enterpriseClient.ClustersService.AddCluster(ctx, req)
			return err
		},
		func(_ sdk.ZeroClient) error { return fmt.Errorf("clusters are not supported by zero") })
	return res, err
}

func (c *Client) DeleteCluster(
	ctx context.Context,
	req *pb.DeleteClusterRequest,
) (*pb.DeleteClusterResponse, error) {
	var res *pb.DeleteClusterResponse
	err := c.byProduct(ctx,
		func() error { return fmt.Errorf("clusters are not supported by core") },
		func(enterpriseClient *client.Client) error {
			var err error
			res, err = enterpriseClient.ClustersService.DeleteCluster(ctx, req)
			return err
		},
		func(_ sdk.ZeroClient) error { return fmt.Errorf("clusters are not supported by zero") })
	return res, err
}

func (c *Client) DeleteExternalDataSource(
	ctx context.Context,
	req *pb.DeleteExternalDataSourceRequest,
) (*emptypb.Empty, error) {
	var res *emptypb.Empty
	err := c.byProduct(ctx,
		func() error { return fmt.Errorf("external data sources are not supported by core") },
		func(enterpriseClient *client.Client) error {
			var err error
			res, err = enterpriseClient.ExternalDataSourceService.DeleteExternalDataSource(ctx, req)
			return err
		},
		func(_ sdk.ZeroClient) error { return fmt.Errorf("external data sources are not supported by zero") })
	return res, err
}

func (c *Client) DeleteNamespace(
	ctx context.Context,
	req *pb.DeleteNamespaceRequest,
) (*pb.DeleteNamespaceResponse, error) {
	var res *pb.DeleteNamespaceResponse
	err := c.byProduct(ctx,
		func() error { return fmt.Errorf("namespace are not supported by core") },
		func(enterpriseClient *client.Client) error {
			var err error
			res, err = enterpriseClient.NamespaceService.DeleteNamespace(ctx, req)
			return err
		},
		func(_ sdk.ZeroClient) error { return fmt.Errorf("namespace are not supported by zero") })
	return res, err
}

func (c *Client) DeleteNamespacePermission(
	ctx context.Context,
	req *pb.DeleteNamespacePermissionRequest,
) (*pb.DeleteNamespacePermissionResponse, error) {
	var res *pb.DeleteNamespacePermissionResponse
	err := c.byProduct(ctx,
		func() error { return fmt.Errorf("namespace permissions are not supported by core") },
		func(enterpriseClient *client.Client) error {
			var err error
			res, err = enterpriseClient.NamespacePermissionService.DeleteNamespacePermission(ctx, req)
			return err
		},
		func(_ sdk.ZeroClient) error { return fmt.Errorf("namespace permissions are not supported by zero") })
	return res, err
}

func (c *Client) GetCluster(
	ctx context.Context,
	req *pb.GetClusterRequest,
) (*pb.GetClusterResponse, error) {
	var res *pb.GetClusterResponse
	err := c.byProduct(ctx,
		func() error { return fmt.Errorf("clusters are not supported by core") },
		func(enterpriseClient *client.Client) error {
			var err error
			res, err = enterpriseClient.ClustersService.GetCluster(ctx, req)
			return err
		},
		func(_ sdk.ZeroClient) error { return fmt.Errorf("clusters are not supported by zero") })
	return res, err
}

func (c *Client) GetExternalDataSource(
	ctx context.Context,
	req *pb.GetExternalDataSourceRequest,
) (*pb.GetExternalDataSourceResponse, error) {
	var res *pb.GetExternalDataSourceResponse
	err := c.byProduct(ctx,
		func() error { return fmt.Errorf("external data sources are not supported by core") },
		func(enterpriseClient *client.Client) error {
			var err error
			res, err = enterpriseClient.ExternalDataSourceService.GetExternalDataSource(ctx, req)
			return err
		},
		func(_ sdk.ZeroClient) error { return fmt.Errorf("external data sources are not supported by zero") })
	return res, err
}

func (c *Client) GetNamespace(
	ctx context.Context,
	req *pb.GetNamespaceRequest,
) (*pb.GetNamespaceResponse, error) {
	var res *pb.GetNamespaceResponse
	err := c.byProduct(ctx,
		func() error { return fmt.Errorf("namespaces are not supported by core") },
		func(enterpriseClient *client.Client) error {
			var err error
			res, err = enterpriseClient.NamespaceService.GetNamespace(ctx, req)
			return err
		},
		func(_ sdk.ZeroClient) error { return fmt.Errorf("namespaces are not supported by zero") })
	return res, err
}

func (c *Client) GetNamespacePermission(
	ctx context.Context,
	req *pb.GetNamespacePermissionRequest,
) (*pb.GetNamespacePermissionResponse, error) {
	var res *pb.GetNamespacePermissionResponse
	err := c.byProduct(ctx,
		func() error { return fmt.Errorf("namespace permissions are not supported by core") },
		func(enterpriseClient *client.Client) error {
			var err error
			res, err = enterpriseClient.NamespacePermissionService.GetNamespacePermission(ctx, req)
			return err
		},
		func(_ sdk.ZeroClient) error { return fmt.Errorf("namespace permissions are not supported by zero") })
	return res, err
}

func (c *Client) ListClusters(
	ctx context.Context,
	req *pb.ListClustersRequest,
) (*pb.ListClustersResponse, error) {
	var res *pb.ListClustersResponse
	err := c.byProduct(ctx,
		func() error { return fmt.Errorf("clusters are not supported by core") },
		func(enterpriseClient *client.Client) error {
			var err error
			res, err = enterpriseClient.ClustersService.ListClusters(ctx, req)
			return err
		},
		func(_ sdk.ZeroClient) error { return fmt.Errorf("clusters are not supported by zero") })
	return res, err
}

func (c *Client) ListNamespaces(
	ctx context.Context,
	req *pb.ListNamespacesRequest,
) (*pb.ListNamespacesResponse, error) {
	var res *pb.ListNamespacesResponse
	err := c.byProduct(ctx,
		func() error { return fmt.Errorf("namespaces are not supported by core") },
		func(enterpriseClient *client.Client) error {
			var err error
			res, err = enterpriseClient.NamespaceService.ListNamespaces(ctx, req)
			return err
		},
		func(_ sdk.ZeroClient) error { return fmt.Errorf("namespaces are not supported by zero") })
	return res, err
}

func (c *Client) SetExternalDataSource(
	ctx context.Context,
	req *pb.SetExternalDataSourceRequest,
) (*pb.SetExternalDataSourceResponse, error) {
	var res *pb.SetExternalDataSourceResponse
	err := c.byProduct(ctx,
		func() error { return fmt.Errorf("external data sources are not supported by core") },
		func(enterpriseClient *client.Client) error {
			var err error
			res, err = enterpriseClient.ExternalDataSourceService.SetExternalDataSource(ctx, req)
			return err
		},
		func(_ sdk.ZeroClient) error { return fmt.Errorf("external data sources are not supported by zero") })
	return res, err
}

func (c *Client) SetNamespace(
	ctx context.Context,
	req *pb.SetNamespaceRequest,
) (*pb.SetNamespaceResponse, error) {
	var res *pb.SetNamespaceResponse
	err := c.byProduct(ctx,
		func() error {
			namespace := proto.CloneOf(req.Namespace)
			if namespace.Id == "" {
				namespace.Id = uuid.NewString()
			}
			res = &pb.SetNamespaceResponse{
				Namespace: namespace,
			}
			return nil
		},
		func(enterpriseClient *client.Client) error {
			var err error
			res, err = enterpriseClient.NamespaceService.SetNamespace(ctx, req)
			return err
		},
		func(_ sdk.ZeroClient) error { return fmt.Errorf("namespaces are not supported by zero") })
	return res, err
}

func (c *Client) SetNamespacePermission(
	ctx context.Context,
	req *pb.SetNamespacePermissionRequest,
) (*pb.SetNamespacePermissionResponse, error) {
	var res *pb.SetNamespacePermissionResponse
	err := c.byProduct(ctx,
		func() error { return fmt.Errorf("namespace permissions are not supported by core") },
		func(enterpriseClient *client.Client) error {
			var err error
			res, err = enterpriseClient.NamespacePermissionService.SetNamespacePermission(ctx, req)
			return err
		},
		func(_ sdk.ZeroClient) error { return fmt.Errorf("namespace permissions are not supported by zero") })
	return res, err
}

func (c *Client) UpdateCluster(
	ctx context.Context,
	req *pb.UpdateClusterRequest,
) (*pb.UpdateClusterResponse, error) {
	var res *pb.UpdateClusterResponse
	err := c.byProduct(ctx,
		func() error { return fmt.Errorf("clusters are not supported by core") },
		func(enterpriseClient *client.Client) error {
			var err error
			res, err = enterpriseClient.ClustersService.UpdateCluster(ctx, req)
			return err
		},
		func(_ sdk.ZeroClient) error { return fmt.Errorf("clusters are not supported by zero") })
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

	token := c.apiToken
	if key, err := base64.StdEncoding.DecodeString(token); err == nil && len(key) == 32 {
		token, err = GenerateBootstrapServiceAccountToken(token)
		if err != nil {
			return nil, fmt.Errorf("error generating bootstrap service account: %w", err)
		}
	}

	c.enterprise, err = client.NewClient(context.Background(),
		net.JoinHostPort(host, port),
		token,
		client.WithTlsConfig(c.tlsConfig))
	if err != nil {
		return nil, fmt.Errorf("error creating enterprise client: %w", err)
	}

	return c.enterprise, nil
}

func (c *Client) getZeroClient() (sdk.ZeroClient, error) {
	c.mu.RLock()
	zeroClient := c.zero
	c.mu.RUnlock()

	if zeroClient != nil {
		return zeroClient, nil
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	if c.zero != nil {
		return c.zero, nil
	}

	var err error
	c.zero, err = sdk.NewZeroClient(
		sdk.WithAPIToken(c.apiToken),
		sdk.WithHTTPClient(c.httpClient),
		sdk.WithURL(c.apiURL),
	)
	if err != nil {
		return nil, fmt.Errorf("error creating zero client: %w", err)
	}

	return c.zero, nil
}

func (c *Client) byProduct(ctx context.Context,
	onCore func() error,
	onEnterprise func(enterpriseClient *client.Client) error,
	onZero func(zeroClient sdk.ZeroClient) error,
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
		zeroClient, err := c.getZeroClient()
		if err != nil {
			return fmt.Errorf("error creating zero client: %w", err)
		}
		return onZero(zeroClient)
	case pomerium.ServerType_SERVER_TYPE_CORE:
		fallthrough
	default:
		return onCore()
	}
}
