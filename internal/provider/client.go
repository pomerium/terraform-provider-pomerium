package provider

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/url"

	client "github.com/pomerium/enterprise-client-go"
)

type Client struct {
	*client.Client
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

	c, err := client.NewClient(context.Background(), net.JoinHostPort(host, port), apiToken, client.WithTlsConfig(tlsConfig))
	if err != nil {
		return nil, fmt.Errorf("error creating client: %w", err)
	}

	return &Client{Client: c}, nil
}
