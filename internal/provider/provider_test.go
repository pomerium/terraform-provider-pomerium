package provider_test

import (
	"context"
	"encoding/base64"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/hashicorp/terraform-plugin-framework/providerserver"
	"github.com/hashicorp/terraform-plugin-go/tfprotov6"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"

	"github.com/pomerium/enterprise-terraform-provider/internal/provider"
	"github.com/pomerium/pomerium/pkg/cryptutil"
	configpb "github.com/pomerium/pomerium/pkg/grpc/config"
	"github.com/pomerium/sdk-go"
)

var testAccProtoV6ProviderFactories = map[string]func() (tfprotov6.ProviderServer, error){
	"pomerium": providerserver.NewProtocol6WithError(provider.New("test")()),
}

// startTestPomeriumCore starts a pomerium core instance for testing.
func startTestPomeriumCore(t *testing.T) (apiURL string, sharedSecret []byte) {
	const grpcPort = "5443"

	sharedSecret = cryptutil.NewKey()
	apiToken := base64.StdEncoding.EncodeToString(sharedSecret)

	container, err := testcontainers.Run(t.Context(), "pomerium/pomerium:main",
		// logging
		// testcontainers.WithLogger(log.TestLogger(t)),
		// testcontainers.WithLogConsumers(testLogConsumer{t}),
		// always pull to make sure we test against main
		testcontainers.WithAlwaysPull(),
		// publish the gRPC port on the host: the container IP is not
		// routable from the host when docker runs in a VM (e.g. macOS)
		testcontainers.WithExposedPorts(grpcPort+"/tcp"),
		// setup the pomerium env
		testcontainers.WithEnv(map[string]string{
			"GRPC_ADDRESS":  "0.0.0.0:" + grpcPort,
			"SHARED_SECRET": apiToken,
		}),
	)
	testcontainers.CleanupContainer(t, container)
	require.NoError(t, err)

	apiURL, err = container.PortEndpoint(t.Context(), grpcPort+"/tcp", "http")
	require.NoError(t, err)

	client := sdk.NewClient(sdk.WithAPIToken(apiToken), sdk.WithURL(apiURL))
	require.EventuallyWithT(t, func(c *assert.CollectT) {
		ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
		defer cancel()
		_, err := client.GetServerInfo(ctx, connect.NewRequest(&configpb.GetServerInfoRequest{}))
		assert.NoError(c, err)
	}, time.Minute, 100*time.Millisecond, "pomerium core did not become ready")

	return apiURL, sharedSecret
}

type testLogConsumer struct {
	testing.TB
}

// Accept prints the log to stdout
func (lc testLogConsumer) Accept(l testcontainers.Log) {
	lc.Log(strings.TrimSpace(string(l.Content)))
}
