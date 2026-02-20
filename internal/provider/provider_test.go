package provider_test

import (
	"context"
	"encoding/base64"
	"fmt"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/hashicorp/terraform-plugin-framework/providerserver"
	"github.com/hashicorp/terraform-plugin-go/tfprotov6"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"

	"github.com/pomerium/enterprise-terraform-provider/internal/provider"
	"github.com/pomerium/pomerium/pkg/cryptutil"
	"github.com/pomerium/sdk-go"
	"github.com/pomerium/sdk-go/proto/pomerium"
)

var testAccProtoV6ProviderFactories = map[string]func() (tfprotov6.ProviderServer, error){
	"pomerium": providerserver.NewProtocol6WithError(provider.New("test")()),
}

// startTestPomeriumCore starts a pomerium core instance for testing.
func startTestPomeriumCore(t *testing.T) (apiURL string, sharedSecret []byte) {
	sharedSecret = cryptutil.NewKey()

	container, err := testcontainers.Run(context.Background(), "pomerium/pomerium:main",
		// logging
		// testcontainers.WithLogger(log.TestLogger(t)),
		// testcontainers.WithLogConsumers(testLogConsumer{t}),
		// always pull to make sure we test against main
		testcontainers.WithAlwaysPull(),
		// setup the pomerium env
		testcontainers.WithEnv(map[string]string{
			"GRPC_ADDRESS":  "0.0.0.0:5443",
			"SHARED_SECRET": base64.StdEncoding.EncodeToString(sharedSecret),
		}),
	)
	testcontainers.CleanupContainer(t, container)
	require.NoError(t, err)

	host, err := container.ContainerIP(t.Context())
	require.NoError(t, err)

	apiURL = fmt.Sprintf("http://%s:5443", host)

	pollInterval := time.NewTicker(100 * time.Millisecond)
	defer pollInterval.Stop()
	for {
		_, err = sdk.NewClient(
			sdk.WithAPIToken(base64.StdEncoding.EncodeToString(sharedSecret)),
			sdk.WithURL(apiURL),
		).GetServerInfo(t.Context(), connect.NewRequest(&pomerium.GetServerInfoRequest{}))
		if err == nil {
			break
		}

		select {
		case <-t.Context().Done():
			t.Fail()
		case <-pollInterval.C:
		}
	}

	return apiURL, sharedSecret
}

type testLogConsumer struct {
	testing.TB
}

// Accept prints the log to stdout
func (lc testLogConsumer) Accept(l testcontainers.Log) {
	lc.Log(strings.TrimSpace(string(l.Content)))
}
