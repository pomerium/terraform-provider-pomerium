package provider_test

import (
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/hashicorp/terraform-plugin-framework-timetypes/timetypes"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/stretchr/testify/assert"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/testing/protocmp"
	"google.golang.org/protobuf/types/known/durationpb"

	"github.com/pomerium/enterprise-terraform-provider/internal/provider"
	"github.com/pomerium/sdk-go/proto/pomerium"
)

func TestModelToAPI(t *testing.T) {
	t.Parallel()
	t.Run("KeyPair", func(t *testing.T) {
		t.Parallel()

		t.Run("empty", func(t *testing.T) {
			t.Parallel()

			var diagnostics diag.Diagnostics
			result := provider.NewModelToAPIConverter(&diagnostics).KeyPair(provider.KeyPairModel{})
			assert.Empty(t, cmp.Diff(&pomerium.KeyPair{
				Origin:       pomerium.KeyPairOrigin_KEY_PAIR_ORIGIN_USER,
				OriginatorId: proto.String(provider.OriginatorID),
				Status:       pomerium.KeyPairStatus_KEY_PAIR_STATUS_READY,
			}, result, protocmp.Transform()))
			assert.Empty(t, diagnostics)
		})
		t.Run("properties", func(t *testing.T) {
			t.Parallel()

			var diagnostics diag.Diagnostics
			result := provider.NewModelToAPIConverter(&diagnostics).KeyPair(provider.KeyPairModel{
				Certificate: types.StringValue("CERTIFICATE"),
				ID:          types.StringValue("ID"),
				Key:         types.StringValue("KEY"),
				Name:        types.StringValue("NAME"),
				NamespaceID: types.StringValue("NAMESPACE_ID"),
			})
			assert.Empty(t, cmp.Diff(&pomerium.KeyPair{
				Certificate:  []byte("CERTIFICATE"),
				Id:           new("ID"),
				Key:          []byte("KEY"),
				Name:         new("NAME"),
				NamespaceId:  new("NAMESPACE_ID"),
				Origin:       pomerium.KeyPairOrigin_KEY_PAIR_ORIGIN_USER,
				OriginatorId: proto.String(provider.OriginatorID),
				Status:       pomerium.KeyPairStatus_KEY_PAIR_STATUS_READY,
			}, result, protocmp.Transform()))
			assert.Empty(t, diagnostics)
		})
	})
	t.Run("Policy", func(t *testing.T) {
		t.Parallel()

		t.Run("empty", func(t *testing.T) {
			var diagnostics diag.Diagnostics
			result := provider.NewModelToAPIConverter(&diagnostics).Policy(provider.PolicyModel{})
			assert.Empty(t, cmp.Diff(&pomerium.Policy{
				Description:  new(""),
				Enforced:     new(false),
				Explanation:  new(""),
				Name:         new(""),
				OriginatorId: proto.String(provider.OriginatorID),
				Remediation:  new(""),
				SourcePpl:    new(""),
			}, result, protocmp.Transform()))
			assert.Empty(t, diagnostics)
		})
		t.Run("properties", func(t *testing.T) {
			t.Parallel()

			ppl, _ := provider.PolicyLanguageType{}.Parse(types.StringValue(`[{
			  "allow": {
				  "and": [
					  {"accept":true}
					]
				}
			}]`))
			var diagnostics diag.Diagnostics
			result := provider.NewModelToAPIConverter(&diagnostics).Policy(provider.PolicyModel{
				Description: types.StringValue("DESCRIPTION"),
				Enforced:    types.BoolValue(true),
				Explanation: types.StringValue("EXPLANATION"),
				ID:          types.StringValue("ID"),
				Name:        types.StringValue("NAME"),
				NamespaceID: types.StringValue("NAMESPACE_ID"),
				PPL:         ppl,
				Rego: types.ListValueMust(types.StringType, []attr.Value{
					types.StringValue("REGO1"), types.StringValue("REGO2"), types.StringValue("REGO3"),
				}),
				Remediation: types.StringValue("REMEDIATION"),
			})
			assert.Empty(t, cmp.Diff(&pomerium.Policy{
				Description:  new("DESCRIPTION"),
				Enforced:     new(true),
				Explanation:  new("EXPLANATION"),
				Id:           new("ID"),
				Name:         new("NAME"),
				NamespaceId:  new("NAMESPACE_ID"),
				OriginatorId: proto.String(provider.OriginatorID),
				Rego:         []string{"REGO1", "REGO2", "REGO3"},
				Remediation:  new("REMEDIATION"),
				SourcePpl:    new(`[{"allow":{"and":[{"accept":true}]}}]`),
			}, result, protocmp.Transform()))
			assert.Empty(t, diagnostics)
		})
	})
	t.Run("Route", func(t *testing.T) {
		t.Parallel()

		t.Run("empty", func(t *testing.T) {
			t.Parallel()

			var diagnostics diag.Diagnostics
			result := provider.NewModelToAPIConverter(&diagnostics).Route(provider.RouteModel{})
			assert.Empty(t, cmp.Diff(&pomerium.Route{
				OriginatorId: proto.String(provider.OriginatorID),
			}, result, protocmp.Transform()))
			assert.Empty(t, diagnostics)
		})
		t.Run("properties", func(t *testing.T) {
			t.Parallel()

			var diagnostics diag.Diagnostics
			result := provider.NewModelToAPIConverter(&diagnostics).Route(provider.RouteModel{
				AllowSPDY:       types.BoolValue(true),
				AllowWebsockets: types.BoolValue(true),
				DependsOnHosts:  types.SetValueMust(types.StringType, []attr.Value{types.StringValue("host1.example.com"), types.StringValue("host2.example.com")}),
				Description:     types.StringValue("DESCRIPTION"),
				From:            types.StringValue("https://from.example.com"),
				HostRewrite:     types.StringValue("HOST_REWRITE"),
				ID:              types.StringValue("ID"),
				IdleTimeout:     timetypes.NewGoDurationValue(30 * time.Second),
				IDPClientID:     types.StringValue("IDP_CLIENT_ID"),
				JWTGroupsFilter: types.ObjectValueMust(
					provider.JWTGroupsFilterObjectType().AttrTypes,
					map[string]attr.Value{
						"groups":         types.SetValueMust(types.StringType, []attr.Value{types.StringValue("group1")}),
						"infer_from_ppl": types.BoolValue(true),
					},
				),
				Name:                types.StringValue("NAME"),
				NamespaceID:         types.StringValue("NAMESPACE_ID"),
				PassIdentityHeaders: types.BoolValue(true),
				Path:                types.StringValue("/path"),
				Policies:            types.SetValueMust(types.StringType, []attr.Value{types.StringValue("POLICY1"), types.StringValue("POLICY2")}),
				Prefix:              types.StringValue("/prefix"),
				PrefixRewrite:       types.StringValue("/new-prefix"),
				Regex:               types.StringValue(`\.example\.com`),
				SetRequestHeaders: types.MapValueMust(types.StringType, map[string]attr.Value{
					"X-Custom": types.StringValue("value"),
				}),
				ShowErrorDetails:      types.BoolValue(true),
				StatName:              types.StringValue("STAT_NAME"),
				Timeout:               timetypes.NewGoDurationValue(60 * time.Second),
				TLSClientKeyPairID:    types.StringValue("TLS_KEY_PAIR_ID"),
				TLSSkipVerify:         types.BoolValue(true),
				TLSUpstreamServerName: types.StringValue("upstream.example.com"),
				To:                    types.SetValueMust(types.StringType, []attr.Value{types.StringValue("https://to1.example.com"), types.StringValue("https://to2.example.com")}),
			})
			assert.Empty(t, cmp.Diff(&pomerium.Route{
				AllowSpdy:                   true,
				AllowWebsockets:             true,
				DependsOn:                   []string{"host1.example.com", "host2.example.com"},
				Description:                 new("DESCRIPTION"),
				From:                        "https://from.example.com",
				HostRewrite:                 new("HOST_REWRITE"),
				Id:                          new("ID"),
				IdleTimeout:                 durationpb.New(30 * time.Second),
				IdpClientId:                 new("IDP_CLIENT_ID"),
				JwtGroupsFilter:             []string{"group1"},
				JwtGroupsFilterInferFromPpl: new(true),
				Name:                        new("NAME"),
				NamespaceId:                 new("NAMESPACE_ID"),
				OriginatorId:                proto.String(provider.OriginatorID),
				PassIdentityHeaders:         new(true),
				Path:                        "/path",
				PolicyIds:                   []string{"POLICY1", "POLICY2"},
				Prefix:                      "/prefix",
				PrefixRewrite:               "/new-prefix",
				Regex:                       `\.example\.com`,
				SetRequestHeaders: map[string]string{
					"X-Custom": "value",
				},
				ShowErrorDetails:      true,
				StatName:              new("STAT_NAME"),
				Timeout:               durationpb.New(60 * time.Second),
				TlsClientKeyPairId:    new("TLS_KEY_PAIR_ID"),
				TlsSkipVerify:         true,
				TlsUpstreamServerName: "upstream.example.com",
				To:                    []string{"https://to1.example.com", "https://to2.example.com"},
			}, result, protocmp.Transform()))
			assert.Empty(t, diagnostics)
		})
	})
	t.Run("Settings", func(t *testing.T) {
		t.Parallel()

		t.Run("empty", func(t *testing.T) {
			t.Parallel()

			var diagnostics diag.Diagnostics
			result := provider.NewModelToAPIConverter(&diagnostics).Settings(provider.SettingsModel{})
			assert.Empty(t, cmp.Diff(&pomerium.Settings{
				OriginatorId: proto.String(provider.OriginatorID),
			}, result, protocmp.Transform()))
			assert.Empty(t, diagnostics)
		})
		t.Run("properties", func(t *testing.T) {
			t.Parallel()

			var diagnostics diag.Diagnostics
			result := provider.NewModelToAPIConverter(&diagnostics).Settings(provider.SettingsModel{
				Address:                    types.StringValue(":443"),
				AuthenticateServiceURL:     types.StringValue("https://authenticate.example.com"),
				AuthorizeServiceURL:        types.StringValue("https://authorize.example.com"),
				Autocert:                   types.BoolValue(true),
				CertificateAuthority:       types.StringValue("CA_CERT"),
				ClusterID:                  types.StringValue("CLUSTER_ID"),
				CookieDomain:               types.StringValue(".example.com"),
				CookieExpire:               timetypes.NewGoDurationValue(24 * time.Hour),
				CookieHTTPOnly:             types.BoolValue(true),
				CookieName:                 types.StringValue("_pomerium"),
				CookieSameSite:             types.StringValue("lax"),
				CookieSecret:               types.StringValue("SECRET"),
				DefaultUpstreamTimeout:     timetypes.NewGoDurationValue(30 * time.Second),
				ErrorMessageFirstParagraph: types.StringValue("ACCESS_DENIED"),
				GRPCAddress:                types.StringValue(":5443"),
				GRPCInsecure:               types.BoolValue(false),
				HTTPRedirectAddr:           types.StringValue(":80"),
				ID:                         types.StringValue("SETTINGS_ID"),
				IdpClientID:                types.StringValue("IDP_CLIENT_ID"),
				IdpClientSecret:            types.StringValue("IDP_CLIENT_SECRET"),
				IdpProvider:                types.StringValue("google"),
				IdpProviderURL:             types.StringValue("https://accounts.google.com"),
				InsecureServer:             types.BoolValue(false),
				InstallationID:             types.StringValue("INSTALLATION_ID"),
				JWTClaimsHeaders:           types.MapValueMust(types.StringType, map[string]attr.Value{"X-Email": types.StringValue("email")}),
				LogLevel:                   types.StringValue("info"),
				LogoURL:                    types.StringValue("https://example.com/logo.png"),
				MetricsAddress:             types.StringValue(":9090"),
				PassIdentityHeaders:        types.BoolValue(true),
				PrimaryColor:               types.StringValue("#000000"),
				ProxyLogLevel:              types.StringValue("debug"),
				RequestParams:              types.MapValueMust(types.StringType, map[string]attr.Value{"param1": types.StringValue("value1")}),
				Scopes:                     types.SetValueMust(types.StringType, []attr.Value{types.StringValue("openid"), types.StringValue("profile")}),
				SecondaryColor:             types.StringValue("#FFFFFF"),
				SetResponseHeaders:         types.MapValueMust(types.StringType, map[string]attr.Value{"X-Frame-Options": types.StringValue("DENY")}),
				SkipXFFAppend:              types.BoolValue(false),
				SSHAddress:                 types.StringValue(":22"),
				SSHUserCAKey:               types.StringValue("SSH_CA_KEY"),
				TimeoutIdle:                timetypes.NewGoDurationValue(5 * time.Minute),
				TimeoutRead:                timetypes.NewGoDurationValue(30 * time.Second),
				TimeoutWrite:               timetypes.NewGoDurationValue(30 * time.Second),
			})
			assert.Equal(t, new(":443"), result.Address)
			assert.Equal(t, new("https://authenticate.example.com"), result.AuthenticateServiceUrl)
			assert.Equal(t, []string{"https://authorize.example.com"}, result.AuthorizeServiceUrls)
			assert.Equal(t, new(true), result.Autocert)
			assert.Equal(t, new("CA_CERT"), result.CertificateAuthority)
			assert.Equal(t, new("CLUSTER_ID"), result.ClusterId)
			assert.Equal(t, new(".example.com"), result.CookieDomain)
			assert.Empty(t, cmp.Diff(durationpb.New(24*time.Hour), result.CookieExpire, protocmp.Transform()))
			assert.Equal(t, new(true), result.CookieHttpOnly)
			assert.Equal(t, new("_pomerium"), result.CookieName)
			assert.Equal(t, new("lax"), result.CookieSameSite)
			assert.Equal(t, new("SECRET"), result.CookieSecret)
			assert.Empty(t, cmp.Diff(durationpb.New(30*time.Second), result.DefaultUpstreamTimeout, protocmp.Transform()))
			assert.Equal(t, new("ACCESS_DENIED"), result.ErrorMessageFirstParagraph)
			assert.Equal(t, new(":5443"), result.GrpcAddress)
			assert.Equal(t, new(false), result.GrpcInsecure)
			assert.Equal(t, new(":80"), result.HttpRedirectAddr)
			assert.Equal(t, new("SETTINGS_ID"), result.Id)
			assert.Equal(t, new("IDP_CLIENT_ID"), result.IdpClientId)
			assert.Equal(t, new("IDP_CLIENT_SECRET"), result.IdpClientSecret)
			assert.Equal(t, new("google"), result.IdpProvider)
			assert.Equal(t, new("https://accounts.google.com"), result.IdpProviderUrl)
			assert.Equal(t, new(false), result.InsecureServer)
			assert.Equal(t, new("INSTALLATION_ID"), result.InstallationId)
			assert.Equal(t, map[string]string{"X-Email": "email"}, result.JwtClaimsHeaders)
			assert.Equal(t, new("info"), result.LogLevel)
			assert.Equal(t, new("https://example.com/logo.png"), result.LogoUrl)
			assert.Equal(t, new(":9090"), result.MetricsAddress)
			assert.Equal(t, proto.String(provider.OriginatorID), result.OriginatorId)
			assert.Equal(t, new(true), result.PassIdentityHeaders)
			assert.Equal(t, new("#000000"), result.PrimaryColor)
			assert.Equal(t, new("debug"), result.ProxyLogLevel)
			assert.Equal(t, map[string]string{"param1": "value1"}, result.RequestParams)
			assert.ElementsMatch(t, []string{"openid", "profile"}, result.Scopes)
			assert.Equal(t, new("#FFFFFF"), result.SecondaryColor)
			assert.Equal(t, map[string]string{"X-Frame-Options": "DENY"}, result.SetResponseHeaders)
			assert.Equal(t, new(false), result.SkipXffAppend)
			assert.Equal(t, new(":22"), result.SshAddress)
			assert.Equal(t, new("SSH_CA_KEY"), result.SshUserCaKey)
			assert.Empty(t, cmp.Diff(durationpb.New(5*time.Minute), result.TimeoutIdle, protocmp.Transform()))
			assert.Empty(t, cmp.Diff(durationpb.New(30*time.Second), result.TimeoutRead, protocmp.Transform()))
			assert.Empty(t, cmp.Diff(durationpb.New(30*time.Second), result.TimeoutWrite, protocmp.Transform()))
			assert.Empty(t, diagnostics)
		})
	})
}
