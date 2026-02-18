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

func TestAPIToModel(t *testing.T) {
	t.Parallel()
	t.Run("KeyPair", func(t *testing.T) {
		t.Parallel()

		t.Run("empty", func(t *testing.T) {
			t.Parallel()

			var diagnostics diag.Diagnostics
			result := provider.NewAPIToModelConverter(&diagnostics).KeyPair(&pomerium.KeyPair{})
			assert.Equal(t, provider.KeyPairModel{
				Certificate: types.StringNull(),
				ID:          types.StringNull(),
				Key:         types.StringNull(),
				Name:        types.StringNull(),
				NamespaceID: types.StringNull(),
			}, result)
			assert.Empty(t, diagnostics)
		})
		t.Run("properties", func(t *testing.T) {
			t.Parallel()

			var diagnostics diag.Diagnostics
			result := provider.NewAPIToModelConverter(&diagnostics).KeyPair(&pomerium.KeyPair{
				Certificate: []byte("CERTIFICATE"),
				Id:          new("ID"),
				Key:         []byte("KEY"),
				Name:        new("NAME"),
				NamespaceId: new("NAMESPACE_ID"),
			})
			assert.Equal(t, provider.KeyPairModel{
				Certificate: types.StringValue("CERTIFICATE"),
				ID:          types.StringValue("ID"),
				Key:         types.StringValue("KEY"),
				Name:        types.StringValue("NAME"),
				NamespaceID: types.StringValue("NAMESPACE_ID"),
			}, result)
			assert.Empty(t, diagnostics)
		})
	})
	t.Run("Policy", func(t *testing.T) {
		t.Parallel()

		t.Run("empty", func(t *testing.T) {
			var diagnostics diag.Diagnostics
			result := provider.NewAPIToModelConverter(&diagnostics).Policy(&pomerium.Policy{})
			assert.Equal(t, provider.PolicyModel{
				Description: types.StringValue(""),
				Enforced:    types.BoolValue(false),
				Explanation: types.StringValue(""),
				ID:          types.StringNull(),
				Name:        types.StringNull(),
				NamespaceID: types.StringNull(),
				PPL:         provider.PolicyLanguage{},
				Rego:        types.ListNull(types.StringType),
				Remediation: types.StringValue(""),
			}, result)
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
			result := provider.NewAPIToModelConverter(&diagnostics).Route(&pomerium.Route{})
			assert.Equal(t, provider.RouteModel{
				AllowSPDY:                types.BoolValue(false),
				AllowWebsockets:          types.BoolValue(false),
				BearerTokenFormat:        types.StringNull(),
				CircuitBreakerThresholds: types.ObjectNull(provider.CircuitBreakerThresholdsObjectType().AttrTypes),
				DependsOnHosts:           types.SetNull(types.StringType),
				Description:              types.StringNull(),
				EnableGoogleCloudServerlessAuthentication: types.BoolNull(),
				From:                              types.StringValue(""),
				HealthChecks:                      types.SetNull(provider.HealthCheckObjectType()),
				HealthyPanicThreshold:             types.Int32Null(),
				HostPathRegexRewritePattern:       types.StringNull(),
				HostPathRegexRewriteSubstitution:  types.StringNull(),
				HostRewrite:                       types.StringNull(),
				HostRewriteHeader:                 types.StringNull(),
				ID:                                types.StringNull(),
				IdleTimeout:                       timetypes.NewGoDurationNull(),
				IDPAccessTokenAllowedAudiences:    types.SetNull(types.StringType),
				IDPClientID:                       types.StringNull(),
				IDPClientSecret:                   types.StringNull(),
				JWTGroupsFilter:                   types.ObjectNull(provider.JWTGroupsFilterObjectType().AttrTypes),
				JWTIssuerFormat:                   types.StringNull(),
				KubernetesServiceAccountToken:     types.StringValue(""),
				KubernetesServiceAccountTokenFile: types.StringValue(""),
				LoadBalancingPolicy:               types.StringNull(),
				LogoURL:                           types.StringNull(),
				Name:                              types.StringNull(),
				NamespaceID:                       types.StringNull(),
				PassIdentityHeaders:               types.BoolNull(),
				Path:                              types.StringValue(""),
				Policies:                          types.SetNull(types.StringType),
				Prefix:                            types.StringValue(""),
				PrefixRewrite:                     types.StringValue(""),
				PreserveHostHeader:                types.BoolValue(false),
				Regex:                             types.StringValue(""),
				RegexPriorityOrder:                types.Int64Null(),
				RegexRewritePattern:               types.StringValue(""),
				RegexRewriteSubstitution:          types.StringValue(""),
				RemoveRequestHeaders:              types.SetNull(types.StringType),
				RewriteResponseHeaders:            types.SetNull(provider.RewriteHeaderObjectType()),
				SetRequestHeaders:                 types.MapNull(types.StringType),
				SetResponseHeaders:                types.MapNull(types.StringType),
				ShowErrorDetails:                  types.BoolValue(false),
				StatName:                          types.StringNull(),
				Timeout:                           timetypes.NewGoDurationNull(),
				TLSClientKeyPairID:                types.StringNull(),
				TLSCustomCAKeyPairID:              types.StringNull(),
				TLSDownstreamServerName:           types.StringValue(""),
				TLSSkipVerify:                     types.BoolValue(false),
				TLSUpstreamAllowRenegotiation:     types.BoolValue(false),
				TLSUpstreamServerName:             types.StringValue(""),
				To:                                types.SetNull(types.StringType),
			}, result)
			assert.Empty(t, diagnostics)
		})
		t.Run("properties", func(t *testing.T) {
			t.Parallel()

			var diagnostics diag.Diagnostics
			result := provider.NewAPIToModelConverter(&diagnostics).Route(&pomerium.Route{
				AllowSpdy:       true,
				AllowWebsockets: true,
				DependsOn:       []string{"host1.example.com", "host2.example.com"},
				Description:     new("DESCRIPTION"),
				From:            "https://from.example.com",
				HostRewrite:     new("HOST_REWRITE"),
				Id:              new("ID"),
				IdleTimeout:     durationpb.New(30 * time.Second),
				IdpClientId:     new("IDP_CLIENT_ID"),
				Name:            new("NAME"),
				NamespaceId:     new("NAMESPACE_ID"),
				Path:            "/path",
				PolicyIds:       []string{"POLICY1", "POLICY2"},
				Prefix:          "/prefix",
				PrefixRewrite:   "/new-prefix",
				Regex:           `\.example\.com`,
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
			})
			assert.Equal(t, provider.RouteModel{
				AllowSPDY:                types.BoolValue(true),
				AllowWebsockets:          types.BoolValue(true),
				BearerTokenFormat:        types.StringNull(),
				CircuitBreakerThresholds: types.ObjectNull(provider.CircuitBreakerThresholdsObjectType().AttrTypes),
				DependsOnHosts:           types.SetValueMust(types.StringType, []attr.Value{types.StringValue("host1.example.com"), types.StringValue("host2.example.com")}),
				Description:              types.StringValue("DESCRIPTION"),
				EnableGoogleCloudServerlessAuthentication: types.BoolNull(),
				From:                              types.StringValue("https://from.example.com"),
				HealthChecks:                      types.SetNull(provider.HealthCheckObjectType()),
				HealthyPanicThreshold:             types.Int32Null(),
				HostPathRegexRewritePattern:       types.StringNull(),
				HostPathRegexRewriteSubstitution:  types.StringNull(),
				HostRewrite:                       types.StringValue("HOST_REWRITE"),
				HostRewriteHeader:                 types.StringNull(),
				ID:                                types.StringValue("ID"),
				IdleTimeout:                       timetypes.NewGoDurationValue(30 * time.Second),
				IDPAccessTokenAllowedAudiences:    types.SetNull(types.StringType),
				IDPClientID:                       types.StringValue("IDP_CLIENT_ID"),
				IDPClientSecret:                   types.StringNull(),
				JWTGroupsFilter:                   types.ObjectNull(provider.JWTGroupsFilterObjectType().AttrTypes),
				JWTIssuerFormat:                   types.StringNull(),
				KubernetesServiceAccountToken:     types.StringValue(""),
				KubernetesServiceAccountTokenFile: types.StringValue(""),
				LoadBalancingPolicy:               types.StringNull(),
				LogoURL:                           types.StringNull(),
				Name:                              types.StringValue("NAME"),
				NamespaceID:                       types.StringValue("NAMESPACE_ID"),
				PassIdentityHeaders:               types.BoolNull(),
				Path:                              types.StringValue("/path"),
				Policies:                          types.SetValueMust(types.StringType, []attr.Value{types.StringValue("POLICY1"), types.StringValue("POLICY2")}),
				Prefix:                            types.StringValue("/prefix"),
				PrefixRewrite:                     types.StringValue("/new-prefix"),
				PreserveHostHeader:                types.BoolValue(false),
				Regex:                             types.StringValue(`\.example\.com`),
				RegexPriorityOrder:                types.Int64Null(),
				RegexRewritePattern:               types.StringValue(""),
				RegexRewriteSubstitution:          types.StringValue(""),
				RemoveRequestHeaders:              types.SetNull(types.StringType),
				RewriteResponseHeaders:            types.SetNull(provider.RewriteHeaderObjectType()),
				SetRequestHeaders:                 types.MapValueMust(types.StringType, map[string]attr.Value{"X-Custom": types.StringValue("value")}),
				SetResponseHeaders:                types.MapNull(types.StringType),
				ShowErrorDetails:                  types.BoolValue(true),
				StatName:                          types.StringValue("STAT_NAME"),
				Timeout:                           timetypes.NewGoDurationValue(60 * time.Second),
				TLSClientKeyPairID:                types.StringValue("TLS_KEY_PAIR_ID"),
				TLSCustomCAKeyPairID:              types.StringNull(),
				TLSDownstreamServerName:           types.StringValue(""),
				TLSSkipVerify:                     types.BoolValue(true),
				TLSUpstreamAllowRenegotiation:     types.BoolValue(false),
				TLSUpstreamServerName:             types.StringValue("upstream.example.com"),
				To:                                types.SetValueMust(types.StringType, []attr.Value{types.StringValue("https://to1.example.com"), types.StringValue("https://to2.example.com")}),
			}, result)
			assert.Empty(t, diagnostics)
		})
	})
	t.Run("Settings", func(t *testing.T) {
		t.Parallel()

		t.Run("empty", func(t *testing.T) {
			t.Parallel()

			var diagnostics diag.Diagnostics
			result := provider.NewAPIToModelConverter(&diagnostics).Settings(&pomerium.Settings{})
			assert.Equal(t, provider.SettingsModel{
				AccessLogFields:               types.SetNull(types.StringType),
				Address:                       types.StringNull(),
				AuthenticateServiceURL:        types.StringNull(),
				AuthorizeLogFields:            types.SetNull(types.StringType),
				AuthorizeServiceURL:           types.StringNull(),
				Autocert:                      types.BoolNull(),
				AutocertDir:                   types.StringNull(),
				AutocertMustStaple:            types.BoolNull(),
				AutocertUseStaging:            types.BoolNull(),
				BearerTokenFormat:             types.StringNull(),
				CacheServiceURL:               types.StringNull(),
				CertificateAuthority:          types.StringNull(),
				CertificateAuthorityFile:      types.StringNull(),
				CertificateAuthorityKeyPairID: types.StringNull(),
				CircuitBreakerThresholds:      types.ObjectNull(provider.CircuitBreakerThresholdsObjectType().AttrTypes),
				ClientCA:                      types.StringNull(),
				ClientCAFile:                  types.StringNull(),
				ClientCAKeyPairID:             types.StringNull(),
				ClusterID:                     types.StringNull(),
				CodecType:                     types.StringNull(),
				CookieDomain:                  types.StringNull(),
				CookieExpire:                  timetypes.NewGoDurationNull(),
				CookieHTTPOnly:                types.BoolNull(),
				CookieName:                    types.StringNull(),
				CookieSameSite:                types.StringNull(),
				CookieSecret:                  types.StringNull(),
				CookieSecure:                  types.BoolNull(),
				DarkmodePrimaryColor:          types.StringNull(),
				DarkmodeSecondaryColor:        types.StringNull(),
				DatabrokerServiceURL:          types.StringNull(),
				DefaultUpstreamTimeout:        timetypes.NewGoDurationNull(),
				DNSFailureRefreshRate:         timetypes.NewGoDurationNull(),
				DNSLookupFamily:               types.StringNull(),
				DNSQueryTimeout:               timetypes.NewGoDurationNull(),
				DNSQueryTries:                 types.Int64Null(),
				DNSRefreshRate:                timetypes.NewGoDurationNull(),
				DNSUDPMaxQueries:              types.Int64Null(),
				DNSUseTCP:                     types.BoolNull(),
				ErrorMessageFirstParagraph:    types.StringNull(),
				FaviconURL:                    types.StringNull(),
				GoogleCloudServerlessAuthenticationServiceAccount: types.StringNull(),
				GRPCAddress:                     types.StringNull(),
				GRPCInsecure:                    types.BoolNull(),
				HTTPRedirectAddr:                types.StringNull(),
				ID:                              types.StringNull(),
				IdentityProviderAuth0:           types.ObjectNull(idpAuth0AttrTypes(t)),
				IdentityProviderAzure:           types.ObjectNull(idpAzureAttrTypes(t)),
				IdentityProviderBlob:            types.ObjectNull(idpBlobAttrTypes(t)),
				IdentityProviderCognito:         types.ObjectNull(idpCognitoAttrTypes(t)),
				IdentityProviderGitHub:          types.ObjectNull(idpGitHubAttrTypes(t)),
				IdentityProviderGitLab:          types.ObjectNull(idpGitLabAttrTypes(t)),
				IdentityProviderGoogle:          types.ObjectNull(idpGoogleAttrTypes(t)),
				IdentityProviderOkta:            types.ObjectNull(idpOktaAttrTypes(t)),
				IdentityProviderOneLogin:        types.ObjectNull(idpOneLoginAttrTypes(t)),
				IdentityProviderPing:            types.ObjectNull(idpPingAttrTypes(t)),
				IdentityProviderRefreshInterval: timetypes.NewGoDurationNull(),
				IdentityProviderRefreshTimeout:  timetypes.NewGoDurationNull(),
				IDPAccessTokenAllowedAudiences:  types.SetNull(types.StringType),
				IdpClientID:                     types.StringNull(),
				IdpClientSecret:                 types.StringNull(),
				IdpProvider:                     types.StringNull(),
				IdpProviderURL:                  types.StringNull(),
				IdpRefreshDirectoryInterval:     timetypes.NewGoDurationNull(),
				IdpRefreshDirectoryTimeout:      timetypes.NewGoDurationNull(),
				IdpServiceAccount:               types.StringNull(),
				InsecureServer:                  types.BoolNull(),
				InstallationID:                  types.StringNull(),
				JWTClaimsHeaders:                types.MapNull(types.StringType),
				JWTGroupsFilter:                 types.ObjectNull(provider.JWTGroupsFilterObjectType().AttrTypes),
				JWTIssuerFormat:                 types.StringNull(),
				LogLevel:                        types.StringNull(),
				LogoURL:                         types.StringNull(),
				MetricsAddress:                  types.StringNull(),
				OtelAttributeValueLengthLimit:   types.Int64Null(),
				OtelBspMaxExportBatchSize:       types.Int64Null(),
				OtelBspScheduleDelay:            timetypes.NewGoDurationNull(),
				OtelExporterOtlpEndpoint:        types.StringNull(),
				OtelExporterOtlpHeaders:         types.SetNull(types.StringType),
				OtelExporterOtlpProtocol:        types.StringNull(),
				OtelExporterOtlpTimeout:         timetypes.NewGoDurationNull(),
				OtelExporterOtlpTracesEndpoint:  types.StringNull(),
				OtelExporterOtlpTracesHeaders:   types.SetNull(types.StringType),
				OtelExporterOtlpTracesProtocol:  types.StringNull(),
				OtelExporterOtlpTracesTimeout:   timetypes.NewGoDurationNull(),
				OtelLogLevel:                    types.StringNull(),
				OtelResourceAttributes:          types.SetNull(types.StringType),
				OtelTracesExporter:              types.StringNull(),
				OtelTracesSamplerArg:            types.Float64Null(),
				PassIdentityHeaders:             types.BoolNull(),
				PrimaryColor:                    types.StringNull(),
				ProxyLogLevel:                   types.StringNull(),
				RequestParams:                   types.MapNull(types.StringType),
				Scopes:                          types.SetNull(types.StringType),
				SecondaryColor:                  types.StringNull(),
				SetResponseHeaders:              types.MapNull(types.StringType),
				SkipXFFAppend:                   types.BoolNull(),
				SSHAddress:                      types.StringNull(),
				SSHHostKeyFiles:                 types.SetNull(types.StringType),
				SSHHostKeys:                     types.SetNull(types.StringType),
				SSHUserCAKey:                    types.StringNull(),
				SSHUserCAKeyFile:                types.StringNull(),
				TimeoutIdle:                     timetypes.NewGoDurationNull(),
				TimeoutRead:                     timetypes.NewGoDurationNull(),
				TimeoutWrite:                    timetypes.NewGoDurationNull(),
			}, result)
			assert.Empty(t, diagnostics)
		})
		t.Run("properties", func(t *testing.T) {
			t.Parallel()

			var diagnostics diag.Diagnostics
			result := provider.NewAPIToModelConverter(&diagnostics).Settings(&pomerium.Settings{
				Address:                    new(":443"),
				AuthenticateServiceUrl:     new("https://authenticate.example.com"),
				AuthorizeServiceUrls:       []string{"https://authorize.example.com"},
				Autocert:                   new(true),
				CertificateAuthority:       new("CA_CERT"),
				ClusterId:                  new("CLUSTER_ID"),
				CookieDomain:               new(".example.com"),
				CookieExpire:               durationpb.New(24 * time.Hour),
				CookieHttpOnly:             new(true),
				CookieName:                 new("_pomerium"),
				CookieSameSite:             new("lax"),
				CookieSecret:               new("SECRET"),
				DefaultUpstreamTimeout:     durationpb.New(30 * time.Second),
				ErrorMessageFirstParagraph: new("ACCESS_DENIED"),
				GrpcAddress:                new(":5443"),
				GrpcInsecure:               new(false),
				HttpRedirectAddr:           new(":80"),
				Id:                         new("SETTINGS_ID"),
				IdpClientId:                new("IDP_CLIENT_ID"),
				IdpClientSecret:            new("IDP_CLIENT_SECRET"),
				IdpProvider:                new("google"),
				IdpProviderUrl:             new("https://accounts.google.com"),
				InsecureServer:             new(false),
				InstallationId:             new("INSTALLATION_ID"),
				JwtClaimsHeaders:           map[string]string{"X-Email": "email"},
				LogLevel:                   new("info"),
				LogoUrl:                    new("https://example.com/logo.png"),
				MetricsAddress:             new(":9090"),
				PassIdentityHeaders:        new(true),
				PrimaryColor:               new("#000000"),
				ProxyLogLevel:              new("debug"),
				RequestParams:              map[string]string{"param1": "value1"},
				Scopes:                     []string{"openid", "profile"},
				SecondaryColor:             new("#FFFFFF"),
				SetResponseHeaders:         map[string]string{"X-Frame-Options": "DENY"},
				SkipXffAppend:              new(false),
				SshAddress:                 new(":22"),
				SshUserCaKey:               new("SSH_CA_KEY"),
				TimeoutIdle:                durationpb.New(5 * time.Minute),
				TimeoutRead:                durationpb.New(30 * time.Second),
				TimeoutWrite:               durationpb.New(30 * time.Second),
			})
			assert.Equal(t, types.StringValue(":443"), result.Address)
			assert.Equal(t, types.StringValue("https://authenticate.example.com"), result.AuthenticateServiceURL)
			assert.Equal(t, types.StringValue("https://authorize.example.com"), result.AuthorizeServiceURL)
			assert.Equal(t, types.BoolValue(true), result.Autocert)
			assert.Equal(t, types.StringValue("CA_CERT"), result.CertificateAuthority)
			assert.Equal(t, types.StringValue("CLUSTER_ID"), result.ClusterID)
			assert.Equal(t, types.StringValue(".example.com"), result.CookieDomain)
			assert.Equal(t, timetypes.NewGoDurationValue(24*time.Hour), result.CookieExpire)
			assert.Equal(t, types.BoolValue(true), result.CookieHTTPOnly)
			assert.Equal(t, types.StringValue("_pomerium"), result.CookieName)
			assert.Equal(t, types.StringValue("lax"), result.CookieSameSite)
			assert.Equal(t, types.StringValue("SECRET"), result.CookieSecret)
			assert.Equal(t, timetypes.NewGoDurationValue(30*time.Second), result.DefaultUpstreamTimeout)
			assert.Equal(t, types.StringValue("ACCESS_DENIED"), result.ErrorMessageFirstParagraph)
			assert.Equal(t, types.StringValue(":5443"), result.GRPCAddress)
			assert.Equal(t, types.BoolValue(false), result.GRPCInsecure)
			assert.Equal(t, types.StringValue(":80"), result.HTTPRedirectAddr)
			assert.Equal(t, types.StringValue("SETTINGS_ID"), result.ID)
			assert.Equal(t, types.StringValue("IDP_CLIENT_ID"), result.IdpClientID)
			assert.Equal(t, types.StringValue("IDP_CLIENT_SECRET"), result.IdpClientSecret)
			assert.Equal(t, types.StringValue("google"), result.IdpProvider)
			assert.Equal(t, types.StringValue("https://accounts.google.com"), result.IdpProviderURL)
			assert.Equal(t, types.BoolValue(false), result.InsecureServer)
			assert.Equal(t, types.StringValue("INSTALLATION_ID"), result.InstallationID)
			assert.Equal(t, types.MapValueMust(types.StringType, map[string]attr.Value{"X-Email": types.StringValue("email")}), result.JWTClaimsHeaders)
			assert.Equal(t, types.StringValue("info"), result.LogLevel)
			assert.Equal(t, types.StringValue("https://example.com/logo.png"), result.LogoURL)
			assert.Equal(t, types.StringValue(":9090"), result.MetricsAddress)
			assert.Equal(t, types.BoolValue(true), result.PassIdentityHeaders)
			assert.Equal(t, types.StringValue("#000000"), result.PrimaryColor)
			assert.Equal(t, types.StringValue("debug"), result.ProxyLogLevel)
			assert.Equal(t, types.MapValueMust(types.StringType, map[string]attr.Value{"param1": types.StringValue("value1")}), result.RequestParams)
			assert.Equal(t, types.SetValueMust(types.StringType, []attr.Value{types.StringValue("openid"), types.StringValue("profile")}), result.Scopes)
			assert.Equal(t, types.StringValue("#FFFFFF"), result.SecondaryColor)
			assert.Equal(t, types.MapValueMust(types.StringType, map[string]attr.Value{"X-Frame-Options": types.StringValue("DENY")}), result.SetResponseHeaders)
			assert.Equal(t, types.BoolValue(false), result.SkipXFFAppend)
			assert.Equal(t, types.StringValue(":22"), result.SSHAddress)
			assert.Equal(t, types.StringValue("SSH_CA_KEY"), result.SSHUserCAKey)
			assert.Equal(t, timetypes.NewGoDurationValue(5*time.Minute), result.TimeoutIdle)
			assert.Equal(t, timetypes.NewGoDurationValue(30*time.Second), result.TimeoutRead)
			assert.Equal(t, timetypes.NewGoDurationValue(30*time.Second), result.TimeoutWrite)
			assert.Empty(t, diagnostics)
		})
	})
}

// idp*AttrTypes helpers call GetTFObjectTypes for each IDP options struct.
func idpAuth0AttrTypes(t *testing.T) map[string]attr.Type {
	t.Helper()
	m, err := provider.GetTFObjectTypes[provider.Auth0Options]()
	assert.NoError(t, err)
	return m
}

func idpAzureAttrTypes(t *testing.T) map[string]attr.Type {
	t.Helper()
	m, err := provider.GetTFObjectTypes[provider.AzureOptions]()
	assert.NoError(t, err)
	return m
}

func idpBlobAttrTypes(t *testing.T) map[string]attr.Type {
	t.Helper()
	m, err := provider.GetTFObjectTypes[provider.BlobOptions]()
	assert.NoError(t, err)
	return m
}

func idpCognitoAttrTypes(t *testing.T) map[string]attr.Type {
	t.Helper()
	m, err := provider.GetTFObjectTypes[provider.CognitoOptions]()
	assert.NoError(t, err)
	return m
}

func idpGitHubAttrTypes(t *testing.T) map[string]attr.Type {
	t.Helper()
	m, err := provider.GetTFObjectTypes[provider.GitHubOptions]()
	assert.NoError(t, err)
	return m
}

func idpGitLabAttrTypes(t *testing.T) map[string]attr.Type {
	t.Helper()
	m, err := provider.GetTFObjectTypes[provider.GitLabOptions]()
	assert.NoError(t, err)
	return m
}

func idpGoogleAttrTypes(t *testing.T) map[string]attr.Type {
	t.Helper()
	m, err := provider.GetTFObjectTypes[provider.GoogleOptions]()
	assert.NoError(t, err)
	return m
}

func idpOktaAttrTypes(t *testing.T) map[string]attr.Type {
	t.Helper()
	m, err := provider.GetTFObjectTypes[provider.OktaOptions]()
	assert.NoError(t, err)
	return m
}

func idpOneLoginAttrTypes(t *testing.T) map[string]attr.Type {
	t.Helper()
	m, err := provider.GetTFObjectTypes[provider.OneLoginOptions]()
	assert.NoError(t, err)
	return m
}

func idpPingAttrTypes(t *testing.T) map[string]attr.Type {
	t.Helper()
	m, err := provider.GetTFObjectTypes[provider.PingOptions]()
	assert.NoError(t, err)
	return m
}
