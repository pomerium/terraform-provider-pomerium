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

	"github.com/pomerium/enterprise-client-go/pb"
	"github.com/pomerium/enterprise-terraform-provider/internal/provider"
)

func TestModelToEnterpriseConverter(t *testing.T) {
	t.Parallel()

	t.Run("CircuitBreakerThresholds", func(t *testing.T) {
		t.Parallel()

		for _, tc := range []struct {
			src    types.Object
			expect *pb.CircuitBreakerThresholds
		}{
			{types.ObjectNull(provider.CircuitBreakerThresholdsAttributes), nil},
			{types.ObjectValueMust(provider.CircuitBreakerThresholdsAttributes, map[string]attr.Value{
				"max_connections":      types.Int64Value(1),
				"max_pending_requests": types.Int64Null(),
				"max_requests":         types.Int64Null(),
				"max_retries":          types.Int64Null(),
				"max_connection_pools": types.Int64Null(),
			}), &pb.CircuitBreakerThresholds{
				MaxConnections: proto.Uint32(1),
			}},
			{types.ObjectValueMust(provider.CircuitBreakerThresholdsAttributes, map[string]attr.Value{
				"max_connections":      types.Int64Null(),
				"max_pending_requests": types.Int64Value(2),
				"max_requests":         types.Int64Value(3),
				"max_retries":          types.Int64Value(4),
				"max_connection_pools": types.Int64Value(5),
			}), &pb.CircuitBreakerThresholds{
				MaxPendingRequests: proto.Uint32(2),
				MaxRequests:        proto.Uint32(3),
				MaxRetries:         proto.Uint32(4),
				MaxConnectionPools: proto.Uint32(5),
			}},
		} {
			var diagnostics diag.Diagnostics
			actual := provider.NewModelToEnterpriseConverter(&diagnostics).CircuitBreakerThresholds(tc.src)
			assert.Equal(t, tc.expect, actual)
		}
	})

	t.Run("KeyPair", func(t *testing.T) {
		t.Parallel()

		t.Run("create", func(t *testing.T) {
			t.Parallel()

			expected := &pb.CreateKeyPairRequest{
				Certificate:  []byte("CERTIFICATE"),
				Format:       pb.Format_PEM,
				Key:          []byte("KEY"),
				Name:         "NAME",
				NamespaceId:  "NAMESPACE_ID",
				OriginatorId: "terraform",
			}
			var diagnostics diag.Diagnostics
			actual := provider.NewModelToEnterpriseConverter(&diagnostics).CreateKeyPairRequest(provider.KeyPairModel{
				ID:          types.StringValue("ID"),
				Name:        types.StringValue("NAME"),
				NamespaceID: types.StringValue("NAMESPACE_ID"),
				Certificate: types.StringValue("CERTIFICATE"),
				Key:         types.StringValue("KEY"),
			})
			if !assert.Equal(t, 0, diagnostics.ErrorsCount()) {
				t.Log(diagnostics.Errors())
			}
			if diff := cmp.Diff(expected, actual, protocmp.Transform()); diff != "" {
				t.Errorf("unexpected difference: %s", diff)
			}
		})

		t.Run("update", func(t *testing.T) {
			t.Parallel()

			fmt := pb.Format_PEM
			expected := &pb.UpdateKeyPairRequest{
				Certificate:  []byte("CERTIFICATE"),
				Format:       &fmt,
				Id:           "ID",
				Key:          []byte("KEY"),
				Name:         proto.String("NAME"),
				OriginatorId: "terraform",
			}
			var diagnostics diag.Diagnostics
			actual := provider.NewModelToEnterpriseConverter(&diagnostics).UpdateKeyPairRequest(provider.KeyPairModel{
				ID:          types.StringValue("ID"),
				Name:        types.StringValue("NAME"),
				NamespaceID: types.StringValue("NAMESPACE_ID"),
				Certificate: types.StringValue("CERTIFICATE"),
				Key:         types.StringValue("KEY"),
			})
			if !assert.Equal(t, 0, diagnostics.ErrorsCount()) {
				t.Log(diagnostics.Errors())
			}
			if diff := cmp.Diff(expected, actual, protocmp.Transform()); diff != "" {
				t.Errorf("unexpected difference: %s", diff)
			}
		})
	})

	t.Run("NamespacePermission", func(t *testing.T) {
		t.Parallel()

		expected := &pb.NamespacePermission{
			Id:           "NAMESPACE_PERMISSION_ID",
			NamespaceId:  "NAMESPACE_ID",
			SubjectType:  "SUBJECT_TYPE",
			SubjectId:    "SUBJECT_ID",
			Role:         "ROLE",
			OriginatorId: "terraform",
		}
		var diagnostics diag.Diagnostics
		actual := provider.NewModelToEnterpriseConverter(&diagnostics).NamespacePermission(provider.NamespacePermissionModel{
			ID:          types.StringValue("NAMESPACE_PERMISSION_ID"),
			NamespaceID: types.StringValue("NAMESPACE_ID"),
			Role:        types.StringValue("ROLE"),
			SubjectID:   types.StringValue("SUBJECT_ID"),
			SubjectType: types.StringValue("SUBJECT_TYPE"),
		})
		if !assert.Equal(t, 0, diagnostics.ErrorsCount()) {
			t.Log(diagnostics.Errors())
		}
		if diff := cmp.Diff(expected, actual, protocmp.Transform()); diff != "" {
			t.Errorf("unexpected difference: %s", diff)
		}
	})

	t.Run("Policy", func(t *testing.T) {
		t.Parallel()

		expected := &pb.Policy{
			Description:  "DESCRIPTION",
			Enforced:     true,
			Explanation:  "EXPLANATION",
			Id:           "ID",
			Name:         "NAME",
			NamespaceId:  "NAMESPACE_ID",
			OriginatorId: "terraform",
			Rego:         []string{"REGO"},
			Remediation:  "REMEDIATION",
		}
		var diagnostics diag.Diagnostics
		actual := provider.NewModelToEnterpriseConverter(&diagnostics).Policy(provider.PolicyModel{
			Description: types.StringValue("DESCRIPTION"),
			Enforced:    types.BoolValue(true),
			Explanation: types.StringValue("EXPLANATION"),
			ID:          types.StringValue("ID"),
			Name:        types.StringValue("NAME"),
			NamespaceID: types.StringValue("NAMESPACE_ID"),
			PPL:         provider.PolicyLanguage{},
			Rego:        types.ListValueMust(types.StringType, []attr.Value{types.StringValue("REGO")}),
			Remediation: types.StringValue("REMEDIATION"),
		})
		if !assert.Equal(t, 0, diagnostics.ErrorsCount()) {
			t.Log(diagnostics.Errors())
		}
		if diff := cmp.Diff(expected, actual, protocmp.Transform()); diff != "" {
			t.Errorf("unexpected difference: %s", diff)
		}
	})

	t.Run("Settings", func(t *testing.T) {
		t.Parallel()

		expected := &pb.Settings{
			AccessLogFields:               &pb.Settings_StringList{Values: []string{"authority", "duration", "path"}},
			Address:                       proto.String("127.0.0.1:8443"),
			AuthenticateServiceUrl:        proto.String("https://authenticate.example.com"),
			AuthorizeLogFields:            &pb.Settings_StringList{Values: []string{"request-id", "path", "ip"}},
			AuthorizeServiceUrl:           proto.String("https://authorize.example.com"),
			Autocert:                      proto.Bool(true),
			AutocertDir:                   proto.String("/tmp/autocert"),
			AutocertMustStaple:            proto.Bool(true),
			AutocertUseStaging:            proto.Bool(false),
			BearerTokenFormat:             pb.BearerTokenFormat_BEARER_TOKEN_FORMAT_IDP_ACCESS_TOKEN.Enum(),
			CacheServiceUrl:               proto.String("https://cache.example.com"),
			CertificateAuthority:          proto.String("CERTIFICATE_AUTHORITY"),
			CertificateAuthorityFile:      proto.String("/tmp/certificate-authority"),
			CertificateAuthorityKeyPairId: proto.String("CERTIFICATE_AUTHORITY_KEY_PAIR_ID"),
			ClientCa:                      proto.String("CLIENT_CA"),
			ClientCaFile:                  proto.String("/tmp/client-ca"),
			ClientCaKeyPairId:             proto.String("CLIENT_CA_KEY_PAIR_ID"),
			CodecType:                     pb.CodecType_CODEC_TYPE_HTTP2.Enum(),
			CookieDomain:                  proto.String("example.com"),
			CookieExpire:                  durationpb.New(15 * time.Minute),
			CookieHttpOnly:                proto.Bool(true),
			CookieName:                    proto.String("COOKIE"),
			CookieSameSite:                proto.String("Strict"),
			CookieSecret:                  proto.String("COOKIE_SECRET"),
			CookieSecure:                  proto.Bool(true),
			DarkmodePrimaryColor:          proto.String("DARKMODE_PRIMARY_COLOR"),
			DarkmodeSecondaryColor:        proto.String("DARKMODE_SECONDARY_COLOR"),
			DatabrokerServiceUrl:          proto.String("https://databroker.example.com"),
			DefaultUpstreamTimeout:        durationpb.New(13 * time.Second),
			DnsFailureRefreshRate:         durationpb.New(14 * time.Second),
			DnsLookupFamily:               proto.String("V6_ONLY"),
			DnsQueryTimeout:               durationpb.New(5 * time.Second),
			DnsQueryTries:                 proto.Uint32(33),
			DnsRefreshRate:                durationpb.New(15 * time.Second),
			DnsUdpMaxQueries:              proto.Uint32(34),
			DnsUseTcp:                     proto.Bool(true),
			ErrorMessageFirstParagraph:    proto.String("ERROR_MESSAGE"),
			FaviconUrl:                    proto.String("https://favicon.example.com"),
			GoogleCloudServerlessAuthenticationServiceAccount: proto.String("GOOGLE_CLOUD_SERVERLESS_AUTHENTICATION_SERVICE_ACCOUNT"),
			GrpcAddress:                     proto.String("127.0.0.1:5443"),
			GrpcInsecure:                    proto.Bool(true),
			HttpRedirectAddr:                proto.String("127.0.0.1:8000"),
			IdentityProviderRefreshInterval: durationpb.New(5 * time.Second),
			IdentityProviderRefreshTimeout:  durationpb.New(6 * time.Second),
			IdpAccessTokenAllowedAudiences:  &pb.Settings_StringList{Values: []string{"a", "b"}},
			IdpClientId:                     proto.String("IDP_CLIENT_ID"),
			IdpClientSecret:                 proto.String("IDP_CLIENT_SECRET"),
			IdpProvider:                     proto.String("IDP_PROVIDER"),
			IdpProviderUrl:                  proto.String("https://idp.example.com"),
			IdpRefreshDirectoryInterval:     durationpb.New(7 * time.Second),
			IdpRefreshDirectoryTimeout:      durationpb.New(8 * time.Second),
			IdpServiceAccount:               proto.String("IDP_SERVICE_ACCOUNT"),
			InsecureServer:                  proto.Bool(true),
			InstallationId:                  proto.String("INSTALLATION_ID"),
			JwtClaimsHeaders:                map[string]string{"X": "Y"},
			JwtGroupsFilter:                 &pb.JwtGroupsFilter{InferFromPpl: proto.Bool(true), Groups: []string{"z"}},
			JwtIssuerFormat:                 pb.IssuerFormat_IssuerURI.Enum(),
			LogLevel:                        proto.String("debug"),
			LogoUrl:                         proto.String("https://logo.example.com"),
			MetricsAddress:                  proto.String("127.0.0.1:9999"),
			OriginatorId:                    "terraform",
			PassIdentityHeaders:             proto.Bool(true),
			PrimaryColor:                    proto.String("PRIMARY_COLOR"),
			ProxyLogLevel:                   proto.String("error"),
			RequestParams:                   map[string]string{"C": "D"},
			Scopes:                          []string{"SCOPE1", "SCOPE2", "SCOPE3"},
			SecondaryColor:                  proto.String("SECONDARY_COLOR"),
			SetResponseHeaders:              map[string]string{"E": "F"},
			SkipXffAppend:                   proto.Bool(true),
			SshAddress:                      proto.String("SSH_ADDRESS"),
			SshHostKeyFiles:                 &pb.Settings_StringList{Values: []string{"HOST1", "HOST2"}},
			SshHostKeys:                     &pb.Settings_StringList{Values: []string{"HOST3", "HOST4"}},
			SshUserCaKey:                    proto.String("SSH_USER_CA_KEY"),
			SshUserCaKeyFile:                proto.String("SSH_USER_CA_KEY_FILE"),
			TimeoutIdle:                     durationpb.New(3 * time.Minute),
			TimeoutRead:                     durationpb.New(4 * time.Minute),
			TimeoutWrite:                    durationpb.New(5 * time.Minute),
		}
		var diagnostics diag.Diagnostics
		actual := provider.NewModelToEnterpriseConverter(&diagnostics).Settings(provider.SettingsModel{
			AccessLogFields:               types.SetValueMust(types.StringType, []attr.Value{types.StringValue("authority"), types.StringValue("duration"), types.StringValue("path")}),
			Address:                       types.StringValue("127.0.0.1:8443"),
			AuthenticateServiceURL:        types.StringValue("https://authenticate.example.com"),
			AuthorizeLogFields:            types.SetValueMust(types.StringType, []attr.Value{types.StringValue("request-id"), types.StringValue("path"), types.StringValue("ip")}),
			AuthorizeServiceURL:           types.StringValue("https://authorize.example.com"),
			Autocert:                      types.BoolValue(true),
			AutocertDir:                   types.StringValue("/tmp/autocert"),
			AutocertMustStaple:            types.BoolValue(true),
			AutocertUseStaging:            types.BoolValue(false),
			BearerTokenFormat:             types.StringValue("idp_access_token"),
			CacheServiceURL:               types.StringValue("https://cache.example.com"),
			CertificateAuthority:          types.StringValue("CERTIFICATE_AUTHORITY"),
			CertificateAuthorityFile:      types.StringValue("/tmp/certificate-authority"),
			CertificateAuthorityKeyPairID: types.StringValue("CERTIFICATE_AUTHORITY_KEY_PAIR_ID"),
			ClientCA:                      types.StringValue("CLIENT_CA"),
			ClientCAFile:                  types.StringValue("/tmp/client-ca"),
			ClientCAKeyPairID:             types.StringValue("CLIENT_CA_KEY_PAIR_ID"),
			CodecType:                     types.StringValue("http2"),
			CookieDomain:                  types.StringValue("example.com"),
			CookieExpire:                  timetypes.NewGoDurationValue(15 * time.Minute),
			CookieHTTPOnly:                types.BoolValue(true),
			CookieName:                    types.StringValue("COOKIE"),
			CookieSameSite:                types.StringValue("Strict"),
			CookieSecret:                  types.StringValue("COOKIE_SECRET"),
			CookieSecure:                  types.BoolValue(true),
			DarkmodePrimaryColor:          types.StringValue("DARKMODE_PRIMARY_COLOR"),
			DarkmodeSecondaryColor:        types.StringValue("DARKMODE_SECONDARY_COLOR"),
			DatabrokerServiceURL:          types.StringValue("https://databroker.example.com"),
			DefaultUpstreamTimeout:        timetypes.NewGoDurationValue(13 * time.Second),
			DNSFailureRefreshRate:         timetypes.NewGoDurationValue(14 * time.Second),
			DNSLookupFamily:               types.StringValue("V6_ONLY"),
			DNSQueryTimeout:               timetypes.NewGoDurationValue(5 * time.Second),
			DNSQueryTries:                 types.Int64Value(33),
			DNSRefreshRate:                timetypes.NewGoDurationValue(15 * time.Second),
			DNSUDPMaxQueries:              types.Int64Value(34),
			DNSUseTCP:                     types.BoolValue(true),
			ErrorMessageFirstParagraph:    types.StringValue("ERROR_MESSAGE"),
			FaviconURL:                    types.StringValue("https://favicon.example.com"),
			GoogleCloudServerlessAuthenticationServiceAccount: types.StringValue("GOOGLE_CLOUD_SERVERLESS_AUTHENTICATION_SERVICE_ACCOUNT"),
			GRPCAddress:                     types.StringValue("127.0.0.1:5443"),
			GRPCInsecure:                    types.BoolValue(true),
			HTTPRedirectAddr:                types.StringValue("127.0.0.1:8000"),
			IdentityProviderRefreshInterval: timetypes.NewGoDurationValue(5 * time.Second),
			IdentityProviderRefreshTimeout:  timetypes.NewGoDurationValue(6 * time.Second),
			IDPAccessTokenAllowedAudiences:  types.SetValueMust(types.StringType, []attr.Value{types.StringValue("a"), types.StringValue("b")}),
			IdpClientID:                     types.StringValue("IDP_CLIENT_ID"),
			IdpClientSecret:                 types.StringValue("IDP_CLIENT_SECRET"),
			IdpProvider:                     types.StringValue("IDP_PROVIDER"),
			IdpProviderURL:                  types.StringValue("https://idp.example.com"),
			IdpRefreshDirectoryInterval:     timetypes.NewGoDurationValue(7 * time.Second),
			IdpRefreshDirectoryTimeout:      timetypes.NewGoDurationValue(8 * time.Second),
			IdpServiceAccount:               types.StringValue("IDP_SERVICE_ACCOUNT"),
			InsecureServer:                  types.BoolValue(true),
			InstallationID:                  types.StringValue("INSTALLATION_ID"),
			JWTClaimsHeaders:                types.MapValueMust(types.StringType, map[string]attr.Value{"X": types.StringValue("Y")}),
			JWTGroupsFilter:                 types.ObjectValueMust(map[string]attr.Type{"infer_from_ppl": types.BoolType, "groups": types.ListType{ElemType: types.StringType}}, map[string]attr.Value{"infer_from_ppl": types.BoolValue(true), "groups": types.ListValueMust(types.StringType, []attr.Value{types.StringValue("z")})}),
			JWTIssuerFormat:                 types.StringValue("IssuerURI"),
			LogLevel:                        types.StringValue("debug"),
			LogoURL:                         types.StringValue("https://logo.example.com"),
			MetricsAddress:                  types.StringValue("127.0.0.1:9999"),
			PassIdentityHeaders:             types.BoolValue(true),
			PrimaryColor:                    types.StringValue("PRIMARY_COLOR"),
			ProxyLogLevel:                   types.StringValue("error"),
			RequestParams:                   types.MapValueMust(types.StringType, map[string]attr.Value{"C": types.StringValue("D")}),
			Scopes:                          types.SetValueMust(types.StringType, []attr.Value{types.StringValue("SCOPE1"), types.StringValue("SCOPE2"), types.StringValue("SCOPE3")}),
			SecondaryColor:                  types.StringValue("SECONDARY_COLOR"),
			SetResponseHeaders:              types.MapValueMust(types.StringType, map[string]attr.Value{"E": types.StringValue("F")}),
			SkipXFFAppend:                   types.BoolValue(true),
			SSHAddress:                      types.StringValue("SSH_ADDRESS"),
			SSHHostKeyFiles:                 types.SetValueMust(types.StringType, []attr.Value{types.StringValue("HOST1"), types.StringValue("HOST2")}),
			SSHHostKeys:                     types.SetValueMust(types.StringType, []attr.Value{types.StringValue("HOST3"), types.StringValue("HOST4")}),
			SSHUserCAKey:                    types.StringValue("SSH_USER_CA_KEY"),
			SSHUserCAKeyFile:                types.StringValue("SSH_USER_CA_KEY_FILE"),
			TimeoutIdle:                     timetypes.NewGoDurationValue(3 * time.Minute),
			TimeoutRead:                     timetypes.NewGoDurationValue(4 * time.Minute),
			TimeoutWrite:                    timetypes.NewGoDurationValue(5 * time.Minute),
		})
		assert.Empty(t, diagnostics)
		if diff := cmp.Diff(expected, actual, protocmp.Transform()); diff != "" {
			t.Errorf("unexpected difference: %s", diff)
		}
	})
}
