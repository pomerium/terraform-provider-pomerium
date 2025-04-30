package provider_test

import (
	"context"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/hashicorp/terraform-plugin-framework-timetypes/timetypes"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/stretchr/testify/assert"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/testing/protocmp"
	"google.golang.org/protobuf/types/known/durationpb"

	"github.com/pomerium/enterprise-client-go/pb"
	"github.com/pomerium/enterprise-terraform-provider/internal/provider"
)

func TestConvertSettingsToPB(t *testing.T) {
	t.Parallel()

	expected := &pb.Settings{
		AccessLogFields:               &pb.Settings_StringList{Values: []string{"authority", "duration", "path"}},
		Address:                       proto.String("127.0.0.1:8443"),
		AuthenticateCallbackPath:      proto.String("/oauth2/callback"),
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
		DnsLookupFamily:               proto.String("V6_ONLY"),
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
		TimeoutIdle:                     durationpb.New(3 * time.Minute),
		TimeoutRead:                     durationpb.New(4 * time.Minute),
		TimeoutWrite:                    durationpb.New(5 * time.Minute),
	}
	actual, diag := provider.ConvertSettingsToPB(context.Background(), &provider.SettingsModel{
		AccessLogFields:               types.SetValueMust(types.StringType, []attr.Value{types.StringValue("authority"), types.StringValue("duration"), types.StringValue("path")}),
		Address:                       types.StringValue("127.0.0.1:8443"),
		AuthenticateCallbackPath:      types.StringValue("/oauth2/callback"),
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
		DNSLookupFamily:               types.StringValue("V6_ONLY"),
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
		TimeoutIdle:                     timetypes.NewGoDurationValue(3 * time.Minute),
		TimeoutRead:                     timetypes.NewGoDurationValue(4 * time.Minute),
		TimeoutWrite:                    timetypes.NewGoDurationValue(5 * time.Minute),
	})
	if !assert.Equal(t, 0, diag.ErrorsCount()) {
		t.Log(diag.Errors())
	}
	if diff := cmp.Diff(expected, actual, protocmp.Transform()); diff != "" {
		t.Errorf("unexpected difference: %s", diff)
	}
}
