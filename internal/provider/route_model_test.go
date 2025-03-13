package provider_test

import (
	"context"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/hashicorp/terraform-plugin-framework-timetypes/timetypes"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/testing/protocmp"
	"google.golang.org/protobuf/types/known/durationpb"

	"github.com/pomerium/enterprise-client-go/pb"
	"github.com/pomerium/enterprise-terraform-provider/internal/provider"
)

func TestConvertRoute(t *testing.T) {
	t.Parallel()

	pbRoute := &pb.Route{
		Id:                               "route-123",
		Name:                             "test-route",
		From:                             "https://from.example.com",
		To:                               []string{"https://to1.example.com", "https://to2.example.com"},
		NamespaceId:                      "namespace-123",
		PolicyIds:                        []string{"policy-1", "policy-2"},
		StatName:                         "test-stat",
		Prefix:                           ptr("/prefix"),
		Path:                             ptr("/path"),
		Regex:                            ptr("^/regex.*$"),
		PrefixRewrite:                    ptr("/prefix-rewrite"),
		RegexRewritePattern:              ptr("^/old(.*)$"),
		RegexRewriteSubstitution:         ptr("/new$1"),
		HostRewrite:                      ptr("rewritten-host"),
		HostRewriteHeader:                ptr("X-Host-Header"),
		HostPathRegexRewritePattern:      ptr("^/path-pattern(.*)$"),
		HostPathRegexRewriteSubstitution: ptr("host-sub$1"),
		RegexPriorityOrder:               ptr(int64(10)),
		Timeout:                          durationpb.New(30 * time.Second),
		IdleTimeout:                      durationpb.New(5 * time.Minute),
		AllowWebsockets:                  ptr(true),
		AllowSpdy:                        ptr(true),
		TlsSkipVerify:                    ptr(false),
		TlsUpstreamServerName:            ptr("upstream.example.com"),
		TlsDownstreamServerName:          ptr("downstream.example.com"),
		TlsUpstreamAllowRenegotiation:    ptr(true),
		SetRequestHeaders:                map[string]string{"X-Request-1": "value1", "X-Request-2": "value2"},
		RemoveRequestHeaders:             []string{"X-Remove-1", "X-Remove-2"},
		SetResponseHeaders:               map[string]string{"X-Response-1": "value1", "X-Response-2": "value2"},
		PreserveHostHeader:               ptr(true),
		PassIdentityHeaders:              ptr(true),
		KubernetesServiceAccountToken:    ptr("k8s-token"),
		IdpClientId:                      ptr("idp-client-id"),
		IdpClientSecret:                  ptr("idp-client-secret"),
		ShowErrorDetails:                 true,
		TlsClientKeyPairId:               ptr("client-key-pair-123"),
		TlsCustomCaKeyPairId:             ptr("ca-key-pair-123"),
		Description:                      ptr("Route description"),
		LogoUrl:                          ptr("https://logo.example.com/logo.png"),
		EnableGoogleCloudServerlessAuthentication: true,
		KubernetesServiceAccountTokenFile:         ptr("/path/to/token"),
		JwtIssuerFormat:                           pb.IssuerFormat_IssuerURI.Enum(),
		BearerTokenFormat:                         pb.BearerTokenFormat_BEARER_TOKEN_FORMAT_IDP_ACCESS_TOKEN.Enum(),
		IdpAccessTokenAllowedAudiences:            &pb.Route_StringList{Values: []string{"aud1", "aud2"}},
		LoadBalancingPolicy:                       pb.LoadBalancingPolicy_LOAD_BALANCING_POLICY_ROUND_ROBIN.Enum(),
		RewriteResponseHeaders: []*pb.RouteRewriteHeader{
			{
				Header:  "X-Rewrite-Header",
				Value:   "new-value",
				Matcher: &pb.RouteRewriteHeader_Prefix{Prefix: "old-prefix"},
			},
		},
		JwtGroupsFilter: &pb.JwtGroupsFilter{
			Groups:       []string{"group1", "group2"},
			InferFromPpl: ptr(true),
		},
		OriginatorId: provider.OriginatorID,
		HealthChecks: []*pb.HealthCheck{
			{
				Timeout:               durationpb.New(5 * time.Second),
				Interval:              durationpb.New(10 * time.Second),
				InitialJitter:         durationpb.New(100 * time.Millisecond),
				IntervalJitter:        durationpb.New(200 * time.Millisecond),
				IntervalJitterPercent: 5,
				UnhealthyThreshold:    2,
				HealthyThreshold:      2,
				HealthChecker: &pb.HealthCheck_HttpHealthCheck_{
					HttpHealthCheck: &pb.HealthCheck_HttpHealthCheck{
						Host:            "health.example.com",
						Path:            "/health",
						CodecClientType: pb.CodecClientType_HTTP2,
						ExpectedStatuses: []*pb.Int64Range{
							{Start: 200, End: 300},
						},
						RetriableStatuses: []*pb.Int64Range{
							{Start: 500, End: 501},
						},
					},
				},
			},
			{
				Timeout:            durationpb.New(3 * time.Second),
				Interval:           durationpb.New(15 * time.Second),
				UnhealthyThreshold: 3,
				HealthyThreshold:   1,
				HealthChecker: &pb.HealthCheck_TcpHealthCheck_{
					TcpHealthCheck: &pb.HealthCheck_TcpHealthCheck{
						Send: &pb.HealthCheck_Payload{
							Payload: &pb.HealthCheck_Payload_Text{
								Text: "000000FF",
							},
						},
						Receive: []*pb.HealthCheck_Payload{
							{
								Payload: &pb.HealthCheck_Payload_Text{
									Text: "0000FFFF",
								},
							},
						},
					},
				},
			},
			{
				Timeout:            durationpb.New(2 * time.Second),
				Interval:           durationpb.New(5 * time.Second),
				UnhealthyThreshold: 2,
				HealthyThreshold:   1,
				HealthChecker: &pb.HealthCheck_GrpcHealthCheck_{
					GrpcHealthCheck: &pb.HealthCheck_GrpcHealthCheck{
						ServiceName: "my-service",
						Authority:   "grpc.example.com",
					},
				},
			},
		},
	}

	tfRoute := provider.RouteModel{
		ID:                               types.StringValue("route-123"),
		Name:                             types.StringValue("test-route"),
		From:                             types.StringValue("https://from.example.com"),
		To:                               types.SetValueMust(types.StringType, []attr.Value{types.StringValue("https://to1.example.com"), types.StringValue("https://to2.example.com")}),
		NamespaceID:                      types.StringValue("namespace-123"),
		Policies:                         types.SetValueMust(types.StringType, []attr.Value{types.StringValue("policy-1"), types.StringValue("policy-2")}),
		StatName:                         types.StringValue("test-stat"),
		Prefix:                           types.StringValue("/prefix"),
		Path:                             types.StringValue("/path"),
		Regex:                            types.StringValue("^/regex.*$"),
		PrefixRewrite:                    types.StringValue("/prefix-rewrite"),
		RegexRewritePattern:              types.StringValue("^/old(.*)$"),
		RegexRewriteSubstitution:         types.StringValue("/new$1"),
		HostRewrite:                      types.StringValue("rewritten-host"),
		HostRewriteHeader:                types.StringValue("X-Host-Header"),
		HostPathRegexRewritePattern:      types.StringValue("^/path-pattern(.*)$"),
		HostPathRegexRewriteSubstitution: types.StringValue("host-sub$1"),
		RegexPriorityOrder:               types.Int64Value(10),
		Timeout:                          timetypes.NewGoDurationValue(30 * time.Second),
		IdleTimeout:                      timetypes.NewGoDurationValue(5 * time.Minute),
		AllowWebsockets:                  types.BoolValue(true),
		AllowSPDY:                        types.BoolValue(true),
		TLSSkipVerify:                    types.BoolValue(false),
		TLSUpstreamServerName:            types.StringValue("upstream.example.com"),
		TLSDownstreamServerName:          types.StringValue("downstream.example.com"),
		TLSUpstreamAllowRenegotiation:    types.BoolValue(true),
		SetRequestHeaders: types.MapValueMust(types.StringType, map[string]attr.Value{
			"X-Request-1": types.StringValue("value1"),
			"X-Request-2": types.StringValue("value2"),
		}),
		RemoveRequestHeaders: types.SetValueMust(types.StringType, []attr.Value{types.StringValue("X-Remove-1"), types.StringValue("X-Remove-2")}),
		SetResponseHeaders: types.MapValueMust(types.StringType, map[string]attr.Value{
			"X-Response-1": types.StringValue("value1"),
			"X-Response-2": types.StringValue("value2"),
		}),
		PreserveHostHeader:            types.BoolValue(true),
		PassIdentityHeaders:           types.BoolValue(true),
		KubernetesServiceAccountToken: types.StringValue("k8s-token"),
		IDPClientID:                   types.StringValue("idp-client-id"),
		IDPClientSecret:               types.StringValue("idp-client-secret"),
		ShowErrorDetails:              types.BoolValue(true),
		TLSClientKeyPairID:            types.StringValue("client-key-pair-123"),
		TLSCustomCAKeyPairID:          types.StringValue("ca-key-pair-123"),
		Description:                   types.StringValue("Route description"),
		LogoURL:                       types.StringValue("https://logo.example.com/logo.png"),
		EnableGoogleCloudServerlessAuthentication: types.BoolValue(true),
		KubernetesServiceAccountTokenFile:         types.StringValue("/path/to/token"),
		JWTIssuerFormat:                           types.StringValue("uri"),
		BearerTokenFormat:                         types.StringValue("idp_access_token"),
		IDPAccessTokenAllowedAudiences:            types.SetValueMust(types.StringType, []attr.Value{types.StringValue("aud1"), types.StringValue("aud2")}),
		LoadBalancingPolicy:                       types.StringValue("round_robin"),
		JWTGroupsFilter: types.ObjectValueMust(
			map[string]attr.Type{
				"infer_from_ppl": types.BoolType,
				"groups":         types.SetType{ElemType: types.StringType},
			},
			map[string]attr.Value{
				"infer_from_ppl": types.BoolValue(true),
				"groups":         types.SetValueMust(types.StringType, []attr.Value{types.StringValue("group1"), types.StringValue("group2")}),
			},
		),
		RewriteResponseHeaders: types.SetValueMust(
			provider.RewriteHeaderObjectType(),
			[]attr.Value{types.ObjectValueMust(
				provider.RewriteHeaderAttrTypes(),
				map[string]attr.Value{
					"header": types.StringValue("X-Rewrite-Header"),
					"value":  types.StringValue("new-value"),
					"prefix": types.StringValue("old-prefix"),
				},
			)},
		),
		HealthChecks: types.SetValueMust(
			provider.HealthCheckObjectType(),
			[]attr.Value{
				types.ObjectValueMust(
					provider.HealthCheckObjectType().AttrTypes,
					map[string]attr.Value{
						"timeout":                 timetypes.NewGoDurationValue(5 * time.Second),
						"interval":                timetypes.NewGoDurationValue(10 * time.Second),
						"initial_jitter":          timetypes.NewGoDurationValue(100 * time.Millisecond),
						"interval_jitter":         timetypes.NewGoDurationValue(200 * time.Millisecond),
						"interval_jitter_percent": types.Int64Value(5),
						"unhealthy_threshold":     types.Int64Value(2),
						"healthy_threshold":       types.Int64Value(2),
						"tcp_health_check":        types.ObjectNull(provider.TCPHealthCheckObjectType().AttrTypes),
						"grpc_health_check":       types.ObjectNull(provider.GrpcHealthCheckObjectType().AttrTypes),
						"http_health_check": types.ObjectValueMust(
							provider.HTTPHealthCheckObjectType().AttrTypes,
							map[string]attr.Value{
								"host":              types.StringValue("health.example.com"),
								"path":              types.StringValue("/health"),
								"codec_client_type": types.StringValue("HTTP2"),
								"expected_statuses": types.SetValueMust(
									provider.Int64RangeObjectType(),
									[]attr.Value{
										types.ObjectValueMust(
											provider.Int64RangeObjectType().AttrTypes,
											map[string]attr.Value{
												"start": types.Int64Value(200),
												"end":   types.Int64Value(300),
											},
										),
									},
								),
								"retriable_statuses": types.SetValueMust(
									provider.Int64RangeObjectType(),
									[]attr.Value{
										types.ObjectValueMust(
											provider.Int64RangeObjectType().AttrTypes,
											map[string]attr.Value{
												"start": types.Int64Value(500),
												"end":   types.Int64Value(501),
											},
										),
									},
								),
							},
						),
					},
				),
				types.ObjectValueMust(
					provider.HealthCheckObjectType().AttrTypes,
					map[string]attr.Value{
						"timeout":                 timetypes.NewGoDurationValue(3 * time.Second),
						"interval":                timetypes.NewGoDurationValue(15 * time.Second),
						"initial_jitter":          timetypes.NewGoDurationNull(),
						"interval_jitter":         timetypes.NewGoDurationNull(),
						"interval_jitter_percent": types.Int64Null(),
						"unhealthy_threshold":     types.Int64Value(3),
						"healthy_threshold":       types.Int64Value(1),
						"http_health_check":       types.ObjectNull(provider.HTTPHealthCheckObjectType().AttrTypes),
						"grpc_health_check":       types.ObjectNull(provider.GrpcHealthCheckObjectType().AttrTypes),
						"tcp_health_check": types.ObjectValueMust(
							provider.TCPHealthCheckObjectType().AttrTypes,
							map[string]attr.Value{
								"send": types.ObjectValueMust(
									provider.HealthCheckPayloadObjectType().AttrTypes,
									map[string]attr.Value{
										"text":       types.StringValue("000000FF"),
										"binary_b64": types.StringNull(),
									},
								),
								"receive": types.SetValueMust(
									provider.HealthCheckPayloadObjectType(),
									[]attr.Value{
										types.ObjectValueMust(
											provider.HealthCheckPayloadObjectType().AttrTypes,
											map[string]attr.Value{
												"text":       types.StringValue("0000FFFF"),
												"binary_b64": types.StringNull(),
											},
										),
									},
								),
							},
						),
					},
				),
				types.ObjectValueMust(
					provider.HealthCheckObjectType().AttrTypes,
					map[string]attr.Value{
						"timeout":                 timetypes.NewGoDurationValue(2 * time.Second),
						"interval":                timetypes.NewGoDurationValue(5 * time.Second),
						"initial_jitter":          timetypes.NewGoDurationNull(),
						"interval_jitter":         timetypes.NewGoDurationNull(),
						"interval_jitter_percent": types.Int64Null(),
						"unhealthy_threshold":     types.Int64Value(2),
						"healthy_threshold":       types.Int64Value(1),
						"http_health_check":       types.ObjectNull(provider.HTTPHealthCheckObjectType().AttrTypes),
						"tcp_health_check":        types.ObjectNull(provider.TCPHealthCheckObjectType().AttrTypes),
						"grpc_health_check": types.ObjectValueMust(
							provider.GrpcHealthCheckObjectType().AttrTypes,
							map[string]attr.Value{
								"service_name": types.StringValue("my-service"),
								"authority":    types.StringValue("grpc.example.com"),
							},
						),
					},
				),
			},
		),
	}

	t.Run("pb to tf", func(t *testing.T) {
		var got provider.RouteModel
		diags := provider.ConvertRouteFromPB(&got, pbRoute)
		require.False(t, diags.HasError(), "ConvertRouteFromPB returned diagnostics errors")

		if diff := cmp.Diff(tfRoute, got); diff != "" {
			t.Errorf("ConvertRouteFromPB() mismatch (-want +got):\n%s", diff)
		}
	})
	t.Run("tf to pb", func(t *testing.T) {
		ctx := context.Background()

		got, diags := provider.ConvertRouteToPB(ctx, &tfRoute)
		require.False(t, diags.HasError(), "ConvertRouteToPB returned diagnostics errors")

		if diff := cmp.Diff(pbRoute, got, protocmp.Transform()); diff != "" {
			t.Errorf("ConvertRouteToPB() mismatch (-want +got):\n%s", diff)
		}
	})
}
