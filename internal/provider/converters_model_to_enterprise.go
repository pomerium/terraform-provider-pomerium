package provider

import (
	"context"
	"encoding/base64"
	"time"

	"github.com/hashicorp/terraform-plugin-framework-timetypes/timetypes"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-framework/types/basetypes"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	enterprise "github.com/pomerium/enterprise-client-go/pb"
)

type ModelToEnterpriseConverter struct {
	diagnostics *diag.Diagnostics
}

func NewModelToEnterpriseConverter(diagnostics *diag.Diagnostics) *ModelToEnterpriseConverter {
	return &ModelToEnterpriseConverter{
		diagnostics: diagnostics,
	}
}

func (c *ModelToEnterpriseConverter) BytesFromBase64(p path.Path, src types.String) []byte {
	if src.IsNull() || src.IsUnknown() || src.ValueString() == "" {
		return nil
	}

	dst, err := base64.StdEncoding.DecodeString(src.ValueString())
	if err != nil {
		appendAttributeDiagnostics(c.diagnostics, p, diag.NewErrorDiagnostic("invalid base64 string", err.Error()))
		return nil
	}

	return dst
}

func (c *ModelToEnterpriseConverter) CircuitBreakerThresholds(src types.Object) *enterprise.CircuitBreakerThresholds {
	if src.IsNull() || src.IsUnknown() {
		return nil
	}

	attrs := src.Attributes()
	maxConnectionPools, _ := attrs["max_connection_pools"].(types.Int64)
	maxConnections, _ := attrs["max_connections"].(types.Int64)
	maxPendingRequests, _ := attrs["max_pending_requests"].(types.Int64)
	maxRequests, _ := attrs["max_requests"].(types.Int64)
	maxRetries, _ := attrs["max_retries"].(types.Int64)

	return &enterprise.CircuitBreakerThresholds{
		MaxConnectionPools: c.NullableUint32(maxConnectionPools),
		MaxConnections:     c.NullableUint32(maxConnections),
		MaxPendingRequests: c.NullableUint32(maxPendingRequests),
		MaxRequests:        c.NullableUint32(maxRequests),
		MaxRetries:         c.NullableUint32(maxRetries),
	}
}

func (c *ModelToEnterpriseConverter) Cluster(src ClusterModel) *enterprise.Cluster {
	return &enterprise.Cluster{
		CertificateAuthority:     c.BytesFromBase64(path.Root("certificate_authority_b64"), src.CertificateAuthorityB64),
		CertificateAuthorityFile: c.NullableString(src.CertificateAuthorityFile),
		CreatedAt:                nil,
		DatabrokerServiceUrl:     src.DatabrokerServiceURL.ValueString(),
		DeletedAt:                nil,
		Id:                       src.ID.ValueString(),
		InsecureSkipVerify:       c.NullableBool(src.InsecureSkipVerify),
		ModifiedAt:               nil,
		Name:                     src.Name.ValueString(),
		OriginatorId:             OriginatorID,
		OverrideCertificateName:  c.NullableString(src.OverrideCertificateName),
		SharedSecret:             c.BytesFromBase64(path.Root("shared_secret_b64"), src.SharedSecretB64),
	}
}

func (c *ModelToEnterpriseConverter) CreateKeyPairRequest(src KeyPairModel) *enterprise.CreateKeyPairRequest {
	return &enterprise.CreateKeyPairRequest{
		Certificate:  []byte(src.Certificate.ValueString()),
		Format:       enterprise.Format_PEM,
		Id:           nil, // generated
		Key:          []byte(src.Key.ValueString()),
		Name:         src.Name.ValueString(),
		NamespaceId:  src.NamespaceID.ValueString(),
		OriginatorId: OriginatorID,
	}
}

func (c *ModelToEnterpriseConverter) Duration(p path.Path, src timetypes.GoDuration) *durationpb.Duration {
	if src.IsNull() || src.IsUnknown() {
		return nil
	}

	dur, diagnostics := src.ValueGoDuration()
	appendAttributeDiagnostics(c.diagnostics, p, diagnostics...)
	return durationpb.New(dur)
}

func (c *ModelToEnterpriseConverter) ExternalDataSource(src ExternalDataSourceModel) *enterprise.ExternalDataSource {
	return &enterprise.ExternalDataSource{
		AllowInsecureTls: src.AllowInsecureTLS.ValueBoolPointer(),
		ClientTlsKeyId:   src.ClientTLSKeyID.ValueStringPointer(),
		ClusterId:        src.ClusterID.ValueStringPointer(),
		ForeignKey:       src.ForeignKey.ValueString(),
		Headers:          c.StringMap(path.Root("headers"), src.Headers),
		Id:               src.ID.ValueString(),
		OriginatorId:     OriginatorID,
		PollingMaxDelay:  c.Duration(path.Root("polling_max_delay"), src.PollingMaxDelay),
		PollingMinDelay:  c.Duration(path.Root("polling_min_delay"), src.PollingMinDelay),
		RecordType:       src.RecordType.ValueString(),
		Url:              src.URL.ValueString(),
	}
}

func (c *ModelToEnterpriseConverter) HealthCheck(src types.Object) *enterprise.HealthCheck {
	if src.IsNull() {
		return nil
	}

	attrs := src.Attributes()

	// Convert basic fields
	timeout := attrs["timeout"].(timetypes.GoDuration)
	interval := attrs["interval"].(timetypes.GoDuration)
	initialJitter := attrs["initial_jitter"].(timetypes.GoDuration)
	intervalJitter := attrs["interval_jitter"].(timetypes.GoDuration)
	intervalJitterPercent := attrs["interval_jitter_percent"].(types.Int64)
	unhealthyThreshold := attrs["unhealthy_threshold"].(types.Int64)
	healthyThreshold := attrs["healthy_threshold"].(types.Int64)

	dst := &enterprise.HealthCheck{
		Timeout:               c.Duration(path.Root("timeout"), timeout),
		Interval:              c.Duration(path.Root("interval"), interval),
		InitialJitter:         c.Duration(path.Root("initial_jitter"), initialJitter),
		IntervalJitter:        c.Duration(path.Root("interval_jitter"), intervalJitter),
		IntervalJitterPercent: uint32(intervalJitterPercent.ValueInt64()),
		UnhealthyThreshold:    uint32(unhealthyThreshold.ValueInt64()),
		HealthyThreshold:      uint32(healthyThreshold.ValueInt64()),
	}

	httpHc := attrs["http_health_check"].(types.Object)
	tcpHc := attrs["tcp_health_check"].(types.Object)
	grpcHc := attrs["grpc_health_check"].(types.Object)

	if !httpHc.IsNull() {
		httpAttrs := httpHc.Attributes()
		httpHealthCheck := &enterprise.HealthCheck_HttpHealthCheck{}

		host := httpAttrs["host"].(types.String)
		path := httpAttrs["path"].(types.String)
		codecType := httpAttrs["codec_client_type"].(types.String)
		expectedStatuses := httpAttrs["expected_statuses"].(types.Set)
		retriableStatuses := httpAttrs["retriable_statuses"].(types.Set)

		if !host.IsNull() {
			httpHealthCheck.Host = host.ValueString()
		}
		if !path.IsNull() {
			httpHealthCheck.Path = path.ValueString()
		}
		if !codecType.IsNull() {
			// Handle codec client type enum properly
			switch codecType.ValueString() {
			case "HTTP1":
				httpHealthCheck.CodecClientType = enterprise.CodecClientType_HTTP1
			case "HTTP2":
				httpHealthCheck.CodecClientType = enterprise.CodecClientType_HTTP2
			default:
				// Default to HTTP1 if not specified or invalid
				httpHealthCheck.CodecClientType = enterprise.CodecClientType_HTTP1
			}
		}

		if !expectedStatuses.IsNull() {
			for _, elem := range expectedStatuses.Elements() {
				obj := elem.(types.Object)
				statusRange, diagsRange := int64RangeToPB(obj)
				c.diagnostics.Append(diagsRange...)
				httpHealthCheck.ExpectedStatuses = append(httpHealthCheck.ExpectedStatuses, statusRange)
			}
		}

		if !retriableStatuses.IsNull() {
			for _, elem := range retriableStatuses.Elements() {
				obj := elem.(types.Object)
				statusRange, diagsRange := int64RangeToPB(obj)
				c.diagnostics.Append(diagsRange...)
				httpHealthCheck.RetriableStatuses = append(httpHealthCheck.RetriableStatuses, statusRange)
			}
		}

		dst.HealthChecker = &enterprise.HealthCheck_HttpHealthCheck_{
			HttpHealthCheck: httpHealthCheck,
		}
	} else if !tcpHc.IsNull() {
		tcpAttrs := tcpHc.Attributes()
		tcpHealthCheck := &enterprise.HealthCheck_TcpHealthCheck{}

		send := tcpAttrs["send"].(types.Object)
		receive := tcpAttrs["receive"].(types.Set)

		if !send.IsNull() {
			sendPayload, diagsSend := payloadToPB(send)
			c.diagnostics.Append(diagsSend...)
			tcpHealthCheck.Send = sendPayload
		}

		if !receive.IsNull() {
			for _, elem := range receive.Elements() {
				obj := elem.(types.Object)
				payload, diagsPayload := payloadToPB(obj)
				c.diagnostics.Append(diagsPayload...)
				tcpHealthCheck.Receive = append(tcpHealthCheck.Receive, payload)
			}
		}

		dst.HealthChecker = &enterprise.HealthCheck_TcpHealthCheck_{
			TcpHealthCheck: tcpHealthCheck,
		}
	} else if !grpcHc.IsNull() {
		grpcAttrs := grpcHc.Attributes()
		grpcHealthCheck := &enterprise.HealthCheck_GrpcHealthCheck{}

		serviceName := grpcAttrs["service_name"].(types.String)
		authority := grpcAttrs["authority"].(types.String)

		if !serviceName.IsNull() {
			grpcHealthCheck.ServiceName = serviceName.ValueString()
		}
		if !authority.IsNull() {
			grpcHealthCheck.Authority = authority.ValueString()
		}

		dst.HealthChecker = &enterprise.HealthCheck_GrpcHealthCheck_{
			GrpcHealthCheck: grpcHealthCheck,
		}
	} else {
		c.diagnostics.AddAttributeError(path.Root("health_checks"), "health check not specified", "must specify one of http_health_check, tcp_health_check, or grpc_health_check")
	}

	return dst
}

func (c *ModelToEnterpriseConverter) JWTGroupsFilter(src types.Object) *enterprise.JwtGroupsFilter {
	if src.IsNull() || src.IsUnknown() {
		return nil
	}
	var obj struct {
		Groups       []string `tfsdk:"groups"`
		InferFromPpl *bool    `tfsdk:"infer_from_ppl"`
	}
	c.diagnostics.Append(src.As(context.Background(), &obj, basetypes.ObjectAsOptions{
		UnhandledNullAsEmpty:    true,
		UnhandledUnknownAsEmpty: false,
	})...)
	return &enterprise.JwtGroupsFilter{
		Groups:       obj.Groups,
		InferFromPpl: obj.InferFromPpl,
	}
}

func (c *ModelToEnterpriseConverter) Namespace(src NamespaceModel) *enterprise.Namespace {
	return &enterprise.Namespace{
		ClusterId:    c.NullableString(src.ClusterID),
		CreatedAt:    nil, // not supported
		DeletedAt:    nil, // not supported
		Id:           src.ID.ValueString(),
		ModifiedAt:   nil, // not supported
		Name:         src.Name.ValueString(),
		OriginatorId: OriginatorID,
		ParentId:     *c.NullableString(src.ParentID),
		PolicyCount:  0, // not supported
		RouteCount:   0, // not supported
	}
}

func (c *ModelToEnterpriseConverter) NamespacePermission(src NamespacePermissionModel) *enterprise.NamespacePermission {
	return &enterprise.NamespacePermission{
		CreatedAt:     nil, // not supported
		Id:            src.ID.ValueString(),
		ModifiedAt:    nil, // not supported
		NamespaceId:   src.NamespaceID.ValueString(),
		NamespaceName: "", // not supported
		OriginatorId:  OriginatorID,
		Role:          src.Role.ValueString(),
		SubjectId:     src.SubjectID.ValueString(),
		SubjectType:   src.SubjectType.ValueString(),
	}
}

func (c *ModelToEnterpriseConverter) NullableBool(src types.Bool) *bool {
	if src.IsNull() || src.IsUnknown() {
		return nil
	}
	return src.ValueBoolPointer()
}

func (c *ModelToEnterpriseConverter) NullableString(src types.String) *string {
	if src.IsNull() || src.IsUnknown() {
		return nil
	}
	return src.ValueStringPointer()
}

func (c *ModelToEnterpriseConverter) NullableUint32(src types.Int64) *uint32 {
	if src.IsNull() || src.IsUnknown() {
		return nil
	}
	return proto.Uint32(uint32(src.ValueInt64()))
}

func (c *ModelToEnterpriseConverter) Policy(src PolicyModel) *enterprise.Policy {
	return &enterprise.Policy{
		AllowedDomains:   nil, // not supported
		AllowedIdpClaims: nil, // not supported
		AllowedUsers:     nil, // not supported
		CreatedAt:        nil, // not supported
		DeletedAt:        nil, // not supported
		Description:      src.Description.ValueString(),
		Enforced:         src.Enforced.ValueBool(),
		Explanation:      src.Explanation.ValueString(),
		Id:               src.ID.ValueString(),
		ModifiedAt:       nil, // not supported
		Name:             src.Name.ValueString(),
		NamespaceId:      src.NamespaceID.ValueString(),
		NamespaceName:    "", // not supported
		OriginatorId:     OriginatorID,
		Ppl:              string(src.PPL.PolicyJSON),
		Rego:             c.StringSliceFromList(path.Root("rego"), src.Rego),
		Remediation:      src.Remediation.ValueString(),
		Routes:           nil, // not supported
	}
}

func (c *ModelToEnterpriseConverter) Route(src RouteModel) *enterprise.Route {
	return &enterprise.Route{
		AllowSpdy:                src.AllowSPDY.ValueBoolPointer(),
		AllowWebsockets:          src.AllowWebsockets.ValueBoolPointer(),
		BearerTokenFormat:        ToBearerTokenFormat(src.BearerTokenFormat),
		CircuitBreakerThresholds: c.CircuitBreakerThresholds(src.CircuitBreakerThresholds),
		DependsOn:                c.StringSliceFromSet(path.Root("depends_on"), src.DependsOnHosts),
		Description:              src.Description.ValueStringPointer(),
		EnableGoogleCloudServerlessAuthentication: *c.NullableBool(src.EnableGoogleCloudServerlessAuthentication),
		From:                              src.From.ValueString(),
		HealthChecks:                      fromSetOfObjects(src.HealthChecks, HealthCheckObjectType(), c.HealthCheck),
		HealthyPanicThreshold:             src.HealthyPanicThreshold.ValueInt32Pointer(),
		HostPathRegexRewritePattern:       src.HostPathRegexRewritePattern.ValueStringPointer(),
		HostPathRegexRewriteSubstitution:  src.HostPathRegexRewriteSubstitution.ValueStringPointer(),
		HostRewrite:                       src.HostRewrite.ValueStringPointer(),
		HostRewriteHeader:                 src.HostRewriteHeader.ValueStringPointer(),
		Id:                                src.ID.ValueString(),
		IdleTimeout:                       c.Duration(path.Root("idle_timeout"), src.IdleTimeout),
		IdpAccessTokenAllowedAudiences:    c.RouteStringList(path.Root("idp_access_token_allowed_audiences"), src.IDPAccessTokenAllowedAudiences),
		IdpClientId:                       src.IDPClientID.ValueStringPointer(),
		IdpClientSecret:                   src.IDPClientSecret.ValueStringPointer(),
		JwtGroupsFilter:                   c.JWTGroupsFilter(src.JWTGroupsFilter),
		JwtIssuerFormat:                   ToIssuerFormat(src.JWTIssuerFormat, c.diagnostics),
		KubernetesServiceAccountToken:     src.KubernetesServiceAccountToken.ValueStringPointer(),
		KubernetesServiceAccountTokenFile: src.KubernetesServiceAccountTokenFile.ValueStringPointer(),
		LoadBalancingPolicy:               OptionalEnumValueToPB[enterprise.LoadBalancingPolicy](src.LoadBalancingPolicy, "LOAD_BALANCING_POLICY", c.diagnostics),
		LogoUrl:                           src.LogoURL.ValueStringPointer(),
		Name:                              src.Name.ValueString(),
		NamespaceId:                       src.NamespaceID.ValueString(),
		OriginatorId:                      OriginatorID,
		PassIdentityHeaders:               src.PassIdentityHeaders.ValueBoolPointer(),
		Path:                              src.Path.ValueStringPointer(),
		PolicyIds:                         c.StringSliceFromSet(path.Root("policies"), src.Policies),
		Prefix:                            src.Prefix.ValueStringPointer(),
		PrefixRewrite:                     src.PrefixRewrite.ValueStringPointer(),
		PreserveHostHeader:                src.PreserveHostHeader.ValueBoolPointer(),
		Regex:                             src.Regex.ValueStringPointer(),
		RegexPriorityOrder:                src.RegexPriorityOrder.ValueInt64Pointer(),
		RegexRewritePattern:               src.RegexRewritePattern.ValueStringPointer(),
		RegexRewriteSubstitution:          src.RegexRewriteSubstitution.ValueStringPointer(),
		RemoveRequestHeaders:              c.StringSliceFromSet(path.Root("remove_request_headers"), src.RemoveRequestHeaders),
		RewriteResponseHeaders:            rewriteHeadersToPB(src.RewriteResponseHeaders),
		SetRequestHeaders:                 c.StringMap(path.Root("set_request_headers"), src.SetRequestHeaders),
		SetResponseHeaders:                c.StringMap(path.Root("set_response_headers"), src.SetResponseHeaders),
		ShowErrorDetails:                  src.ShowErrorDetails.ValueBool(),
		StatName:                          src.StatName.ValueString(),
		Timeout:                           c.Duration(path.Root("timeout"), src.Timeout),
		TlsClientKeyPairId:                src.TLSClientKeyPairID.ValueStringPointer(),
		TlsCustomCaKeyPairId:              src.TLSCustomCAKeyPairID.ValueStringPointer(),
		TlsDownstreamServerName:           src.TLSDownstreamServerName.ValueStringPointer(),
		TlsSkipVerify:                     src.TLSSkipVerify.ValueBoolPointer(),
		TlsUpstreamAllowRenegotiation:     src.TLSUpstreamAllowRenegotiation.ValueBoolPointer(),
		TlsUpstreamServerName:             src.TLSUpstreamServerName.ValueStringPointer(),
		To:                                c.StringSliceFromSet(path.Root("to"), src.To),
	}
}

func (c *ModelToEnterpriseConverter) RouteStringList(p path.Path, src types.Set) *enterprise.Route_StringList {
	if src.IsNull() || src.IsUnknown() {
		return nil
	}
	var values []string
	appendAttributeDiagnostics(c.diagnostics, p, src.ElementsAs(context.Background(), &values, false)...)
	return &enterprise.Route_StringList{Values: values}
}

func (c *ModelToEnterpriseConverter) ServiceAccount(src ServiceAccountModel) *enterprise.PomeriumServiceAccount {
	return &enterprise.PomeriumServiceAccount{
		AccessedAt:   nil, // not supported
		Description:  c.NullableString(src.Description),
		ExpiresAt:    c.Timestamp(path.Root("expires_at"), src.ExpiresAt),
		Id:           src.ID.ValueString(),
		IssuedAt:     nil, // not supported
		NamespaceId:  zeroToNil(src.NamespaceID.ValueString()),
		OriginatorId: proto.String(OriginatorID),
		UserId:       src.Name.ValueString(),
	}
}

func (c *ModelToEnterpriseConverter) Settings(src SettingsModel) *enterprise.Settings {
	dst := &enterprise.Settings{}

	ToStringListFromSet(context.Background(), &dst.AccessLogFields, src.AccessLogFields, c.diagnostics)
	dst.Address = src.Address.ValueStringPointer()
	dst.AuthenticateServiceUrl = src.AuthenticateServiceURL.ValueStringPointer()
	ToStringListFromSet(context.Background(), &dst.AuthorizeLogFields, src.AuthorizeLogFields, c.diagnostics)
	dst.AuthorizeServiceUrl = src.AuthorizeServiceURL.ValueStringPointer()
	dst.Autocert = src.Autocert.ValueBoolPointer()
	dst.AutocertDir = src.AutocertDir.ValueStringPointer()
	dst.AutocertMustStaple = src.AutocertMustStaple.ValueBoolPointer()
	dst.AutocertUseStaging = src.AutocertUseStaging.ValueBoolPointer()
	dst.BearerTokenFormat = ToBearerTokenFormat(src.BearerTokenFormat)
	dst.CacheServiceUrl = src.CacheServiceURL.ValueStringPointer()
	dst.CertificateAuthority = src.CertificateAuthority.ValueStringPointer()
	dst.CertificateAuthorityFile = src.CertificateAuthorityFile.ValueStringPointer()
	dst.CertificateAuthorityKeyPairId = src.CertificateAuthorityKeyPairID.ValueStringPointer()
	dst.CircuitBreakerThresholds = NewModelToEnterpriseConverter(c.diagnostics).CircuitBreakerThresholds(src.CircuitBreakerThresholds)
	dst.ClientCa = src.ClientCA.ValueStringPointer()
	dst.ClientCaFile = src.ClientCAFile.ValueStringPointer()
	dst.ClientCaKeyPairId = src.ClientCAKeyPairID.ValueStringPointer()
	dst.ClusterId = src.ClusterID.ValueStringPointer()
	dst.CodecType = ToCodecType(src.CodecType)
	dst.CookieDomain = src.CookieDomain.ValueStringPointer()
	ToDuration(&dst.CookieExpire, src.CookieExpire, c.diagnostics)
	dst.CookieHttpOnly = src.CookieHTTPOnly.ValueBoolPointer()
	dst.CookieName = src.CookieName.ValueStringPointer()
	dst.CookieSameSite = src.CookieSameSite.ValueStringPointer()
	dst.CookieSecret = src.CookieSecret.ValueStringPointer()
	dst.CookieSecure = src.CookieSecure.ValueBoolPointer()
	dst.DarkmodePrimaryColor = src.DarkmodePrimaryColor.ValueStringPointer()
	dst.DarkmodeSecondaryColor = src.DarkmodeSecondaryColor.ValueStringPointer()
	dst.DatabrokerServiceUrl = src.DatabrokerServiceURL.ValueStringPointer()
	ToDuration(&dst.DefaultUpstreamTimeout, src.DefaultUpstreamTimeout, c.diagnostics)
	ToDuration(&dst.DnsFailureRefreshRate, src.DNSFailureRefreshRate, c.diagnostics)
	dst.DnsLookupFamily = src.DNSLookupFamily.ValueStringPointer()
	ToDuration(&dst.DnsQueryTimeout, src.DNSQueryTimeout, c.diagnostics)
	dst.DnsQueryTries = FromInt64Pointer[uint32](src.DNSQueryTries)
	ToDuration(&dst.DnsRefreshRate, src.DNSRefreshRate, c.diagnostics)
	dst.DnsUdpMaxQueries = FromInt64Pointer[uint32](src.DNSUDPMaxQueries)
	dst.DnsUseTcp = src.DNSUseTCP.ValueBoolPointer()
	dst.ErrorMessageFirstParagraph = src.ErrorMessageFirstParagraph.ValueStringPointer()
	dst.FaviconUrl = src.FaviconURL.ValueStringPointer()
	dst.GoogleCloudServerlessAuthenticationServiceAccount = src.GoogleCloudServerlessAuthenticationServiceAccount.ValueStringPointer()
	dst.GrpcAddress = src.GRPCAddress.ValueStringPointer()
	dst.GrpcInsecure = src.GRPCInsecure.ValueBoolPointer()
	dst.HttpRedirectAddr = src.HTTPRedirectAddr.ValueStringPointer()
	dst.Id = src.ID.ValueString()
	IdentityProviderSettingsToPB(context.Background(), dst, &src, c.diagnostics)
	ToDuration(&dst.IdentityProviderRefreshInterval, src.IdentityProviderRefreshInterval, c.diagnostics)
	ToDuration(&dst.IdentityProviderRefreshTimeout, src.IdentityProviderRefreshTimeout, c.diagnostics)
	ToSettingsStringList(context.Background(), &dst.IdpAccessTokenAllowedAudiences, src.IDPAccessTokenAllowedAudiences, c.diagnostics)
	dst.IdpClientId = src.IdpClientID.ValueStringPointer()
	dst.IdpClientSecret = src.IdpClientSecret.ValueStringPointer()
	dst.IdpProvider = src.IdpProvider.ValueStringPointer()
	dst.IdpProviderUrl = src.IdpProviderURL.ValueStringPointer()
	ToDuration(&dst.IdpRefreshDirectoryInterval, src.IdpRefreshDirectoryInterval, c.diagnostics)
	ToDuration(&dst.IdpRefreshDirectoryTimeout, src.IdpRefreshDirectoryTimeout, c.diagnostics)
	dst.IdpServiceAccount = src.IdpServiceAccount.ValueStringPointer()
	dst.InsecureServer = src.InsecureServer.ValueBoolPointer()
	dst.InstallationId = src.InstallationID.ValueStringPointer()
	ToStringMap(context.Background(), &dst.JwtClaimsHeaders, src.JWTClaimsHeaders, c.diagnostics)
	dst.JwtIssuerFormat = ToIssuerFormat(src.JWTIssuerFormat, c.diagnostics)
	dst.LogLevel = src.LogLevel.ValueStringPointer()
	dst.LogoUrl = src.LogoURL.ValueStringPointer()
	dst.MetricsAddress = src.MetricsAddress.ValueStringPointer()
	dst.OriginatorId = OriginatorID
	dst.PassIdentityHeaders = src.PassIdentityHeaders.ValueBoolPointer()
	dst.PrimaryColor = src.PrimaryColor.ValueStringPointer()
	dst.ProxyLogLevel = src.ProxyLogLevel.ValueStringPointer()
	ToStringMap(context.Background(), &dst.RequestParams, src.RequestParams, c.diagnostics)
	ToStringSliceFromSet(context.Background(), &dst.Scopes, src.Scopes, c.diagnostics)
	dst.SecondaryColor = src.SecondaryColor.ValueStringPointer()
	ToStringMap(context.Background(), &dst.SetResponseHeaders, src.SetResponseHeaders, c.diagnostics)
	dst.SkipXffAppend = src.SkipXFFAppend.ValueBoolPointer()
	dst.SshAddress = src.SSHAddress.ValueStringPointer()
	ToSettingsStringList(context.Background(), &dst.SshHostKeyFiles, src.SSHHostKeyFiles, c.diagnostics)
	ToSettingsStringList(context.Background(), &dst.SshHostKeys, src.SSHHostKeys, c.diagnostics)
	dst.SshUserCaKey = src.SSHUserCAKey.ValueStringPointer()
	dst.SshUserCaKeyFile = src.SSHUserCAKeyFile.ValueStringPointer()
	ToDuration(&dst.TimeoutIdle, src.TimeoutIdle, c.diagnostics)
	ToDuration(&dst.TimeoutRead, src.TimeoutRead, c.diagnostics)
	ToDuration(&dst.TimeoutWrite, src.TimeoutWrite, c.diagnostics)
	dst.JwtGroupsFilter = NewModelToEnterpriseConverter(c.diagnostics).JWTGroupsFilter(src.JWTGroupsFilter)

	dst.OtelTracesExporter = src.OtelTracesExporter.ValueStringPointer()
	dst.OtelTracesSamplerArg = src.OtelTracesSamplerArg.ValueFloat64Pointer()
	ToStringSliceFromSet(context.Background(), &dst.OtelResourceAttributes, src.OtelResourceAttributes, c.diagnostics)
	dst.OtelLogLevel = src.OtelLogLevel.ValueStringPointer()
	dst.OtelAttributeValueLengthLimit = FromInt64Pointer[int32](src.OtelAttributeValueLengthLimit)
	dst.OtelExporterOtlpEndpoint = src.OtelExporterOtlpEndpoint.ValueStringPointer()
	dst.OtelExporterOtlpTracesEndpoint = src.OtelExporterOtlpTracesEndpoint.ValueStringPointer()
	dst.OtelExporterOtlpProtocol = src.OtelExporterOtlpProtocol.ValueStringPointer()
	dst.OtelExporterOtlpTracesProtocol = src.OtelExporterOtlpTracesProtocol.ValueStringPointer()
	ToStringSliceFromSet(context.Background(), &dst.OtelExporterOtlpHeaders, src.OtelExporterOtlpHeaders, c.diagnostics)
	ToStringSliceFromSet(context.Background(), &dst.OtelExporterOtlpTracesHeaders, src.OtelExporterOtlpTracesHeaders, c.diagnostics)
	ToDuration(&dst.OtelExporterOtlpTimeout, src.OtelExporterOtlpTimeout, c.diagnostics)
	ToDuration(&dst.OtelExporterOtlpTracesTimeout, src.OtelExporterOtlpTracesTimeout, c.diagnostics)
	ToDuration(&dst.OtelBspScheduleDelay, src.OtelBspScheduleDelay, c.diagnostics)
	dst.OtelBspMaxExportBatchSize = FromInt64Pointer[int32](src.OtelBspMaxExportBatchSize)

	return dst
}

func (c *ModelToEnterpriseConverter) StringMap(p path.Path, src types.Map) map[string]string {
	if src.IsNull() || src.IsUnknown() {
		return nil
	}

	dst := make(map[string]string)
	appendAttributeDiagnostics(c.diagnostics, p, src.ElementsAs(context.Background(), &dst, false)...)
	return dst
}

func (c *ModelToEnterpriseConverter) StringSliceFromList(p path.Path, src types.List) []string {
	var dst []string
	appendAttributeDiagnostics(c.diagnostics, p, src.ElementsAs(context.Background(), &dst, false)...)
	return dst
}

func (c *ModelToEnterpriseConverter) StringSliceFromSet(p path.Path, src types.Set) []string {
	var dst []string
	appendAttributeDiagnostics(c.diagnostics, p, src.ElementsAs(context.Background(), &dst, false)...)
	return dst
}

func (c *ModelToEnterpriseConverter) Timestamp(p path.Path, src types.String) *timestamppb.Timestamp {
	if src.IsNull() || src.IsUnknown() || src.ValueString() == "" {
		return nil
	}

	tm, err := time.Parse(time.RFC1123, src.ValueString())
	if err != nil {
		appendAttributeDiagnostics(c.diagnostics, p, diag.NewErrorDiagnostic("error parsing timestamp", err.Error()))
		return nil
	}

	return timestamppb.New(tm)
}

func (c *ModelToEnterpriseConverter) UpdateKeyPairRequest(src KeyPairModel) *enterprise.UpdateKeyPairRequest {
	return &enterprise.UpdateKeyPairRequest{
		Certificate:  []byte(src.Certificate.ValueString()),
		Format:       enterprise.Format_PEM.Enum(),
		Id:           src.ID.ValueString(),
		Key:          []byte(src.Key.ValueString()),
		Name:         c.NullableString(src.Name),
		OriginatorId: OriginatorID,
	}
}
