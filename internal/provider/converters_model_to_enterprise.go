package provider

import (
	"context"
	"encoding/base64"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework-timetypes/timetypes"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-framework/types/basetypes"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/structpb"

	enterprise "github.com/pomerium/enterprise-client-go/pb"
)

type ModelToEnterpriseConverter struct {
	baseModelConverter
	diagnostics *diag.Diagnostics
}

func NewModelToEnterpriseConverter(diagnostics *diag.Diagnostics) *ModelToEnterpriseConverter {
	return &ModelToEnterpriseConverter{
		baseModelConverter: baseModelConverter{diagnostics: diagnostics},
		diagnostics:        diagnostics,
	}
}

func (c *ModelToEnterpriseConverter) BearerTokenFormat(p path.Path, src types.String) *enterprise.BearerTokenFormat {
	if src.IsNull() || src.IsUnknown() {
		return nil
	}

	switch src.ValueString() {
	case "default":
		return enterprise.BearerTokenFormat_BEARER_TOKEN_FORMAT_DEFAULT.Enum()
	case "idp_access_token":
		return enterprise.BearerTokenFormat_BEARER_TOKEN_FORMAT_IDP_ACCESS_TOKEN.Enum()
	case "idp_identity_token":
		return enterprise.BearerTokenFormat_BEARER_TOKEN_FORMAT_IDP_IDENTITY_TOKEN.Enum()
	case "":
		fallthrough
	default:
		c.diagnostics.AddAttributeError(p, "unknown bearer token format", fmt.Sprintf("unknown bearer token format: %s", src.ValueString()))
		return nil
	}
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
	if src.IsNull() || src.IsUnknown() {
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
				httpHealthCheck.ExpectedStatuses = append(httpHealthCheck.ExpectedStatuses, c.Int64Range(obj))
			}
		}

		if !retriableStatuses.IsNull() {
			for _, elem := range retriableStatuses.Elements() {
				obj := elem.(types.Object)
				httpHealthCheck.RetriableStatuses = append(httpHealthCheck.RetriableStatuses, c.Int64Range(obj))
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
			tcpHealthCheck.Send = c.HealthCheckPayload(send)
		}

		if !receive.IsNull() {
			for _, elem := range receive.Elements() {
				obj := elem.(types.Object)
				tcpHealthCheck.Receive = append(tcpHealthCheck.Receive, c.HealthCheckPayload(obj))
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

func (c *ModelToEnterpriseConverter) HealthCheckPayload(src types.Object) *enterprise.HealthCheck_Payload {
	if src.IsNull() || src.IsUnknown() {
		return nil
	}

	attrs := src.Attributes()
	payload := new(enterprise.HealthCheck_Payload)

	text := attrs["text"].(types.String)
	binaryB64 := attrs["binary_b64"].(types.String)

	if !text.IsNull() {
		payload.Payload = &enterprise.HealthCheck_Payload_Text{
			Text: text.ValueString(),
		}
	} else if !binaryB64.IsNull() {
		binaryData, err := base64.StdEncoding.DecodeString(binaryB64.ValueString())
		if err != nil {
			c.diagnostics.AddError("Invalid base64 data", "Could not decode base64 binary payload: "+err.Error())
			return nil
		}
		payload.Payload = &enterprise.HealthCheck_Payload_Binary{
			Binary: binaryData,
		}
	}

	return payload
}

func (c *ModelToEnterpriseConverter) IdentityProvider(src SettingsModel) *string {
	if !src.IdentityProviderAuth0.IsNull() && !src.IdentityProviderAuth0.IsUnknown() {
		return proto.String("auth0")
	}
	if !src.IdentityProviderAzure.IsNull() && !src.IdentityProviderAzure.IsUnknown() {
		return proto.String("azure")
	}
	if !src.IdentityProviderBlob.IsNull() && !src.IdentityProviderBlob.IsUnknown() {
		return proto.String("blob")
	}
	if !src.IdentityProviderCognito.IsNull() && !src.IdentityProviderCognito.IsUnknown() {
		return proto.String("cognito")
	}
	if !src.IdentityProviderGitHub.IsNull() && !src.IdentityProviderGitHub.IsUnknown() {
		return proto.String("github")
	}
	if !src.IdentityProviderGitLab.IsNull() && !src.IdentityProviderGitLab.IsUnknown() {
		return proto.String("gitlab")
	}
	if !src.IdentityProviderGoogle.IsNull() && !src.IdentityProviderGoogle.IsUnknown() {
		return proto.String("google")
	}
	if !src.IdentityProviderOkta.IsNull() && !src.IdentityProviderOkta.IsUnknown() {
		return proto.String("okta")
	}
	if !src.IdentityProviderOneLogin.IsNull() && !src.IdentityProviderOneLogin.IsUnknown() {
		return proto.String("onelogin")
	}
	if !src.IdentityProviderPing.IsNull() && !src.IdentityProviderPing.IsUnknown() {
		return proto.String("ping")
	}
	return nil
}

func (c *ModelToEnterpriseConverter) IdentityProviderOptions(src SettingsModel) *structpb.Struct {
	if !src.IdentityProviderAuth0.IsNull() && !src.IdentityProviderAuth0.IsUnknown() {
		return idpOptionsToStruct[Auth0Options](c.diagnostics, src.IdentityProviderAuth0)
	}
	if !src.IdentityProviderAzure.IsNull() && !src.IdentityProviderAzure.IsUnknown() {
		return idpOptionsToStruct[AzureOptions](c.diagnostics, src.IdentityProviderAzure)
	}
	if !src.IdentityProviderBlob.IsNull() && !src.IdentityProviderBlob.IsUnknown() {
		return idpOptionsToStruct[BlobOptions](c.diagnostics, src.IdentityProviderBlob)
	}
	if !src.IdentityProviderCognito.IsNull() && !src.IdentityProviderCognito.IsUnknown() {
		return idpOptionsToStruct[CognitoOptions](c.diagnostics, src.IdentityProviderCognito)
	}
	if !src.IdentityProviderGitHub.IsNull() && !src.IdentityProviderGitHub.IsUnknown() {
		return idpOptionsToStruct[GitHubOptions](c.diagnostics, src.IdentityProviderGitHub)
	}
	if !src.IdentityProviderGitLab.IsNull() && !src.IdentityProviderGitLab.IsUnknown() {
		return idpOptionsToStruct[GitLabOptions](c.diagnostics, src.IdentityProviderGitLab)
	}
	if !src.IdentityProviderGoogle.IsNull() && !src.IdentityProviderGoogle.IsUnknown() {
		return idpOptionsToStruct[GoogleOptions](c.diagnostics, src.IdentityProviderGoogle)
	}
	if !src.IdentityProviderOkta.IsNull() && !src.IdentityProviderOkta.IsUnknown() {
		return idpOptionsToStruct[OktaOptions](c.diagnostics, src.IdentityProviderOkta)
	}
	if !src.IdentityProviderOneLogin.IsNull() && !src.IdentityProviderOneLogin.IsUnknown() {
		return idpOptionsToStruct[OneLoginOptions](c.diagnostics, src.IdentityProviderOneLogin)
	}
	if !src.IdentityProviderPing.IsNull() && !src.IdentityProviderPing.IsUnknown() {
		return idpOptionsToStruct[PingOptions](c.diagnostics, src.IdentityProviderPing)
	}
	return nil
}

func (c *ModelToEnterpriseConverter) Int64Range(src types.Object) *enterprise.Int64Range {
	if src.IsNull() || src.IsUnknown() {
		return nil
	}

	attrs := src.Attributes()
	return &enterprise.Int64Range{
		Start: attrs["start"].(types.Int64).ValueInt64(),
		End:   attrs["end"].(types.Int64).ValueInt64(),
	}
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
		ParentId:     src.ParentID.ValueString(),
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
		BearerTokenFormat:        c.BearerTokenFormat(path.Root("bearer_token_format"), src.BearerTokenFormat),
		CircuitBreakerThresholds: c.CircuitBreakerThresholds(src.CircuitBreakerThresholds),
		DependsOn:                c.StringSliceFromSet(path.Root("depends_on"), src.DependsOnHosts),
		Description:              src.Description.ValueStringPointer(),
		EnableGoogleCloudServerlessAuthentication: src.EnableGoogleCloudServerlessAuthentication.ValueBool(),
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
		RewriteResponseHeaders:            fromSetOfObjects(src.RewriteResponseHeaders, RewriteHeaderObjectType(), c.RouteRewriteHeader),
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

func (c *ModelToEnterpriseConverter) RouteRewriteHeader(src types.Object) *enterprise.RouteRewriteHeader {
	if src.IsNull() || src.IsUnknown() {
		return nil
	}

	prefixAttr := src.Attributes()["prefix"].(types.String)
	dst := &enterprise.RouteRewriteHeader{
		Header: src.Attributes()["header"].(types.String).ValueString(),
		Value:  src.Attributes()["value"].(types.String).ValueString(),
	}
	if !prefixAttr.IsNull() && prefixAttr.ValueString() != "" {
		dst.Matcher = &enterprise.RouteRewriteHeader_Prefix{Prefix: prefixAttr.ValueString()}
	}
	return dst
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
	return &enterprise.Settings{
		AccessLogFields:               c.SettingsStringList(path.Root("access_log_fields"), src.AccessLogFields),
		Address:                       src.Address.ValueStringPointer(),
		AuthenticateServiceUrl:        src.AuthenticateServiceURL.ValueStringPointer(),
		AuthorizeLogFields:            c.SettingsStringList(path.Root("authorize_log_fields"), src.AuthorizeLogFields),
		AuthorizeServiceUrl:           src.AuthorizeServiceURL.ValueStringPointer(),
		Autocert:                      src.Autocert.ValueBoolPointer(),
		AutocertDir:                   src.AutocertDir.ValueStringPointer(),
		AutocertMustStaple:            src.AutocertMustStaple.ValueBoolPointer(),
		AutocertUseStaging:            src.AutocertUseStaging.ValueBoolPointer(),
		BearerTokenFormat:             c.BearerTokenFormat(path.Root("bearer_token_format"), src.BearerTokenFormat),
		CacheServiceUrl:               src.CacheServiceURL.ValueStringPointer(),
		CertificateAuthority:          src.CertificateAuthority.ValueStringPointer(),
		CertificateAuthorityFile:      src.CertificateAuthorityFile.ValueStringPointer(),
		CertificateAuthorityKeyPairId: src.CertificateAuthorityKeyPairID.ValueStringPointer(),
		CircuitBreakerThresholds:      c.CircuitBreakerThresholds(src.CircuitBreakerThresholds),
		ClientCa:                      src.ClientCA.ValueStringPointer(),
		ClientCaFile:                  src.ClientCAFile.ValueStringPointer(),
		ClientCaKeyPairId:             src.ClientCAKeyPairID.ValueStringPointer(),
		ClusterId:                     src.ClusterID.ValueStringPointer(),
		CodecType:                     ToCodecType(src.CodecType),
		CookieDomain:                  src.CookieDomain.ValueStringPointer(),
		CookieExpire:                  c.Duration(path.Root("cookie_expire"), src.CookieExpire),
		CookieHttpOnly:                src.CookieHTTPOnly.ValueBoolPointer(),
		CookieName:                    src.CookieName.ValueStringPointer(),
		CookieSameSite:                src.CookieSameSite.ValueStringPointer(),
		CookieSecret:                  src.CookieSecret.ValueStringPointer(),
		CookieSecure:                  src.CookieSecure.ValueBoolPointer(),
		DarkmodePrimaryColor:          src.DarkmodePrimaryColor.ValueStringPointer(),
		DarkmodeSecondaryColor:        src.DarkmodeSecondaryColor.ValueStringPointer(),
		DatabrokerServiceUrl:          src.DatabrokerServiceURL.ValueStringPointer(),
		DefaultUpstreamTimeout:        c.Duration(path.Root("default_upstream_timeout"), src.DefaultUpstreamTimeout),
		DnsFailureRefreshRate:         c.Duration(path.Root("dns_failure_refresh_rate"), src.DNSFailureRefreshRate),
		DnsLookupFamily:               src.DNSLookupFamily.ValueStringPointer(),
		DnsQueryTimeout:               c.Duration(path.Root("dns_query_timeout"), src.DNSQueryTimeout),
		DnsQueryTries:                 c.NullableUint32(src.DNSQueryTries),
		DnsRefreshRate:                c.Duration(path.Root("dns_refresh_rate"), src.DNSRefreshRate),
		DnsUdpMaxQueries:              c.NullableUint32(src.DNSUDPMaxQueries),
		DnsUseTcp:                     src.DNSUseTCP.ValueBoolPointer(),
		ErrorMessageFirstParagraph:    src.ErrorMessageFirstParagraph.ValueStringPointer(),
		FaviconUrl:                    src.FaviconURL.ValueStringPointer(),
		GoogleCloudServerlessAuthenticationServiceAccount: src.GoogleCloudServerlessAuthenticationServiceAccount.ValueStringPointer(),
		GrpcAddress:                     src.GRPCAddress.ValueStringPointer(),
		GrpcInsecure:                    src.GRPCInsecure.ValueBoolPointer(),
		HttpRedirectAddr:                src.HTTPRedirectAddr.ValueStringPointer(),
		Id:                              src.ID.ValueString(),
		IdentityProvider:                c.IdentityProvider(src),
		IdentityProviderOptions:         c.IdentityProviderOptions(src),
		IdentityProviderRefreshInterval: c.Duration(path.Root("identity_provider_refresh_interval"), src.IdentityProviderRefreshInterval),
		IdentityProviderRefreshTimeout:  c.Duration(path.Root("identity_provider_refresh_timeout"), src.IdentityProviderRefreshTimeout),
		IdpAccessTokenAllowedAudiences:  c.SettingsStringList(path.Root("idp_access_token_allowed_audiences"), src.IDPAccessTokenAllowedAudiences),
		IdpClientId:                     src.IdpClientID.ValueStringPointer(),
		IdpClientSecret:                 src.IdpClientSecret.ValueStringPointer(),
		IdpProvider:                     src.IdpProvider.ValueStringPointer(),
		IdpProviderUrl:                  src.IdpProviderURL.ValueStringPointer(),
		IdpRefreshDirectoryInterval:     c.Duration(path.Root("idp_refresh_directory_interval"), src.IdpRefreshDirectoryInterval),
		IdpRefreshDirectoryTimeout:      c.Duration(path.Root("idp_refresh_directory_timeout"), src.IdpRefreshDirectoryTimeout),
		IdpServiceAccount:               src.IdpServiceAccount.ValueStringPointer(),
		InsecureServer:                  src.InsecureServer.ValueBoolPointer(),
		InstallationId:                  src.InstallationID.ValueStringPointer(),
		JwtClaimsHeaders:                c.StringMap(path.Root("jwt_claims_headers"), src.JWTClaimsHeaders),
		JwtGroupsFilter:                 c.JWTGroupsFilter(src.JWTGroupsFilter),
		JwtIssuerFormat:                 ToIssuerFormat(src.JWTIssuerFormat, c.diagnostics),
		LogLevel:                        src.LogLevel.ValueStringPointer(),
		LogoUrl:                         src.LogoURL.ValueStringPointer(),
		MetricsAddress:                  src.MetricsAddress.ValueStringPointer(),
		OriginatorId:                    OriginatorID,
		OtelAttributeValueLengthLimit:   c.NullableInt32(src.OtelAttributeValueLengthLimit),
		OtelBspMaxExportBatchSize:       c.NullableInt32(src.OtelBspMaxExportBatchSize),
		OtelBspScheduleDelay:            c.Duration(path.Root("otel_bsp_schedule_delay"), src.OtelBspScheduleDelay),
		OtelExporterOtlpEndpoint:        src.OtelExporterOtlpEndpoint.ValueStringPointer(),
		OtelExporterOtlpHeaders:         c.StringSliceFromSet(path.Root("otel_exporter_otlp_headers"), src.OtelExporterOtlpHeaders),
		OtelExporterOtlpProtocol:        src.OtelExporterOtlpProtocol.ValueStringPointer(),
		OtelExporterOtlpTimeout:         c.Duration(path.Root("otel_exporter_otlp_timeout"), src.OtelExporterOtlpTimeout),
		OtelExporterOtlpTracesEndpoint:  src.OtelExporterOtlpTracesEndpoint.ValueStringPointer(),
		OtelExporterOtlpTracesHeaders:   c.StringSliceFromSet(path.Root("otel_exporter_otlp_traces_headers"), src.OtelExporterOtlpTracesHeaders),
		OtelExporterOtlpTracesProtocol:  src.OtelExporterOtlpTracesProtocol.ValueStringPointer(),
		OtelExporterOtlpTracesTimeout:   c.Duration(path.Root("otel_exporter_otlp_traces_timeout"), src.OtelExporterOtlpTracesTimeout),
		OtelLogLevel:                    src.OtelLogLevel.ValueStringPointer(),
		OtelResourceAttributes:          c.StringSliceFromSet(path.Root("otel_resource_attributes"), src.OtelResourceAttributes),
		OtelTracesExporter:              src.OtelTracesExporter.ValueStringPointer(),
		OtelTracesSamplerArg:            src.OtelTracesSamplerArg.ValueFloat64Pointer(),
		PassIdentityHeaders:             src.PassIdentityHeaders.ValueBoolPointer(),
		PrimaryColor:                    src.PrimaryColor.ValueStringPointer(),
		ProxyLogLevel:                   src.ProxyLogLevel.ValueStringPointer(),
		RequestParams:                   c.StringMap(path.Root("request_params"), src.RequestParams),
		Scopes:                          c.StringSliceFromSet(path.Root("scopes"), src.Scopes),
		SecondaryColor:                  src.SecondaryColor.ValueStringPointer(),
		SetResponseHeaders:              c.StringMap(path.Root("set_response_headers"), src.SetResponseHeaders),
		SkipXffAppend:                   src.SkipXFFAppend.ValueBoolPointer(),
		SshAddress:                      src.SSHAddress.ValueStringPointer(),
		SshHostKeyFiles:                 c.SettingsStringList(path.Root("ssh_host_key_files"), src.SSHHostKeyFiles),
		SshHostKeys:                     c.SettingsStringList(path.Root("ssh_host_keys"), src.SSHHostKeys),
		SshUserCaKey:                    src.SSHUserCAKey.ValueStringPointer(),
		SshUserCaKeyFile:                src.SSHUserCAKeyFile.ValueStringPointer(),
		TimeoutIdle:                     c.Duration(path.Root("timeout_idle"), src.TimeoutIdle),
		TimeoutRead:                     c.Duration(path.Root("timeout_read"), src.TimeoutRead),
		TimeoutWrite:                    c.Duration(path.Root("timeout_write"), src.TimeoutWrite),
	}
}

func (c *ModelToEnterpriseConverter) SettingsStringList(p path.Path, src types.Set) *enterprise.Settings_StringList {
	if src.IsNull() || src.IsUnknown() {
		return nil
	}
	var values []string
	appendAttributeDiagnostics(c.diagnostics, p, src.ElementsAs(context.Background(), &values, false)...)
	return &enterprise.Settings_StringList{Values: values}
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
