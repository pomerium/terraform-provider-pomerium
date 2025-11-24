package provider

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework-timetypes/timetypes"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/pomerium/enterprise-client-go/pb"
)

// ExternalDataSourceModel represents the shared model for external data source resources and data sources
type ExternalDataSourceModel struct {
	ID               types.String         `tfsdk:"id"`
	URL              types.String         `tfsdk:"url"`
	RecordType       types.String         `tfsdk:"record_type"`
	ForeignKey       types.String         `tfsdk:"foreign_key"`
	Headers          types.Map            `tfsdk:"headers"`
	AllowInsecureTLS types.Bool           `tfsdk:"allow_insecure_tls"`
	ClientTLSKeyID   types.String         `tfsdk:"client_tls_key_id"`
	ClusterID        types.String         `tfsdk:"cluster_id"`
	PollingMinDelay  timetypes.GoDuration `tfsdk:"polling_min_delay"`
	PollingMaxDelay  timetypes.GoDuration `tfsdk:"polling_max_delay"`
}

func ConvertExternalDataSourceToPB(
	ctx context.Context,
	src *ExternalDataSourceModel,
) (*pb.ExternalDataSource, diag.Diagnostics) {
	dst := new(pb.ExternalDataSource)
	var diagnostics diag.Diagnostics

	dst.Id = src.ID.ValueString()
	dst.Url = src.URL.ValueString()
	dst.RecordType = src.RecordType.ValueString()
	dst.ForeignKey = src.ForeignKey.ValueString()
	ToStringMap(ctx, &dst.Headers, src.Headers, &diagnostics)
	dst.AllowInsecureTls = src.AllowInsecureTLS.ValueBoolPointer()
	dst.ClientTlsKeyId = src.ClientTLSKeyID.ValueStringPointer()
	dst.ClusterId = src.ClusterID.ValueStringPointer()
	ToDuration(&dst.PollingMinDelay, src.PollingMinDelay, &diagnostics)
	ToDuration(&dst.PollingMaxDelay, src.PollingMaxDelay, &diagnostics)
	dst.OriginatorId = OriginatorID

	return dst, diagnostics
}

func ConvertExternalDataSourceFromPB(
	dst *ExternalDataSourceModel,
	src *pb.ExternalDataSource,
) diag.Diagnostics {
	dst.ID = types.StringValue(src.Id)
	dst.URL = types.StringValue(src.Url)
	dst.RecordType = types.StringValue(src.RecordType)
	dst.ForeignKey = types.StringValue(src.ForeignKey)
	dst.Headers = FromStringMap(src.Headers)
	dst.AllowInsecureTLS = types.BoolPointerValue(src.AllowInsecureTls)
	dst.ClientTLSKeyID = types.StringPointerValue(src.ClientTlsKeyId)
	dst.ClusterID = types.StringPointerValue(src.ClusterId)
	dst.PollingMinDelay = FromDuration(src.PollingMinDelay)
	dst.PollingMaxDelay = FromDuration(src.PollingMaxDelay)

	return nil
}
