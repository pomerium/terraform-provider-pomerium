package provider

import (
	"context"

	"github.com/google/uuid"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	client "github.com/pomerium/enterprise-client-go"
	"github.com/pomerium/enterprise-client-go/pb"
	"github.com/pomerium/sdk-go"
)

type ClusterResourceModel = ClusterModel

// A ClusterResource manages clusters.
type ClusterResource struct {
	client *Client
}

// NewClusterResource creates a new clusters resource.
func NewClusterResource() resource.Resource {
	return &ClusterResource{}
}

func (r *ClusterResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_cluster"
}

func (r *ClusterResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Cluster for Pomerium.",
		Attributes: map[string]schema.Attribute{
			"parent_namespace_id": schema.StringAttribute{
				Optional:    true,
				Computed:    true,
				Description: "Parent namespace of the cluster.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"namespace_id": schema.StringAttribute{
				Computed:    true,
				Description: "Namespace ID for the cluster.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"id": schema.StringAttribute{
				Computed:    true,
				Description: "Unique identifier for the cluster.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"name": schema.StringAttribute{
				Required:    true,
				Description: "Name for the cluster.",
			},
			"databroker_service_url": schema.StringAttribute{
				Optional:    true,
				Description: "Databroker service url for the cluster.",
			},
			"shared_secret_b64": schema.StringAttribute{
				Optional:    true,
				Sensitive:   true,
				Description: "Shared secret for the cluster as base64.",
			},
			"insecure_skip_verify": schema.BoolAttribute{
				Optional:    true,
				Description: "Skip verification of TLS certificates for the cluster.",
			},
			"override_certificate_name": schema.StringAttribute{
				Optional:    true,
				Description: "Override the certificate name for TLS verification for the cluster.",
			},
			"certificate_authority_b64": schema.StringAttribute{
				Optional:    true,
				Description: "Certificate authority for the cluster as base64.",
			},
			"certificate_authority_file": schema.StringAttribute{
				Optional:    true,
				Description: "Certificate authority file for the cluster",
			},
			"domain": schema.StringAttribute{
				Optional:    true,
				Computed:    true,
				Description: "Domain name of the cluster.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplaceIfConfigured(),
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"flavor": schema.StringAttribute{
				Optional:    true,
				Computed:    true,
				Description: "Flavor of the cluster.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"fqdn": schema.StringAttribute{
				Computed:    true,
				Description: "Fully-qualified domain name of the cluster.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"manual_override_ip_address": schema.StringAttribute{
				Optional:    true,
				Description: "Manual override for the cluster ip address.",
			},
		},
	}
}

func (r *ClusterResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	r.client = ConfigureClient(req, resp)
}

func (r *ClusterResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan ClusterResourceModel

	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	if plan.ParentNamespaceID.IsNull() || plan.ParentNamespaceID.IsUnknown() {
		plan.ParentNamespaceID = types.StringValue(GlobalNamespaceID)
	}

	resp.Diagnostics.Append(r.client.ByServerType(
		func(client sdk.CoreClient) {
			if plan.ID.IsNull() || plan.ID.IsUnknown() {
				plan.ID = types.StringValue(uuid.NewString())
			}
			if plan.NamespaceID.IsNull() || plan.NamespaceID.IsUnknown() {
				plan.NamespaceID = types.StringValue(uuid.NewString())
			}

			cluster := NewModelToCoreConverter(&resp.Diagnostics).Cluster(plan)
			if resp.Diagnostics.HasError() {
				return
			}

			namespace := NewModelToCoreConverter(&resp.Diagnostics).Namespace(NamespaceModel{
				ClusterID: plan.ID,
				ID:        plan.NamespaceID,
				Name:      plan.Name,
				ParentID:  plan.ParentNamespaceID,
			})
			if resp.Diagnostics.HasError() {
				return
			}

			err := databrokerPut(ctx, client, RecordTypeCluster, plan.ID.ValueString(), cluster)
			if err != nil {
				resp.Diagnostics.AddError("error creating cluster", err.Error())
				return
			}

			err = databrokerPut(ctx, client, RecordTypeNamespace, plan.NamespaceID.ValueString(), namespace)
			if err != nil {
				resp.Diagnostics.AddError("error creating cluster namespace", err.Error())
				return
			}

			plan = NewCoreToModelConverter(&resp.Diagnostics).Cluster(cluster)
		},
		func(client *client.Client) {
			pbCluster := NewModelToEnterpriseConverter(&resp.Diagnostics).Cluster(plan)
			if resp.Diagnostics.HasError() {
				return
			}

			checkUnsupportedProperties(serverTypeEnterprise, &resp.Diagnostics, []unsupportedProperty{
				{"domain", plan.Domain},
				{"manual_override_ip_address", plan.ManualOverrideIPAddress},
			})
			if resp.Diagnostics.HasError() {
				return
			}

			addReq := &pb.AddClusterRequest{
				ParentNamespaceId: plan.ParentNamespaceID.ValueString(),
				Cluster:           pbCluster,
			}
			addRes, err := client.ClustersService.AddCluster(ctx, addReq)
			if err != nil {
				resp.Diagnostics.AddError("Error creating cluster", err.Error())
				return
			}

			plan.NamespaceID = types.StringValue(addRes.Namespace.Id)
			plan.ParentNamespaceID = types.StringValue(addRes.Namespace.ParentId)
			plan.ID = types.StringValue(addRes.Cluster.Id)
		},
		func(client sdk.ZeroClient) {
			organizationID, err := getZeroOrganizationID(ctx, client)
			if err != nil {
				resp.Diagnostics.AddError(err.Error(), err.Error())
				return
			}

			checkUnsupportedProperties(serverTypeZero, &resp.Diagnostics, []unsupportedProperty{
				{"certificate_authority_b64", plan.CertificateAuthorityB64},
				{"certificate_authority_file", plan.CertificateAuthorityFile},
				{"databroker_service_url", plan.DatabrokerServiceURL},
				{"insecure_skip_verify", plan.InsecureSkipVerify},
				{"override_certificate_name", plan.OverrideCertificateName},
				{"shared_secret_b64", plan.SharedSecretB64},
			})
			if resp.Diagnostics.HasError() {
				return
			}

			if plan.Domain.IsNull() || plan.Domain.IsUnknown() {
				generateRes, err := client.GenerateSubdomainNameWithResponse(ctx)
				if err != nil {
					resp.Diagnostics.AddError("error generating subdomain for cluster", err.Error())
					return
				} else if generateRes.JSON200 == nil || generateRes.JSON200.Name == "" {
					addZeroResponseError(&resp.Diagnostics, generateRes.Body, generateRes.HTTPResponse)
					return
				}
				plan.Domain = types.StringValue(generateRes.JSON200.Name)
			}

			createReq := NewModelToZeroConverter(&resp.Diagnostics).CreateClusterRequest(plan)
			if resp.Diagnostics.HasError() {
				return
			}

			createRes, err := client.CreateClusterWithResponse(ctx, organizationID, createReq)
			if err != nil {
				resp.Diagnostics.AddError("error creating cluster", err.Error())
				return
			} else if createRes.JSON201 == nil {
				addZeroResponseError(&resp.Diagnostics, createRes.Body, createRes.HTTPResponse)
				return
			}

			cluster, namespace := getZeroCluster(ctx, client, &resp.Diagnostics, organizationID, createRes.JSON201.Id)
			if resp.Diagnostics.HasError() {
				return
			}

			plan = NewZeroToModelConverter(&resp.Diagnostics).Cluster(cluster, namespace)
		})...)
	if resp.Diagnostics.HasError() {
		return
	}

	tflog.Trace(ctx, "Created a cluster", map[string]any{
		"id":   plan.ID.ValueString(),
		"name": plan.Name.ValueString(),
	})

	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *ClusterResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state ClusterResourceModel

	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(r.client.ByServerType(
		func(client sdk.CoreClient) {
			data, err := databrokerGet(ctx, client, RecordTypeCluster, state.ID.ValueString())
			if status.Code(err) == codes.NotFound {
				resp.State.RemoveResource(ctx)
				return
			} else if err != nil {
				resp.Diagnostics.AddError("error reading cluster", err.Error())
				return
			}

			state = NewCoreToModelConverter(&resp.Diagnostics).Cluster(data)
		},
		func(client *client.Client) {
			getReq := &pb.GetClusterRequest{
				Id: state.ID.ValueString(),
			}
			getRes, err := client.ClustersService.GetCluster(ctx, getReq)
			if err != nil {
				if status.Code(err) == codes.NotFound {
					resp.State.RemoveResource(ctx)
					return
				}
				resp.Diagnostics.AddError("Error reading cluster", err.Error())
				return
			}

			state = NewEnterpriseToModelConverter(&resp.Diagnostics).Cluster(getRes.GetCluster(), getRes.GetNamespace())
		},
		func(client sdk.ZeroClient) {
			organizationID, err := getZeroOrganizationID(ctx, client)
			if err != nil {
				resp.Diagnostics.AddError(err.Error(), err.Error())
				return
			}

			cluster, namespace := getZeroCluster(ctx, client, &resp.Diagnostics, organizationID, state.ID.ValueString())
			if resp.Diagnostics.HasError() {
				return
			}

			state = NewZeroToModelConverter(&resp.Diagnostics).Cluster(cluster, namespace)
		})...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *ClusterResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan ClusterResourceModel

	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(r.client.ByServerType(
		func(client sdk.CoreClient) {
			cluster := NewModelToCoreConverter(&resp.Diagnostics).Cluster(plan)
			if resp.Diagnostics.HasError() {
				return
			}

			err := databrokerPut(ctx, client, RecordTypeCluster, plan.ID.ValueString(), cluster)
			if err != nil {
				resp.Diagnostics.AddError("error updating cluster", err.Error())
				return
			}

			plan = NewCoreToModelConverter(&resp.Diagnostics).Cluster(cluster)
		},
		func(client *client.Client) {
			pbCluster := NewModelToEnterpriseConverter(&resp.Diagnostics).Cluster(plan)
			if resp.Diagnostics.HasError() {
				return
			}

			updateReq := &pb.UpdateClusterRequest{
				Cluster: pbCluster,
			}
			updateRes, err := client.ClustersService.UpdateCluster(ctx, updateReq)
			if err != nil {
				resp.Diagnostics.AddError("Error updating cluster", err.Error())
				return
			}

			plan = NewEnterpriseToModelConverter(&resp.Diagnostics).Cluster(updateRes.GetCluster(), updateRes.GetNamespace())
		},
		func(client sdk.ZeroClient) {
			organizationID, err := getZeroOrganizationID(ctx, client)
			if err != nil {
				resp.Diagnostics.AddError(err.Error(), err.Error())
				return
			}

			updateReq := NewModelToZeroConverter(&resp.Diagnostics).UpdateClusterRequest(plan)
			if resp.Diagnostics.HasError() {
				return
			}

			updateRes, err := client.UpdateClusterWithResponse(ctx, organizationID, plan.ID.ValueString(), updateReq)
			if err != nil {
				resp.Diagnostics.AddError("error updating cluster", err.Error())
				return
			} else if updateRes.JSON200 == nil {
				addZeroResponseError(&resp.Diagnostics, updateRes.Body, updateRes.HTTPResponse)
				return
			}

			cluster, namespace := getZeroCluster(ctx, client, &resp.Diagnostics, organizationID, plan.ID.ValueString())
			if resp.Diagnostics.HasError() {
				return
			}

			plan = NewZeroToModelConverter(&resp.Diagnostics).Cluster(cluster, namespace)
		})...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *ClusterResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state ClusterResourceModel

	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(r.client.ByServerType(
		func(client sdk.CoreClient) {
			err := databrokerDelete(ctx, client, RecordTypeCluster, state.ID.ValueString())
			if err != nil {
				resp.Diagnostics.AddError("error deleting cluster", err.Error())
				return
			}

			err = databrokerDelete(ctx, client, RecordTypeNamespace, state.NamespaceID.ValueString())
			if err != nil {
				resp.Diagnostics.AddError("error deleting cluster namespace", err.Error())
				return
			}
		},
		func(client *client.Client) {
			deleteReq := &pb.DeleteClusterRequest{
				Id: state.ID.ValueString(),
			}
			_, err := client.ClustersService.DeleteCluster(ctx, deleteReq)
			if err != nil {
				resp.Diagnostics.AddError("Error deleting cluster", err.Error())
				return
			}
		},
		func(client sdk.ZeroClient) {
			organizationID, err := getZeroOrganizationID(ctx, client)
			if err != nil {
				resp.Diagnostics.AddError(err.Error(), err.Error())
				return
			}

			deleteRes, err := client.DeleteClusterWithResponse(ctx, organizationID, state.ID.ValueString())
			if err != nil {
				resp.Diagnostics.AddError("error deleting cluster", err.Error())
				return
			} else if deleteRes.StatusCode() != 204 && deleteRes.StatusCode() != 404 {
				addZeroResponseError(&resp.Diagnostics, deleteRes.Body, deleteRes.HTTPResponse)
				return
			}
		})...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.State.RemoveResource(ctx)
}
