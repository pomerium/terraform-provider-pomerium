package provider

import (
	"context"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

func deleteResource[TModel interface {
	GetID() types.String
}](
	ctx context.Context,
	req resource.DeleteRequest,
	res *resource.DeleteResponse,
	fn func(ctx context.Context, id string) error,
) {
	var data TModel

	res.Diagnostics.Append(req.State.Get(ctx, &data)...)
	if res.Diagnostics.HasError() {
		return
	}

	err := fn(ctx, data.GetID().ValueString())
	if err != nil {
		res.Diagnostics.AddError(fmt.Sprintf("error deleting %T", data), err.Error())
		return
	}

	res.State.RemoveResource(ctx)
}

func readDataSource[Model any](
	ctx context.Context,
	req datasource.ReadRequest,
	res *datasource.ReadResponse,
	fn func(model *Model),
) {
	var model Model

	res.Diagnostics.Append(req.Config.Get(ctx, &model)...)
	if res.Diagnostics.HasError() {
		return
	}

	fn(&model)
	if res.Diagnostics.HasError() {
		return
	}

	res.Diagnostics.Append(res.State.Set(ctx, &model)...)
}

func updateResource[Model, Type any](
	ctx context.Context,
	req resource.UpdateRequest,
	res *resource.UpdateResponse,
	fromModel func(src *Model, current *Type) *Type,
	toModel func(src *Type, current *Model) *Model,
	fn func(ctx context.Context, obj *Type) (*Type, error),
) {
	var model Model

	res.Diagnostics.Append(req.Plan.Get(ctx, &model)...)
	if res.Diagnostics.HasError() {
		return
	}

	current := fromModel(&model, nil)
	if res.Diagnostics.HasError() {
		return
	}

	updated, err := fn(ctx, current)
	if err != nil {
		res.Diagnostics.AddError("error updating resource", err.Error())
		return
	}

	updatedModel := toModel(updated, &model)
	if res.Diagnostics.HasError() {
		return
	}

	res.Diagnostics.Append(res.State.Set(ctx, updatedModel)...)
}
