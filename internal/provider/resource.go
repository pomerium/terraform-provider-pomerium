package provider

import (
	"fmt"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/structpb"
)

func createOrUpdate[T proto.Message](
	create func() (T, error),
	list func(filter *structpb.Struct) ([]T, error),
	update func() (T, error),
	obj T,
) (T, error) {
	newObj, err := create()
	if connect.CodeOf(err) == connect.CodeAlreadyExists {
		filter := &structpb.Struct{Fields: map[string]*structpb.Value{}}
		if o, ok := any(obj).(interface{ GetName() string }); ok && o.GetName() != "" {
			filter.Fields["name"] = structpb.NewStringValue(o.GetName())
		}
		if o, ok := any(obj).(interface{ GetNamespaceId() string }); ok && o.GetNamespaceId() != "" {
			filter.Fields["namespace_id"] = structpb.NewStringValue(o.GetNamespaceId())
		}
		objs, err := list(filter)
		if err != nil {
			return obj, fmt.Errorf("error listing existing objects: %w", err)
		} else if len(objs) == 0 {
			return obj, fmt.Errorf("no existing object found")
		}
		obj.ProtoReflect().Set(
			obj.ProtoReflect().Descriptor().Fields().ByName("id"),
			objs[0].ProtoReflect().Get(objs[0].ProtoReflect().Descriptor().Fields().ByName("id")),
		)
		newObj, err = update()
		if err != nil {
			return obj, fmt.Errorf("error updating object: %w", err)
		}
	} else if err != nil {
		return obj, fmt.Errorf("error creating object: %w", err)
	}

	return newObj, nil
}
