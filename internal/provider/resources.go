package provider

import (
	"connectrpc.com/connect"
	"google.golang.org/protobuf/types/known/structpb"
)

func createOrUpdateByName[T interface {
	GetId() string
	GetName() string
	GetNamespaceId() string
}](
	obj T,
	create func() error,
	list func(filter *structpb.Struct) ([]T, error),
	update func(id string) error,
) error {
	err := create()
	if connect.CodeOf(err) != connect.CodeAlreadyExists {
		return err
	}

	filter := &structpb.Struct{
		Fields: map[string]*structpb.Value{
			"name":          structpb.NewStringValue(obj.GetName()),
			"originator_id": structpb.NewStringValue(OriginatorID),
		},
	}
	if v := obj.GetNamespaceId(); v != "" {
		filter.Fields["namespace_id"] = structpb.NewStringValue(v)
	}
	msgs, listErr := list(filter)
	if listErr != nil {
		return listErr
	} else if len(msgs) == 0 {
		return err
	}

	return update(msgs[0].GetId())
}
