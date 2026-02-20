package provider

import (
	"context"
	"errors"
	"fmt"
	"io"

	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/pomerium/sdk-go/proto/pomerium"
)

func databrokerDelete(
	ctx context.Context,
	client pomerium.DataBrokerServiceClient,
	recordType string,
	recordID string,
) error {
	anyData, err := anypb.New(&structpb.Struct{Fields: make(map[string]*structpb.Value)})
	if err != nil {
		return err
	}
	_, err = client.Put(ctx, &pomerium.PutRequest{
		Records: []*pomerium.Record{{
			Type:      recordType,
			Id:        recordID,
			Data:      anyData,
			DeletedAt: timestamppb.Now(),
		}},
	})
	return err
}

func databrokerGet(
	ctx context.Context,
	client pomerium.DataBrokerServiceClient,
	recordType string,
	recordID string,
) (*structpb.Struct, error) {
	res, err := client.Get(ctx, &pomerium.GetRequest{
		Type: recordType,
		Id:   recordID,
	})
	if err != nil {
		return nil, err
	}
	var data structpb.Struct
	err = res.GetRecord().GetData().UnmarshalTo(&data)
	if err != nil {
		return nil, fmt.Errorf("unexpected data record: %w", err)
	}
	return &data, nil
}

func databrokerList(
	ctx context.Context,
	client pomerium.DataBrokerServiceClient,
	recordType string,
) ([]*structpb.Struct, error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	stream, err := client.SyncLatest(ctx, &pomerium.SyncLatestRequest{
		Type: recordType,
	})
	if err != nil {
		return nil, err
	}

	var s []*structpb.Struct
	for {
		res, err := stream.Recv()
		if errors.Is(err, io.EOF) {
			break
		} else if err != nil {
			return nil, err
		}

		switch res := res.Response.(type) {
		case *pomerium.SyncLatestResponse_Record:
			var d structpb.Struct
			err = res.Record.GetData().UnmarshalTo(&d)
			if err != nil {
				return nil, fmt.Errorf("unexpected data record: %w", err)
			}
			s = append(s, &d)
		}
	}
	return s, nil
}

func databrokerPut(
	ctx context.Context,
	client pomerium.DataBrokerServiceClient,
	recordType string,
	recordID string,
	data *structpb.Struct,
) error {
	anyData, err := anypb.New(data)
	if err != nil {
		return err
	}
	_, err = client.Put(ctx, &pomerium.PutRequest{
		Records: []*pomerium.Record{{
			Type: recordType,
			Id:   recordID,
			Data: anyData,
		}},
	})
	return err
}
