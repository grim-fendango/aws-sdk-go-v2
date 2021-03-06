// Code generated by private/model/cli/gen-api/main.go. DO NOT EDIT.

package iotsitewise

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/internal/awsutil"
	"github.com/aws/aws-sdk-go-v2/private/protocol"
)

type UpdateAssetInput struct {
	_ struct{} `type:"structure"`

	// The ID of the asset to update.
	//
	// AssetId is a required field
	AssetId *string `location:"uri" locationName:"assetId" min:"36" type:"string" required:"true"`

	// A unique, friendly name for the asset.
	//
	// AssetName is a required field
	AssetName *string `locationName:"assetName" min:"1" type:"string" required:"true"`

	// A unique case-sensitive identifier that you can provide to ensure the idempotency
	// of the request. Don't reuse this client token if a new idempotent request
	// is required.
	ClientToken *string `locationName:"clientToken" min:"36" type:"string" idempotencyToken:"true"`
}

// String returns the string representation
func (s UpdateAssetInput) String() string {
	return awsutil.Prettify(s)
}

// Validate inspects the fields of the type to determine if they are valid.
func (s *UpdateAssetInput) Validate() error {
	invalidParams := aws.ErrInvalidParams{Context: "UpdateAssetInput"}

	if s.AssetId == nil {
		invalidParams.Add(aws.NewErrParamRequired("AssetId"))
	}
	if s.AssetId != nil && len(*s.AssetId) < 36 {
		invalidParams.Add(aws.NewErrParamMinLen("AssetId", 36))
	}

	if s.AssetName == nil {
		invalidParams.Add(aws.NewErrParamRequired("AssetName"))
	}
	if s.AssetName != nil && len(*s.AssetName) < 1 {
		invalidParams.Add(aws.NewErrParamMinLen("AssetName", 1))
	}
	if s.ClientToken != nil && len(*s.ClientToken) < 36 {
		invalidParams.Add(aws.NewErrParamMinLen("ClientToken", 36))
	}

	if invalidParams.Len() > 0 {
		return invalidParams
	}
	return nil
}

// MarshalFields encodes the AWS API shape using the passed in protocol encoder.
func (s UpdateAssetInput) MarshalFields(e protocol.FieldEncoder) error {
	e.SetValue(protocol.HeaderTarget, "Content-Type", protocol.StringValue("application/json"), protocol.Metadata{})

	if s.AssetName != nil {
		v := *s.AssetName

		metadata := protocol.Metadata{}
		e.SetValue(protocol.BodyTarget, "assetName", protocol.QuotedValue{ValueMarshaler: protocol.StringValue(v)}, metadata)
	}
	var ClientToken string
	if s.ClientToken != nil {
		ClientToken = *s.ClientToken
	} else {
		ClientToken = protocol.GetIdempotencyToken()
	}
	{
		v := ClientToken

		metadata := protocol.Metadata{}
		e.SetValue(protocol.BodyTarget, "clientToken", protocol.QuotedValue{ValueMarshaler: protocol.StringValue(v)}, metadata)
	}
	if s.AssetId != nil {
		v := *s.AssetId

		metadata := protocol.Metadata{}
		e.SetValue(protocol.PathTarget, "assetId", protocol.QuotedValue{ValueMarshaler: protocol.StringValue(v)}, metadata)
	}
	return nil
}

type UpdateAssetOutput struct {
	_ struct{} `type:"structure"`

	// The status of the asset, which contains a state (UPDATING after successfully
	// calling this operation) and any error message.
	//
	// AssetStatus is a required field
	AssetStatus *AssetStatus `locationName:"assetStatus" type:"structure" required:"true"`
}

// String returns the string representation
func (s UpdateAssetOutput) String() string {
	return awsutil.Prettify(s)
}

// MarshalFields encodes the AWS API shape using the passed in protocol encoder.
func (s UpdateAssetOutput) MarshalFields(e protocol.FieldEncoder) error {
	if s.AssetStatus != nil {
		v := s.AssetStatus

		metadata := protocol.Metadata{}
		e.SetFields(protocol.BodyTarget, "assetStatus", v, metadata)
	}
	return nil
}

const opUpdateAsset = "UpdateAsset"

// UpdateAssetRequest returns a request value for making API operation for
// AWS IoT SiteWise.
//
// Updates an asset's name. For more information, see Updating Assets and Models
// (https://docs.aws.amazon.com/iot-sitewise/latest/userguide/update-assets-and-models.html)
// in the AWS IoT SiteWise User Guide.
//
//    // Example sending a request using UpdateAssetRequest.
//    req := client.UpdateAssetRequest(params)
//    resp, err := req.Send(context.TODO())
//    if err == nil {
//        fmt.Println(resp)
//    }
//
// Please also see https://docs.aws.amazon.com/goto/WebAPI/iotsitewise-2019-12-02/UpdateAsset
func (c *Client) UpdateAssetRequest(input *UpdateAssetInput) UpdateAssetRequest {
	op := &aws.Operation{
		Name:       opUpdateAsset,
		HTTPMethod: "PUT",
		HTTPPath:   "/assets/{assetId}",
	}

	if input == nil {
		input = &UpdateAssetInput{}
	}

	req := c.newRequest(op, input, &UpdateAssetOutput{})
	req.Handlers.Build.PushBackNamed(protocol.NewHostPrefixHandler("model.", nil))
	req.Handlers.Build.PushBackNamed(protocol.ValidateEndpointHostHandler)

	return UpdateAssetRequest{Request: req, Input: input, Copy: c.UpdateAssetRequest}
}

// UpdateAssetRequest is the request type for the
// UpdateAsset API operation.
type UpdateAssetRequest struct {
	*aws.Request
	Input *UpdateAssetInput
	Copy  func(*UpdateAssetInput) UpdateAssetRequest
}

// Send marshals and sends the UpdateAsset API request.
func (r UpdateAssetRequest) Send(ctx context.Context) (*UpdateAssetResponse, error) {
	r.Request.SetContext(ctx)
	err := r.Request.Send()
	if err != nil {
		return nil, err
	}

	resp := &UpdateAssetResponse{
		UpdateAssetOutput: r.Request.Data.(*UpdateAssetOutput),
		response:          &aws.Response{Request: r.Request},
	}

	return resp, nil
}

// UpdateAssetResponse is the response type for the
// UpdateAsset API operation.
type UpdateAssetResponse struct {
	*UpdateAssetOutput

	response *aws.Response
}

// SDKResponseMetdata returns the response metadata for the
// UpdateAsset request.
func (r *UpdateAssetResponse) SDKResponseMetdata() *aws.Response {
	return r.response
}
