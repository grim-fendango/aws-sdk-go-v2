// Code generated by private/model/cli/gen-api/main.go. DO NOT EDIT.

package outposts

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/internal/awsutil"
	"github.com/aws/aws-sdk-go-v2/private/protocol"
)

type GetOutpostInstanceTypesInput struct {
	_ struct{} `type:"structure"`

	// The maximum page size.
	MaxResults *int64 `location:"querystring" locationName:"MaxResults" min:"1" type:"integer"`

	// The pagination token.
	NextToken *string `location:"querystring" locationName:"NextToken" min:"1" type:"string"`

	// The ID of the Outpost.
	//
	// OutpostId is a required field
	OutpostId *string `location:"uri" locationName:"OutpostId" min:"1" type:"string" required:"true"`
}

// String returns the string representation
func (s GetOutpostInstanceTypesInput) String() string {
	return awsutil.Prettify(s)
}

// Validate inspects the fields of the type to determine if they are valid.
func (s *GetOutpostInstanceTypesInput) Validate() error {
	invalidParams := aws.ErrInvalidParams{Context: "GetOutpostInstanceTypesInput"}
	if s.MaxResults != nil && *s.MaxResults < 1 {
		invalidParams.Add(aws.NewErrParamMinValue("MaxResults", 1))
	}
	if s.NextToken != nil && len(*s.NextToken) < 1 {
		invalidParams.Add(aws.NewErrParamMinLen("NextToken", 1))
	}

	if s.OutpostId == nil {
		invalidParams.Add(aws.NewErrParamRequired("OutpostId"))
	}
	if s.OutpostId != nil && len(*s.OutpostId) < 1 {
		invalidParams.Add(aws.NewErrParamMinLen("OutpostId", 1))
	}

	if invalidParams.Len() > 0 {
		return invalidParams
	}
	return nil
}

// MarshalFields encodes the AWS API shape using the passed in protocol encoder.
func (s GetOutpostInstanceTypesInput) MarshalFields(e protocol.FieldEncoder) error {
	e.SetValue(protocol.HeaderTarget, "Content-Type", protocol.StringValue("application/json"), protocol.Metadata{})

	if s.OutpostId != nil {
		v := *s.OutpostId

		metadata := protocol.Metadata{}
		e.SetValue(protocol.PathTarget, "OutpostId", protocol.QuotedValue{ValueMarshaler: protocol.StringValue(v)}, metadata)
	}
	if s.MaxResults != nil {
		v := *s.MaxResults

		metadata := protocol.Metadata{}
		e.SetValue(protocol.QueryTarget, "MaxResults", protocol.Int64Value(v), metadata)
	}
	if s.NextToken != nil {
		v := *s.NextToken

		metadata := protocol.Metadata{}
		e.SetValue(protocol.QueryTarget, "NextToken", protocol.QuotedValue{ValueMarshaler: protocol.StringValue(v)}, metadata)
	}
	return nil
}

type GetOutpostInstanceTypesOutput struct {
	_ struct{} `type:"structure"`

	// Information about the instance types.
	InstanceTypes []InstanceTypeItem `type:"list"`

	// The pagination token.
	NextToken *string `min:"1" type:"string"`

	// The Amazon Resource Name (ARN) of the Outpost.
	OutpostArn *string `min:"1" type:"string"`

	// The ID of the Outpost.
	OutpostId *string `min:"1" type:"string"`
}

// String returns the string representation
func (s GetOutpostInstanceTypesOutput) String() string {
	return awsutil.Prettify(s)
}

// MarshalFields encodes the AWS API shape using the passed in protocol encoder.
func (s GetOutpostInstanceTypesOutput) MarshalFields(e protocol.FieldEncoder) error {
	if s.InstanceTypes != nil {
		v := s.InstanceTypes

		metadata := protocol.Metadata{}
		ls0 := e.List(protocol.BodyTarget, "InstanceTypes", metadata)
		ls0.Start()
		for _, v1 := range v {
			ls0.ListAddFields(v1)
		}
		ls0.End()

	}
	if s.NextToken != nil {
		v := *s.NextToken

		metadata := protocol.Metadata{}
		e.SetValue(protocol.BodyTarget, "NextToken", protocol.QuotedValue{ValueMarshaler: protocol.StringValue(v)}, metadata)
	}
	if s.OutpostArn != nil {
		v := *s.OutpostArn

		metadata := protocol.Metadata{}
		e.SetValue(protocol.BodyTarget, "OutpostArn", protocol.QuotedValue{ValueMarshaler: protocol.StringValue(v)}, metadata)
	}
	if s.OutpostId != nil {
		v := *s.OutpostId

		metadata := protocol.Metadata{}
		e.SetValue(protocol.BodyTarget, "OutpostId", protocol.QuotedValue{ValueMarshaler: protocol.StringValue(v)}, metadata)
	}
	return nil
}

const opGetOutpostInstanceTypes = "GetOutpostInstanceTypes"

// GetOutpostInstanceTypesRequest returns a request value for making API operation for
// AWS Outposts.
//
// Lists the instance types for the specified Outpost.
//
//    // Example sending a request using GetOutpostInstanceTypesRequest.
//    req := client.GetOutpostInstanceTypesRequest(params)
//    resp, err := req.Send(context.TODO())
//    if err == nil {
//        fmt.Println(resp)
//    }
//
// Please also see https://docs.aws.amazon.com/goto/WebAPI/outposts-2019-12-03/GetOutpostInstanceTypes
func (c *Client) GetOutpostInstanceTypesRequest(input *GetOutpostInstanceTypesInput) GetOutpostInstanceTypesRequest {
	op := &aws.Operation{
		Name:       opGetOutpostInstanceTypes,
		HTTPMethod: "GET",
		HTTPPath:   "/outposts/{OutpostId}/instanceTypes",
	}

	if input == nil {
		input = &GetOutpostInstanceTypesInput{}
	}

	req := c.newRequest(op, input, &GetOutpostInstanceTypesOutput{})

	return GetOutpostInstanceTypesRequest{Request: req, Input: input, Copy: c.GetOutpostInstanceTypesRequest}
}

// GetOutpostInstanceTypesRequest is the request type for the
// GetOutpostInstanceTypes API operation.
type GetOutpostInstanceTypesRequest struct {
	*aws.Request
	Input *GetOutpostInstanceTypesInput
	Copy  func(*GetOutpostInstanceTypesInput) GetOutpostInstanceTypesRequest
}

// Send marshals and sends the GetOutpostInstanceTypes API request.
func (r GetOutpostInstanceTypesRequest) Send(ctx context.Context) (*GetOutpostInstanceTypesResponse, error) {
	r.Request.SetContext(ctx)
	err := r.Request.Send()
	if err != nil {
		return nil, err
	}

	resp := &GetOutpostInstanceTypesResponse{
		GetOutpostInstanceTypesOutput: r.Request.Data.(*GetOutpostInstanceTypesOutput),
		response:                      &aws.Response{Request: r.Request},
	}

	return resp, nil
}

// GetOutpostInstanceTypesResponse is the response type for the
// GetOutpostInstanceTypes API operation.
type GetOutpostInstanceTypesResponse struct {
	*GetOutpostInstanceTypesOutput

	response *aws.Response
}

// SDKResponseMetdata returns the response metadata for the
// GetOutpostInstanceTypes request.
func (r *GetOutpostInstanceTypesResponse) SDKResponseMetdata() *aws.Response {
	return r.response
}
