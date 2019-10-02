// Code generated by private/model/cli/gen-api/main.go. DO NOT EDIT.

package amplify

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/internal/awsutil"
	"github.com/aws/aws-sdk-go-v2/private/protocol"
)

// Request structure for the list webhooks request.
type ListWebhooksInput struct {
	_ struct{} `type:"structure"`

	// Unique Id for an Amplify App.
	//
	// AppId is a required field
	AppId *string `location:"uri" locationName:"appId" min:"1" type:"string" required:"true"`

	// Maximum number of records to list in a single response.
	MaxResults *int64 `location:"querystring" locationName:"maxResults" min:"1" type:"integer"`

	// Pagination token. Set to null to start listing webhooks from start. If non-null
	// pagination token is returned in a result, then pass its value in here to
	// list more webhooks.
	NextToken *string `location:"querystring" locationName:"nextToken" type:"string"`
}

// String returns the string representation
func (s ListWebhooksInput) String() string {
	return awsutil.Prettify(s)
}

// Validate inspects the fields of the type to determine if they are valid.
func (s *ListWebhooksInput) Validate() error {
	invalidParams := aws.ErrInvalidParams{Context: "ListWebhooksInput"}

	if s.AppId == nil {
		invalidParams.Add(aws.NewErrParamRequired("AppId"))
	}
	if s.AppId != nil && len(*s.AppId) < 1 {
		invalidParams.Add(aws.NewErrParamMinLen("AppId", 1))
	}
	if s.MaxResults != nil && *s.MaxResults < 1 {
		invalidParams.Add(aws.NewErrParamMinValue("MaxResults", 1))
	}

	if invalidParams.Len() > 0 {
		return invalidParams
	}
	return nil
}

// MarshalFields encodes the AWS API shape using the passed in protocol encoder.
func (s ListWebhooksInput) MarshalFields(e protocol.FieldEncoder) error {
	e.SetValue(protocol.HeaderTarget, "Content-Type", protocol.StringValue("application/json"), protocol.Metadata{})

	if s.AppId != nil {
		v := *s.AppId

		metadata := protocol.Metadata{}
		e.SetValue(protocol.PathTarget, "appId", protocol.QuotedValue{ValueMarshaler: protocol.StringValue(v)}, metadata)
	}
	if s.MaxResults != nil {
		v := *s.MaxResults

		metadata := protocol.Metadata{}
		e.SetValue(protocol.QueryTarget, "maxResults", protocol.Int64Value(v), metadata)
	}
	if s.NextToken != nil {
		v := *s.NextToken

		metadata := protocol.Metadata{}
		e.SetValue(protocol.QueryTarget, "nextToken", protocol.QuotedValue{ValueMarshaler: protocol.StringValue(v)}, metadata)
	}
	return nil
}

// Result structure for the list webhooks request.
type ListWebhooksOutput struct {
	_ struct{} `type:"structure"`

	// Pagination token. If non-null pagination token is returned in a result, then
	// pass its value in another request to fetch more entries.
	NextToken *string `locationName:"nextToken" type:"string"`

	// List of webhooks.
	//
	// Webhooks is a required field
	Webhooks []Webhook `locationName:"webhooks" type:"list" required:"true"`
}

// String returns the string representation
func (s ListWebhooksOutput) String() string {
	return awsutil.Prettify(s)
}

// MarshalFields encodes the AWS API shape using the passed in protocol encoder.
func (s ListWebhooksOutput) MarshalFields(e protocol.FieldEncoder) error {
	if s.NextToken != nil {
		v := *s.NextToken

		metadata := protocol.Metadata{}
		e.SetValue(protocol.BodyTarget, "nextToken", protocol.QuotedValue{ValueMarshaler: protocol.StringValue(v)}, metadata)
	}
	if s.Webhooks != nil {
		v := s.Webhooks

		metadata := protocol.Metadata{}
		ls0 := e.List(protocol.BodyTarget, "webhooks", metadata)
		ls0.Start()
		for _, v1 := range v {
			ls0.ListAddFields(v1)
		}
		ls0.End()

	}
	return nil
}

const opListWebhooks = "ListWebhooks"

// ListWebhooksRequest returns a request value for making API operation for
// AWS Amplify.
//
// List webhooks with an app.
//
//    // Example sending a request using ListWebhooksRequest.
//    req := client.ListWebhooksRequest(params)
//    resp, err := req.Send(context.TODO())
//    if err == nil {
//        fmt.Println(resp)
//    }
//
// Please also see https://docs.aws.amazon.com/goto/WebAPI/amplify-2017-07-25/ListWebhooks
func (c *Client) ListWebhooksRequest(input *ListWebhooksInput) ListWebhooksRequest {
	op := &aws.Operation{
		Name:       opListWebhooks,
		HTTPMethod: "GET",
		HTTPPath:   "/apps/{appId}/webhooks",
	}

	if input == nil {
		input = &ListWebhooksInput{}
	}

	req := c.newRequest(op, input, &ListWebhooksOutput{})
	return ListWebhooksRequest{Request: req, Input: input, Copy: c.ListWebhooksRequest}
}

// ListWebhooksRequest is the request type for the
// ListWebhooks API operation.
type ListWebhooksRequest struct {
	*aws.Request
	Input *ListWebhooksInput
	Copy  func(*ListWebhooksInput) ListWebhooksRequest
}

// Send marshals and sends the ListWebhooks API request.
func (r ListWebhooksRequest) Send(ctx context.Context) (*ListWebhooksResponse, error) {
	r.Request.SetContext(ctx)
	err := r.Request.Send()
	if err != nil {
		return nil, err
	}

	resp := &ListWebhooksResponse{
		ListWebhooksOutput: r.Request.Data.(*ListWebhooksOutput),
		response:           &aws.Response{Request: r.Request},
	}

	return resp, nil
}

// ListWebhooksResponse is the response type for the
// ListWebhooks API operation.
type ListWebhooksResponse struct {
	*ListWebhooksOutput

	response *aws.Response
}

// SDKResponseMetdata returns the response metadata for the
// ListWebhooks request.
func (r *ListWebhooksResponse) SDKResponseMetdata() *aws.Response {
	return r.response
}