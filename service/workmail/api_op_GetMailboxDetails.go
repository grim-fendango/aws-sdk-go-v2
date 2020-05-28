// Code generated by private/model/cli/gen-api/main.go. DO NOT EDIT.

package workmail

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/internal/awsutil"
)

type GetMailboxDetailsInput struct {
	_ struct{} `type:"structure"`

	// The identifier for the organization that contains the user whose mailbox
	// details are being requested.
	//
	// OrganizationId is a required field
	OrganizationId *string `type:"string" required:"true"`

	// The identifier for the user whose mailbox details are being requested.
	//
	// UserId is a required field
	UserId *string `min:"12" type:"string" required:"true"`
}

// String returns the string representation
func (s GetMailboxDetailsInput) String() string {
	return awsutil.Prettify(s)
}

// Validate inspects the fields of the type to determine if they are valid.
func (s *GetMailboxDetailsInput) Validate() error {
	invalidParams := aws.ErrInvalidParams{Context: "GetMailboxDetailsInput"}

	if s.OrganizationId == nil {
		invalidParams.Add(aws.NewErrParamRequired("OrganizationId"))
	}

	if s.UserId == nil {
		invalidParams.Add(aws.NewErrParamRequired("UserId"))
	}
	if s.UserId != nil && len(*s.UserId) < 12 {
		invalidParams.Add(aws.NewErrParamMinLen("UserId", 12))
	}

	if invalidParams.Len() > 0 {
		return invalidParams
	}
	return nil
}

type GetMailboxDetailsOutput struct {
	_ struct{} `type:"structure"`

	// The maximum allowed mailbox size, in MB, for the specified user.
	MailboxQuota *int64 `min:"1" type:"integer"`

	// The current mailbox size, in MB, for the specified user.
	MailboxSize *float64 `type:"double"`
}

// String returns the string representation
func (s GetMailboxDetailsOutput) String() string {
	return awsutil.Prettify(s)
}

const opGetMailboxDetails = "GetMailboxDetails"

// GetMailboxDetailsRequest returns a request value for making API operation for
// Amazon WorkMail.
//
// Requests a user's mailbox details for a specified organization and user.
//
//    // Example sending a request using GetMailboxDetailsRequest.
//    req := client.GetMailboxDetailsRequest(params)
//    resp, err := req.Send(context.TODO())
//    if err == nil {
//        fmt.Println(resp)
//    }
//
// Please also see https://docs.aws.amazon.com/goto/WebAPI/workmail-2017-10-01/GetMailboxDetails
func (c *Client) GetMailboxDetailsRequest(input *GetMailboxDetailsInput) GetMailboxDetailsRequest {
	op := &aws.Operation{
		Name:       opGetMailboxDetails,
		HTTPMethod: "POST",
		HTTPPath:   "/",
	}

	if input == nil {
		input = &GetMailboxDetailsInput{}
	}

	req := c.newRequest(op, input, &GetMailboxDetailsOutput{})

	return GetMailboxDetailsRequest{Request: req, Input: input, Copy: c.GetMailboxDetailsRequest}
}

// GetMailboxDetailsRequest is the request type for the
// GetMailboxDetails API operation.
type GetMailboxDetailsRequest struct {
	*aws.Request
	Input *GetMailboxDetailsInput
	Copy  func(*GetMailboxDetailsInput) GetMailboxDetailsRequest
}

// Send marshals and sends the GetMailboxDetails API request.
func (r GetMailboxDetailsRequest) Send(ctx context.Context) (*GetMailboxDetailsResponse, error) {
	r.Request.SetContext(ctx)
	err := r.Request.Send()
	if err != nil {
		return nil, err
	}

	resp := &GetMailboxDetailsResponse{
		GetMailboxDetailsOutput: r.Request.Data.(*GetMailboxDetailsOutput),
		response:                &aws.Response{Request: r.Request},
	}

	return resp, nil
}

// GetMailboxDetailsResponse is the response type for the
// GetMailboxDetails API operation.
type GetMailboxDetailsResponse struct {
	*GetMailboxDetailsOutput

	response *aws.Response
}

// SDKResponseMetdata returns the response metadata for the
// GetMailboxDetails request.
func (r *GetMailboxDetailsResponse) SDKResponseMetdata() *aws.Response {
	return r.response
}