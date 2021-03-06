// Code generated by private/model/cli/gen-api/main.go. DO NOT EDIT.

package workspaces

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/internal/awsutil"
)

type RebootWorkspacesInput struct {
	_ struct{} `type:"structure"`

	// The WorkSpaces to reboot. You can specify up to 25 WorkSpaces.
	//
	// RebootWorkspaceRequests is a required field
	RebootWorkspaceRequests []RebootRequest `min:"1" type:"list" required:"true"`
}

// String returns the string representation
func (s RebootWorkspacesInput) String() string {
	return awsutil.Prettify(s)
}

// Validate inspects the fields of the type to determine if they are valid.
func (s *RebootWorkspacesInput) Validate() error {
	invalidParams := aws.ErrInvalidParams{Context: "RebootWorkspacesInput"}

	if s.RebootWorkspaceRequests == nil {
		invalidParams.Add(aws.NewErrParamRequired("RebootWorkspaceRequests"))
	}
	if s.RebootWorkspaceRequests != nil && len(s.RebootWorkspaceRequests) < 1 {
		invalidParams.Add(aws.NewErrParamMinLen("RebootWorkspaceRequests", 1))
	}
	if s.RebootWorkspaceRequests != nil {
		for i, v := range s.RebootWorkspaceRequests {
			if err := v.Validate(); err != nil {
				invalidParams.AddNested(fmt.Sprintf("%s[%v]", "RebootWorkspaceRequests", i), err.(aws.ErrInvalidParams))
			}
		}
	}

	if invalidParams.Len() > 0 {
		return invalidParams
	}
	return nil
}

type RebootWorkspacesOutput struct {
	_ struct{} `type:"structure"`

	// Information about the WorkSpaces that could not be rebooted.
	FailedRequests []FailedWorkspaceChangeRequest `type:"list"`
}

// String returns the string representation
func (s RebootWorkspacesOutput) String() string {
	return awsutil.Prettify(s)
}

const opRebootWorkspaces = "RebootWorkspaces"

// RebootWorkspacesRequest returns a request value for making API operation for
// Amazon WorkSpaces.
//
// Reboots the specified WorkSpaces.
//
// You cannot reboot a WorkSpace unless its state is AVAILABLE or UNHEALTHY.
//
// This operation is asynchronous and returns before the WorkSpaces have rebooted.
//
//    // Example sending a request using RebootWorkspacesRequest.
//    req := client.RebootWorkspacesRequest(params)
//    resp, err := req.Send(context.TODO())
//    if err == nil {
//        fmt.Println(resp)
//    }
//
// Please also see https://docs.aws.amazon.com/goto/WebAPI/workspaces-2015-04-08/RebootWorkspaces
func (c *Client) RebootWorkspacesRequest(input *RebootWorkspacesInput) RebootWorkspacesRequest {
	op := &aws.Operation{
		Name:       opRebootWorkspaces,
		HTTPMethod: "POST",
		HTTPPath:   "/",
	}

	if input == nil {
		input = &RebootWorkspacesInput{}
	}

	req := c.newRequest(op, input, &RebootWorkspacesOutput{})

	return RebootWorkspacesRequest{Request: req, Input: input, Copy: c.RebootWorkspacesRequest}
}

// RebootWorkspacesRequest is the request type for the
// RebootWorkspaces API operation.
type RebootWorkspacesRequest struct {
	*aws.Request
	Input *RebootWorkspacesInput
	Copy  func(*RebootWorkspacesInput) RebootWorkspacesRequest
}

// Send marshals and sends the RebootWorkspaces API request.
func (r RebootWorkspacesRequest) Send(ctx context.Context) (*RebootWorkspacesResponse, error) {
	r.Request.SetContext(ctx)
	err := r.Request.Send()
	if err != nil {
		return nil, err
	}

	resp := &RebootWorkspacesResponse{
		RebootWorkspacesOutput: r.Request.Data.(*RebootWorkspacesOutput),
		response:               &aws.Response{Request: r.Request},
	}

	return resp, nil
}

// RebootWorkspacesResponse is the response type for the
// RebootWorkspaces API operation.
type RebootWorkspacesResponse struct {
	*RebootWorkspacesOutput

	response *aws.Response
}

// SDKResponseMetdata returns the response metadata for the
// RebootWorkspaces request.
func (r *RebootWorkspacesResponse) SDKResponseMetdata() *aws.Response {
	return r.response
}
