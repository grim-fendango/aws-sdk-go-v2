// Code generated by private/model/cli/gen-api/main.go. DO NOT EDIT.

package transcribe

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/internal/awsutil"
	"github.com/aws/aws-sdk-go-v2/private/protocol"
	"github.com/aws/aws-sdk-go-v2/private/protocol/jsonrpc"
)

type DeleteVocabularyFilterInput struct {
	_ struct{} `type:"structure"`

	// The name of the vocabulary filter to remove.
	//
	// VocabularyFilterName is a required field
	VocabularyFilterName *string `min:"1" type:"string" required:"true"`
}

// String returns the string representation
func (s DeleteVocabularyFilterInput) String() string {
	return awsutil.Prettify(s)
}

// Validate inspects the fields of the type to determine if they are valid.
func (s *DeleteVocabularyFilterInput) Validate() error {
	invalidParams := aws.ErrInvalidParams{Context: "DeleteVocabularyFilterInput"}

	if s.VocabularyFilterName == nil {
		invalidParams.Add(aws.NewErrParamRequired("VocabularyFilterName"))
	}
	if s.VocabularyFilterName != nil && len(*s.VocabularyFilterName) < 1 {
		invalidParams.Add(aws.NewErrParamMinLen("VocabularyFilterName", 1))
	}

	if invalidParams.Len() > 0 {
		return invalidParams
	}
	return nil
}

type DeleteVocabularyFilterOutput struct {
	_ struct{} `type:"structure"`
}

// String returns the string representation
func (s DeleteVocabularyFilterOutput) String() string {
	return awsutil.Prettify(s)
}

const opDeleteVocabularyFilter = "DeleteVocabularyFilter"

// DeleteVocabularyFilterRequest returns a request value for making API operation for
// Amazon Transcribe Service.
//
// Removes a vocabulary filter.
//
//    // Example sending a request using DeleteVocabularyFilterRequest.
//    req := client.DeleteVocabularyFilterRequest(params)
//    resp, err := req.Send(context.TODO())
//    if err == nil {
//        fmt.Println(resp)
//    }
//
// Please also see https://docs.aws.amazon.com/goto/WebAPI/transcribe-2017-10-26/DeleteVocabularyFilter
func (c *Client) DeleteVocabularyFilterRequest(input *DeleteVocabularyFilterInput) DeleteVocabularyFilterRequest {
	op := &aws.Operation{
		Name:       opDeleteVocabularyFilter,
		HTTPMethod: "POST",
		HTTPPath:   "/",
	}

	if input == nil {
		input = &DeleteVocabularyFilterInput{}
	}

	req := c.newRequest(op, input, &DeleteVocabularyFilterOutput{})
	req.Handlers.Unmarshal.Remove(jsonrpc.UnmarshalHandler)
	req.Handlers.Unmarshal.PushBackNamed(protocol.UnmarshalDiscardBodyHandler)

	return DeleteVocabularyFilterRequest{Request: req, Input: input, Copy: c.DeleteVocabularyFilterRequest}
}

// DeleteVocabularyFilterRequest is the request type for the
// DeleteVocabularyFilter API operation.
type DeleteVocabularyFilterRequest struct {
	*aws.Request
	Input *DeleteVocabularyFilterInput
	Copy  func(*DeleteVocabularyFilterInput) DeleteVocabularyFilterRequest
}

// Send marshals and sends the DeleteVocabularyFilter API request.
func (r DeleteVocabularyFilterRequest) Send(ctx context.Context) (*DeleteVocabularyFilterResponse, error) {
	r.Request.SetContext(ctx)
	err := r.Request.Send()
	if err != nil {
		return nil, err
	}

	resp := &DeleteVocabularyFilterResponse{
		DeleteVocabularyFilterOutput: r.Request.Data.(*DeleteVocabularyFilterOutput),
		response:                     &aws.Response{Request: r.Request},
	}

	return resp, nil
}

// DeleteVocabularyFilterResponse is the response type for the
// DeleteVocabularyFilter API operation.
type DeleteVocabularyFilterResponse struct {
	*DeleteVocabularyFilterOutput

	response *aws.Response
}

// SDKResponseMetdata returns the response metadata for the
// DeleteVocabularyFilter request.
func (r *DeleteVocabularyFilterResponse) SDKResponseMetdata() *aws.Response {
	return r.response
}
