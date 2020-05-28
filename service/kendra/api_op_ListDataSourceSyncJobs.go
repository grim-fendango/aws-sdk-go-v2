// Code generated by private/model/cli/gen-api/main.go. DO NOT EDIT.

package kendra

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/internal/awsutil"
)

type ListDataSourceSyncJobsInput struct {
	_ struct{} `type:"structure"`

	// The identifier of the data source.
	//
	// Id is a required field
	Id *string `min:"1" type:"string" required:"true"`

	// The identifier of the index that contains the data source.
	//
	// IndexId is a required field
	IndexId *string `min:"36" type:"string" required:"true"`

	// The maximum number of synchronization jobs to return in the response. If
	// there are fewer results in the list, this response contains only the actual
	// results.
	MaxResults *int64 `min:"1" type:"integer"`

	// If the result of the previous request to GetDataSourceSyncJobHistory was
	// truncated, include the NextToken to fetch the next set of jobs.
	NextToken *string `min:"1" type:"string"`

	// When specified, the synchronization jobs returned in the list are limited
	// to jobs between the specified dates.
	StartTimeFilter *TimeRange `type:"structure"`

	// When specified, only returns synchronization jobs with the Status field equal
	// to the specified status.
	StatusFilter DataSourceSyncJobStatus `type:"string" enum:"true"`
}

// String returns the string representation
func (s ListDataSourceSyncJobsInput) String() string {
	return awsutil.Prettify(s)
}

// Validate inspects the fields of the type to determine if they are valid.
func (s *ListDataSourceSyncJobsInput) Validate() error {
	invalidParams := aws.ErrInvalidParams{Context: "ListDataSourceSyncJobsInput"}

	if s.Id == nil {
		invalidParams.Add(aws.NewErrParamRequired("Id"))
	}
	if s.Id != nil && len(*s.Id) < 1 {
		invalidParams.Add(aws.NewErrParamMinLen("Id", 1))
	}

	if s.IndexId == nil {
		invalidParams.Add(aws.NewErrParamRequired("IndexId"))
	}
	if s.IndexId != nil && len(*s.IndexId) < 36 {
		invalidParams.Add(aws.NewErrParamMinLen("IndexId", 36))
	}
	if s.MaxResults != nil && *s.MaxResults < 1 {
		invalidParams.Add(aws.NewErrParamMinValue("MaxResults", 1))
	}
	if s.NextToken != nil && len(*s.NextToken) < 1 {
		invalidParams.Add(aws.NewErrParamMinLen("NextToken", 1))
	}

	if invalidParams.Len() > 0 {
		return invalidParams
	}
	return nil
}

type ListDataSourceSyncJobsOutput struct {
	_ struct{} `type:"structure"`

	// A history of synchronization jobs for the data source.
	History []DataSourceSyncJob `type:"list"`

	// The GetDataSourceSyncJobHistory operation returns a page of vocabularies
	// at a time. The maximum size of the page is set by the MaxResults parameter.
	// If there are more jobs in the list than the page size, Amazon Kendra returns
	// the NextPage token. Include the token in the next request to the GetDataSourceSyncJobHistory
	// operation to return in the next page of jobs.
	NextToken *string `min:"1" type:"string"`
}

// String returns the string representation
func (s ListDataSourceSyncJobsOutput) String() string {
	return awsutil.Prettify(s)
}

const opListDataSourceSyncJobs = "ListDataSourceSyncJobs"

// ListDataSourceSyncJobsRequest returns a request value for making API operation for
// AWSKendraFrontendService.
//
// Gets statistics about synchronizing Amazon Kendra with a data source.
//
//    // Example sending a request using ListDataSourceSyncJobsRequest.
//    req := client.ListDataSourceSyncJobsRequest(params)
//    resp, err := req.Send(context.TODO())
//    if err == nil {
//        fmt.Println(resp)
//    }
//
// Please also see https://docs.aws.amazon.com/goto/WebAPI/kendra-2019-02-03/ListDataSourceSyncJobs
func (c *Client) ListDataSourceSyncJobsRequest(input *ListDataSourceSyncJobsInput) ListDataSourceSyncJobsRequest {
	op := &aws.Operation{
		Name:       opListDataSourceSyncJobs,
		HTTPMethod: "POST",
		HTTPPath:   "/",
		Paginator: &aws.Paginator{
			InputTokens:     []string{"NextToken"},
			OutputTokens:    []string{"NextToken"},
			LimitToken:      "MaxResults",
			TruncationToken: "",
		},
	}

	if input == nil {
		input = &ListDataSourceSyncJobsInput{}
	}

	req := c.newRequest(op, input, &ListDataSourceSyncJobsOutput{})

	return ListDataSourceSyncJobsRequest{Request: req, Input: input, Copy: c.ListDataSourceSyncJobsRequest}
}

// ListDataSourceSyncJobsRequest is the request type for the
// ListDataSourceSyncJobs API operation.
type ListDataSourceSyncJobsRequest struct {
	*aws.Request
	Input *ListDataSourceSyncJobsInput
	Copy  func(*ListDataSourceSyncJobsInput) ListDataSourceSyncJobsRequest
}

// Send marshals and sends the ListDataSourceSyncJobs API request.
func (r ListDataSourceSyncJobsRequest) Send(ctx context.Context) (*ListDataSourceSyncJobsResponse, error) {
	r.Request.SetContext(ctx)
	err := r.Request.Send()
	if err != nil {
		return nil, err
	}

	resp := &ListDataSourceSyncJobsResponse{
		ListDataSourceSyncJobsOutput: r.Request.Data.(*ListDataSourceSyncJobsOutput),
		response:                     &aws.Response{Request: r.Request},
	}

	return resp, nil
}

// NewListDataSourceSyncJobsRequestPaginator returns a paginator for ListDataSourceSyncJobs.
// Use Next method to get the next page, and CurrentPage to get the current
// response page from the paginator. Next will return false, if there are
// no more pages, or an error was encountered.
//
// Note: This operation can generate multiple requests to a service.
//
//   // Example iterating over pages.
//   req := client.ListDataSourceSyncJobsRequest(input)
//   p := kendra.NewListDataSourceSyncJobsRequestPaginator(req)
//
//   for p.Next(context.TODO()) {
//       page := p.CurrentPage()
//   }
//
//   if err := p.Err(); err != nil {
//       return err
//   }
//
func NewListDataSourceSyncJobsPaginator(req ListDataSourceSyncJobsRequest) ListDataSourceSyncJobsPaginator {
	return ListDataSourceSyncJobsPaginator{
		Pager: aws.Pager{
			NewRequest: func(ctx context.Context) (*aws.Request, error) {
				var inCpy *ListDataSourceSyncJobsInput
				if req.Input != nil {
					tmp := *req.Input
					inCpy = &tmp
				}

				newReq := req.Copy(inCpy)
				newReq.SetContext(ctx)
				return newReq.Request, nil
			},
		},
	}
}

// ListDataSourceSyncJobsPaginator is used to paginate the request. This can be done by
// calling Next and CurrentPage.
type ListDataSourceSyncJobsPaginator struct {
	aws.Pager
}

func (p *ListDataSourceSyncJobsPaginator) CurrentPage() *ListDataSourceSyncJobsOutput {
	return p.Pager.CurrentPage().(*ListDataSourceSyncJobsOutput)
}

// ListDataSourceSyncJobsResponse is the response type for the
// ListDataSourceSyncJobs API operation.
type ListDataSourceSyncJobsResponse struct {
	*ListDataSourceSyncJobsOutput

	response *aws.Response
}

// SDKResponseMetdata returns the response metadata for the
// ListDataSourceSyncJobs request.
func (r *ListDataSourceSyncJobsResponse) SDKResponseMetdata() *aws.Response {
	return r.response
}