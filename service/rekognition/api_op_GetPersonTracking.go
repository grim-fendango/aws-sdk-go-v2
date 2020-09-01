// Code generated by smithy-go-codegen DO NOT EDIT.

package rekognition

import (
	"context"
	awsmiddleware "github.com/aws/aws-sdk-go-v2/aws/middleware"
	"github.com/aws/aws-sdk-go-v2/aws/retry"
	"github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/aws/aws-sdk-go-v2/service/rekognition/types"
	smithy "github.com/awslabs/smithy-go"
	"github.com/awslabs/smithy-go/middleware"
	smithyhttp "github.com/awslabs/smithy-go/transport/http"
)

// Gets the path tracking results of a Amazon Rekognition Video analysis started by
// StartPersonTracking ().  <p>The person path tracking operation is started by a
// call to <code>StartPersonTracking</code> which returns a job identifier
// (<code>JobId</code>). When the operation finishes, Amazon Rekognition Video
// publishes a completion status to the Amazon Simple Notification Service topic
// registered in the initial call to <code>StartPersonTracking</code>.</p> <p>To
// get the results of the person path tracking operation, first check that the
// status value published to the Amazon SNS topic is <code>SUCCEEDED</code>. If so,
// call <a>GetPersonTracking</a> and pass the job identifier (<code>JobId</code>)
// from the initial call to <code>StartPersonTracking</code>.</p> <p>
// <code>GetPersonTracking</code> returns an array, <code>Persons</code>, of
// tracked persons and the time(s) their paths were tracked in the video. </p>
// <note> <p> <code>GetPersonTracking</code> only returns the default facial
// attributes (<code>BoundingBox</code>, <code>Confidence</code>,
// <code>Landmarks</code>, <code>Pose</code>, and <code>Quality</code>). The other
// facial attributes listed in the <code>Face</code> object of the following
// response syntax are not returned. </p> <p>For more information, see FaceDetail
// in the Amazon Rekognition Developer Guide.</p> </note> <p>By default, the array
// is sorted by the time(s) a person's path is tracked in the video. You can sort
// by tracked persons by specifying <code>INDEX</code> for the <code>SortBy</code>
// input parameter.</p> <p>Use the <code>MaxResults</code> parameter to limit the
// number of items returned. If there are more results than  specified in
// MaxResults, the value of NextToken in the operation response contains a
// pagination token for getting the next set of results. To get the next page of
// results, call GetPersonTracking and populate the NextToken request parameter
// with the token value returned from the previous call to GetPersonTracking.
func (c *Client) GetPersonTracking(ctx context.Context, params *GetPersonTrackingInput, optFns ...func(*Options)) (*GetPersonTrackingOutput, error) {
	stack := middleware.NewStack("GetPersonTracking", smithyhttp.NewStackRequest)
	options := c.options.Copy()
	for _, fn := range optFns {
		fn(&options)
	}
	addawsAwsjson11_serdeOpGetPersonTrackingMiddlewares(stack)
	awsmiddleware.AddRequestInvocationIDMiddleware(stack)
	smithyhttp.AddContentLengthMiddleware(stack)
	AddResolveEndpointMiddleware(stack, options)
	v4.AddComputePayloadSHA256Middleware(stack)
	retry.AddRetryMiddlewares(stack, options)
	addHTTPSignerV4Middleware(stack, options)
	awsmiddleware.AddAttemptClockSkewMiddleware(stack)
	addClientUserAgent(stack)
	smithyhttp.AddErrorCloseResponseBodyMiddleware(stack)
	smithyhttp.AddCloseResponseBodyMiddleware(stack)
	addOpGetPersonTrackingValidationMiddleware(stack)
	stack.Initialize.Add(newServiceMetadataMiddleware_opGetPersonTracking(options.Region), middleware.Before)

	for _, fn := range options.APIOptions {
		if err := fn(stack); err != nil {
			return nil, err
		}
	}
	handler := middleware.DecorateHandler(smithyhttp.NewClientHandler(options.HTTPClient), stack)
	result, metadata, err := handler.Handle(ctx, params)
	if err != nil {
		return nil, &smithy.OperationError{
			ServiceID:     ServiceID,
			OperationName: "GetPersonTracking",
			Err:           err,
		}
	}
	out := result.(*GetPersonTrackingOutput)
	out.ResultMetadata = metadata
	return out, nil
}

type GetPersonTrackingInput struct {
	// Sort to use for elements in the Persons array. Use TIMESTAMP to sort array
	// elements by the time persons are detected. Use INDEX to sort by the tracked
	// persons. If you sort by INDEX, the array elements for each person are sorted by
	// detection confidence. The default sort is by TIMESTAMP.
	SortBy types.PersonTrackingSortBy
	// The identifier for a job that tracks persons in a video. You get the JobId from
	// a call to StartPersonTracking.
	JobId *string
	// Maximum number of results to return per paginated call. The largest value you
	// can specify is 1000. If you specify a value greater than 1000, a maximum of 1000
	// results is returned. The default value is 1000.
	MaxResults *int32
	// If the previous response was incomplete (because there are more persons to
	// retrieve), Amazon Rekognition Video returns a pagination token in the response.
	// You can use this pagination token to retrieve the next set of persons.
	NextToken *string
}

type GetPersonTrackingOutput struct {
	// The current status of the person tracking job.
	JobStatus types.VideoJobStatus
	// If the response is truncated, Amazon Rekognition Video returns this token that
	// you can use in the subsequent request to retrieve the next set of persons.
	NextToken *string
	// An array of the persons detected in the video and the time(s) their path was
	// tracked throughout the video. An array element will exist for each time a
	// person's path is tracked.
	Persons []*types.PersonDetection
	// Information about a video that Amazon Rekognition Video analyzed. Videometadata
	// is returned in every page of paginated responses from a Amazon Rekognition Video
	// operation.
	VideoMetadata *types.VideoMetadata
	// If the job fails, StatusMessage provides a descriptive error message.
	StatusMessage *string

	// Metadata pertaining to the operation's result.
	ResultMetadata middleware.Metadata
}

func addawsAwsjson11_serdeOpGetPersonTrackingMiddlewares(stack *middleware.Stack) {
	stack.Serialize.Add(&awsAwsjson11_serializeOpGetPersonTracking{}, middleware.After)
	stack.Deserialize.Add(&awsAwsjson11_deserializeOpGetPersonTracking{}, middleware.After)
}

func newServiceMetadataMiddleware_opGetPersonTracking(region string) awsmiddleware.RegisterServiceMetadata {
	return awsmiddleware.RegisterServiceMetadata{
		Region:        region,
		ServiceID:     ServiceID,
		SigningName:   "rekognition",
		OperationName: "GetPersonTracking",
	}
}