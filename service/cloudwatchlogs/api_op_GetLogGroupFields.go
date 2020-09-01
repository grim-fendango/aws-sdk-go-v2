// Code generated by smithy-go-codegen DO NOT EDIT.

package cloudwatchlogs

import (
	"context"
	awsmiddleware "github.com/aws/aws-sdk-go-v2/aws/middleware"
	"github.com/aws/aws-sdk-go-v2/aws/retry"
	"github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs/types"
	smithy "github.com/awslabs/smithy-go"
	"github.com/awslabs/smithy-go/middleware"
	smithyhttp "github.com/awslabs/smithy-go/transport/http"
)

// Returns a list of the fields that are included in log events in the specified
// log group, along with the percentage of log events that contain each field. The
// search is limited to a time period that you specify. In the results, fields that
// start with @ are fields generated by CloudWatch Logs. For example, @timestamp is
// the timestamp of each log event. For more information about the fields that are
// generated by CloudWatch logs, see Supported Logs and Discovered Fields
// (https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/CWL_AnalyzeLogData-discoverable-fields.html).
// The response results are sorted by the frequency percentage, starting with the
// highest percentage.
func (c *Client) GetLogGroupFields(ctx context.Context, params *GetLogGroupFieldsInput, optFns ...func(*Options)) (*GetLogGroupFieldsOutput, error) {
	stack := middleware.NewStack("GetLogGroupFields", smithyhttp.NewStackRequest)
	options := c.options.Copy()
	for _, fn := range optFns {
		fn(&options)
	}
	addawsAwsjson11_serdeOpGetLogGroupFieldsMiddlewares(stack)
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
	addOpGetLogGroupFieldsValidationMiddleware(stack)
	stack.Initialize.Add(newServiceMetadataMiddleware_opGetLogGroupFields(options.Region), middleware.Before)

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
			OperationName: "GetLogGroupFields",
			Err:           err,
		}
	}
	out := result.(*GetLogGroupFieldsOutput)
	out.ResultMetadata = metadata
	return out, nil
}

type GetLogGroupFieldsInput struct {
	// The time to set as the center of the query. If you specify time, the 8 minutes
	// before and 8 minutes after this time are searched. If you omit time, the past 15
	// minutes are queried. The time value is specified as epoch time, the number of
	// seconds since January 1, 1970, 00:00:00 UTC.
	Time *int64
	// The name of the log group to search.
	LogGroupName *string
}

type GetLogGroupFieldsOutput struct {
	// The array of fields found in the query. Each object in the array contains the
	// name of the field, along with the percentage of time it appeared in the log
	// events that were queried.
	LogGroupFields []*types.LogGroupField

	// Metadata pertaining to the operation's result.
	ResultMetadata middleware.Metadata
}

func addawsAwsjson11_serdeOpGetLogGroupFieldsMiddlewares(stack *middleware.Stack) {
	stack.Serialize.Add(&awsAwsjson11_serializeOpGetLogGroupFields{}, middleware.After)
	stack.Deserialize.Add(&awsAwsjson11_deserializeOpGetLogGroupFields{}, middleware.After)
}

func newServiceMetadataMiddleware_opGetLogGroupFields(region string) awsmiddleware.RegisterServiceMetadata {
	return awsmiddleware.RegisterServiceMetadata{
		Region:        region,
		ServiceID:     ServiceID,
		SigningName:   "logs",
		OperationName: "GetLogGroupFields",
	}
}