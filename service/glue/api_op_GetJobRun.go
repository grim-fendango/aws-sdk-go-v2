// Code generated by smithy-go-codegen DO NOT EDIT.

package glue

import (
	"context"
	awsmiddleware "github.com/aws/aws-sdk-go-v2/aws/middleware"
	"github.com/aws/aws-sdk-go-v2/aws/retry"
	"github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/aws/aws-sdk-go-v2/service/glue/types"
	smithy "github.com/awslabs/smithy-go"
	"github.com/awslabs/smithy-go/middleware"
	smithyhttp "github.com/awslabs/smithy-go/transport/http"
)

// Retrieves the metadata for a given job run.
func (c *Client) GetJobRun(ctx context.Context, params *GetJobRunInput, optFns ...func(*Options)) (*GetJobRunOutput, error) {
	stack := middleware.NewStack("GetJobRun", smithyhttp.NewStackRequest)
	options := c.options.Copy()
	for _, fn := range optFns {
		fn(&options)
	}
	addawsAwsjson11_serdeOpGetJobRunMiddlewares(stack)
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
	addOpGetJobRunValidationMiddleware(stack)
	stack.Initialize.Add(newServiceMetadataMiddleware_opGetJobRun(options.Region), middleware.Before)

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
			OperationName: "GetJobRun",
			Err:           err,
		}
	}
	out := result.(*GetJobRunOutput)
	out.ResultMetadata = metadata
	return out, nil
}

type GetJobRunInput struct {
	// The ID of the job run.
	RunId *string
	// Name of the job definition being run.
	JobName *string
	// True if a list of predecessor runs should be returned.
	PredecessorsIncluded *bool
}

type GetJobRunOutput struct {
	// The requested job-run metadata.
	JobRun *types.JobRun

	// Metadata pertaining to the operation's result.
	ResultMetadata middleware.Metadata
}

func addawsAwsjson11_serdeOpGetJobRunMiddlewares(stack *middleware.Stack) {
	stack.Serialize.Add(&awsAwsjson11_serializeOpGetJobRun{}, middleware.After)
	stack.Deserialize.Add(&awsAwsjson11_deserializeOpGetJobRun{}, middleware.After)
}

func newServiceMetadataMiddleware_opGetJobRun(region string) awsmiddleware.RegisterServiceMetadata {
	return awsmiddleware.RegisterServiceMetadata{
		Region:        region,
		ServiceID:     ServiceID,
		SigningName:   "glue",
		OperationName: "GetJobRun",
	}
}