// Code generated by smithy-go-codegen DO NOT EDIT.

package comprehendmedical

import (
	"context"
	awsmiddleware "github.com/aws/aws-sdk-go-v2/aws/middleware"
	"github.com/aws/aws-sdk-go-v2/aws/retry"
	"github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/aws/aws-sdk-go-v2/service/comprehendmedical/types"
	smithy "github.com/awslabs/smithy-go"
	"github.com/awslabs/smithy-go/middleware"
	smithyhttp "github.com/awslabs/smithy-go/transport/http"
)

// Gets the properties associated with a protected health information (PHI)
// detection job. Use this operation to get the status of a detection job.
func (c *Client) DescribePHIDetectionJob(ctx context.Context, params *DescribePHIDetectionJobInput, optFns ...func(*Options)) (*DescribePHIDetectionJobOutput, error) {
	stack := middleware.NewStack("DescribePHIDetectionJob", smithyhttp.NewStackRequest)
	options := c.options.Copy()
	for _, fn := range optFns {
		fn(&options)
	}
	addawsAwsjson11_serdeOpDescribePHIDetectionJobMiddlewares(stack)
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
	addOpDescribePHIDetectionJobValidationMiddleware(stack)
	stack.Initialize.Add(newServiceMetadataMiddleware_opDescribePHIDetectionJob(options.Region), middleware.Before)

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
			OperationName: "DescribePHIDetectionJob",
			Err:           err,
		}
	}
	out := result.(*DescribePHIDetectionJobOutput)
	out.ResultMetadata = metadata
	return out, nil
}

type DescribePHIDetectionJobInput struct {
	// The identifier that Amazon Comprehend Medical generated for the job. The
	// StartPHIDetectionJob operation returns this identifier in its response.
	JobId *string
}

type DescribePHIDetectionJobOutput struct {
	// An object that contains the properties associated with a detection job.
	ComprehendMedicalAsyncJobProperties *types.ComprehendMedicalAsyncJobProperties

	// Metadata pertaining to the operation's result.
	ResultMetadata middleware.Metadata
}

func addawsAwsjson11_serdeOpDescribePHIDetectionJobMiddlewares(stack *middleware.Stack) {
	stack.Serialize.Add(&awsAwsjson11_serializeOpDescribePHIDetectionJob{}, middleware.After)
	stack.Deserialize.Add(&awsAwsjson11_deserializeOpDescribePHIDetectionJob{}, middleware.After)
}

func newServiceMetadataMiddleware_opDescribePHIDetectionJob(region string) awsmiddleware.RegisterServiceMetadata {
	return awsmiddleware.RegisterServiceMetadata{
		Region:        region,
		ServiceID:     ServiceID,
		SigningName:   "comprehendmedical",
		OperationName: "DescribePHIDetectionJob",
	}
}