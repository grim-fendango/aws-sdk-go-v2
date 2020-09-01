// Code generated by smithy-go-codegen DO NOT EDIT.

package codestar

import (
	"context"
	awsmiddleware "github.com/aws/aws-sdk-go-v2/aws/middleware"
	"github.com/aws/aws-sdk-go-v2/aws/retry"
	"github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	smithy "github.com/awslabs/smithy-go"
	"github.com/awslabs/smithy-go/middleware"
	smithyhttp "github.com/awslabs/smithy-go/transport/http"
)

// Removes tags from a project.
func (c *Client) UntagProject(ctx context.Context, params *UntagProjectInput, optFns ...func(*Options)) (*UntagProjectOutput, error) {
	stack := middleware.NewStack("UntagProject", smithyhttp.NewStackRequest)
	options := c.options.Copy()
	for _, fn := range optFns {
		fn(&options)
	}
	addawsAwsjson11_serdeOpUntagProjectMiddlewares(stack)
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
	addOpUntagProjectValidationMiddleware(stack)
	stack.Initialize.Add(newServiceMetadataMiddleware_opUntagProject(options.Region), middleware.Before)

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
			OperationName: "UntagProject",
			Err:           err,
		}
	}
	out := result.(*UntagProjectOutput)
	out.ResultMetadata = metadata
	return out, nil
}

type UntagProjectInput struct {
	// The tags to remove from the project.
	Tags []*string
	// The ID of the project to remove tags from.
	Id *string
}

type UntagProjectOutput struct {
	// Metadata pertaining to the operation's result.
	ResultMetadata middleware.Metadata
}

func addawsAwsjson11_serdeOpUntagProjectMiddlewares(stack *middleware.Stack) {
	stack.Serialize.Add(&awsAwsjson11_serializeOpUntagProject{}, middleware.After)
	stack.Deserialize.Add(&awsAwsjson11_deserializeOpUntagProject{}, middleware.After)
}

func newServiceMetadataMiddleware_opUntagProject(region string) awsmiddleware.RegisterServiceMetadata {
	return awsmiddleware.RegisterServiceMetadata{
		Region:        region,
		ServiceID:     ServiceID,
		SigningName:   "codestar",
		OperationName: "UntagProject",
	}
}