// Code generated by smithy-go-codegen DO NOT EDIT.

package machinelearning

import (
	"context"
	awsmiddleware "github.com/aws/aws-sdk-go-v2/aws/middleware"
	"github.com/aws/aws-sdk-go-v2/aws/retry"
	"github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	smithy "github.com/awslabs/smithy-go"
	"github.com/awslabs/smithy-go/middleware"
	smithyhttp "github.com/awslabs/smithy-go/transport/http"
)

// Updates the EvaluationName of an Evaluation. You can use the GetEvaluation
// operation to view the contents of the updated data element.
func (c *Client) UpdateEvaluation(ctx context.Context, params *UpdateEvaluationInput, optFns ...func(*Options)) (*UpdateEvaluationOutput, error) {
	stack := middleware.NewStack("UpdateEvaluation", smithyhttp.NewStackRequest)
	options := c.options.Copy()
	for _, fn := range optFns {
		fn(&options)
	}
	addawsAwsjson11_serdeOpUpdateEvaluationMiddlewares(stack)
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
	addOpUpdateEvaluationValidationMiddleware(stack)
	stack.Initialize.Add(newServiceMetadataMiddleware_opUpdateEvaluation(options.Region), middleware.Before)

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
			OperationName: "UpdateEvaluation",
			Err:           err,
		}
	}
	out := result.(*UpdateEvaluationOutput)
	out.ResultMetadata = metadata
	return out, nil
}

type UpdateEvaluationInput struct {
	// A new user-supplied name or description of the Evaluation that will replace the
	// current content.
	EvaluationName *string
	// The ID assigned to the Evaluation during creation.
	EvaluationId *string
}

// Represents the output of an UpdateEvaluation operation. You can see the updated
// content by using the GetEvaluation operation.
type UpdateEvaluationOutput struct {
	// The ID assigned to the Evaluation during creation. This value should be
	// identical to the value of the Evaluation in the request.
	EvaluationId *string

	// Metadata pertaining to the operation's result.
	ResultMetadata middleware.Metadata
}

func addawsAwsjson11_serdeOpUpdateEvaluationMiddlewares(stack *middleware.Stack) {
	stack.Serialize.Add(&awsAwsjson11_serializeOpUpdateEvaluation{}, middleware.After)
	stack.Deserialize.Add(&awsAwsjson11_deserializeOpUpdateEvaluation{}, middleware.After)
}

func newServiceMetadataMiddleware_opUpdateEvaluation(region string) awsmiddleware.RegisterServiceMetadata {
	return awsmiddleware.RegisterServiceMetadata{
		Region:        region,
		ServiceID:     ServiceID,
		SigningName:   "machinelearning",
		OperationName: "UpdateEvaluation",
	}
}