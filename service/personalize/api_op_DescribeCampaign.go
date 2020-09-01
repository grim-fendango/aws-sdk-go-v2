// Code generated by smithy-go-codegen DO NOT EDIT.

package personalize

import (
	"context"
	awsmiddleware "github.com/aws/aws-sdk-go-v2/aws/middleware"
	"github.com/aws/aws-sdk-go-v2/aws/retry"
	"github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/aws/aws-sdk-go-v2/service/personalize/types"
	smithy "github.com/awslabs/smithy-go"
	"github.com/awslabs/smithy-go/middleware"
	smithyhttp "github.com/awslabs/smithy-go/transport/http"
)

// Describes the given campaign, including its status. A campaign can be in one of
// the following states:
//
//     * CREATE PENDING > CREATE IN_PROGRESS > ACTIVE -or-
// CREATE FAILED
//
//     * DELETE PENDING > DELETE IN_PROGRESS
//
// When the status is
// CREATE FAILED, the response includes the failureReason key, which describes why.
// For more information on campaigns, see CreateCampaign ().
func (c *Client) DescribeCampaign(ctx context.Context, params *DescribeCampaignInput, optFns ...func(*Options)) (*DescribeCampaignOutput, error) {
	stack := middleware.NewStack("DescribeCampaign", smithyhttp.NewStackRequest)
	options := c.options.Copy()
	for _, fn := range optFns {
		fn(&options)
	}
	addawsAwsjson11_serdeOpDescribeCampaignMiddlewares(stack)
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
	addOpDescribeCampaignValidationMiddleware(stack)
	stack.Initialize.Add(newServiceMetadataMiddleware_opDescribeCampaign(options.Region), middleware.Before)

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
			OperationName: "DescribeCampaign",
			Err:           err,
		}
	}
	out := result.(*DescribeCampaignOutput)
	out.ResultMetadata = metadata
	return out, nil
}

type DescribeCampaignInput struct {
	// The Amazon Resource Name (ARN) of the campaign.
	CampaignArn *string
}

type DescribeCampaignOutput struct {
	// The properties of the campaign.
	Campaign *types.Campaign

	// Metadata pertaining to the operation's result.
	ResultMetadata middleware.Metadata
}

func addawsAwsjson11_serdeOpDescribeCampaignMiddlewares(stack *middleware.Stack) {
	stack.Serialize.Add(&awsAwsjson11_serializeOpDescribeCampaign{}, middleware.After)
	stack.Deserialize.Add(&awsAwsjson11_deserializeOpDescribeCampaign{}, middleware.After)
}

func newServiceMetadataMiddleware_opDescribeCampaign(region string) awsmiddleware.RegisterServiceMetadata {
	return awsmiddleware.RegisterServiceMetadata{
		Region:        region,
		ServiceID:     ServiceID,
		SigningName:   "personalize",
		OperationName: "DescribeCampaign",
	}
}