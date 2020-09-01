// Code generated by smithy-go-codegen DO NOT EDIT.

package wafv2

import (
	"context"
	awsmiddleware "github.com/aws/aws-sdk-go-v2/aws/middleware"
	"github.com/aws/aws-sdk-go-v2/aws/retry"
	"github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/aws/aws-sdk-go-v2/service/wafv2/types"
	smithy "github.com/awslabs/smithy-go"
	"github.com/awslabs/smithy-go/middleware"
	smithyhttp "github.com/awslabs/smithy-go/transport/http"
)

// This is the latest version of AWS WAF, named AWS WAFV2, released in November,
// 2019. For information, including how to migrate your AWS WAF resources from the
// prior release, see the AWS WAF Developer Guide
// (https://docs.aws.amazon.com/waf/latest/developerguide/waf-chapter.html).
// Retrieves the keys that are currently blocked by a rate-based rule. The maximum
// number of managed keys that can be blocked for a single rate-based rule is
// 10,000. If more than 10,000 addresses exceed the rate limit, those with the
// highest rates are blocked.
func (c *Client) GetRateBasedStatementManagedKeys(ctx context.Context, params *GetRateBasedStatementManagedKeysInput, optFns ...func(*Options)) (*GetRateBasedStatementManagedKeysOutput, error) {
	stack := middleware.NewStack("GetRateBasedStatementManagedKeys", smithyhttp.NewStackRequest)
	options := c.options.Copy()
	for _, fn := range optFns {
		fn(&options)
	}
	addawsAwsjson11_serdeOpGetRateBasedStatementManagedKeysMiddlewares(stack)
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
	addOpGetRateBasedStatementManagedKeysValidationMiddleware(stack)
	stack.Initialize.Add(newServiceMetadataMiddleware_opGetRateBasedStatementManagedKeys(options.Region), middleware.Before)

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
			OperationName: "GetRateBasedStatementManagedKeys",
			Err:           err,
		}
	}
	out := result.(*GetRateBasedStatementManagedKeysOutput)
	out.ResultMetadata = metadata
	return out, nil
}

type GetRateBasedStatementManagedKeysInput struct {
	// The name of the rate-based rule to get the keys for.
	RuleName *string
	// Specifies whether this is for an AWS CloudFront distribution or for a regional
	// application. A regional application can be an Application Load Balancer (ALB) or
	// an API Gateway stage. To work with CloudFront, you must also specify the Region
	// US East (N. Virginia) as follows:
	//
	//     * CLI - Specify the Region when you use
	// the CloudFront scope: --scope=CLOUDFRONT --region=us-east-1.
	//
	//     * API and SDKs
	// - For all calls, use the Region endpoint us-east-1.
	Scope types.Scope
	// The unique identifier for the Web ACL. This ID is returned in the responses to
	// create and list commands. You provide it to operations like update and delete.
	WebACLId *string
	// The name of the Web ACL. You cannot change the name of a Web ACL after you
	// create it.
	WebACLName *string
}

type GetRateBasedStatementManagedKeysOutput struct {
	// The keys that are of Internet Protocol version 6 (IPv6).
	ManagedKeysIPV6 *types.RateBasedStatementManagedKeysIPSet
	// The keys that are of Internet Protocol version 4 (IPv4).
	ManagedKeysIPV4 *types.RateBasedStatementManagedKeysIPSet

	// Metadata pertaining to the operation's result.
	ResultMetadata middleware.Metadata
}

func addawsAwsjson11_serdeOpGetRateBasedStatementManagedKeysMiddlewares(stack *middleware.Stack) {
	stack.Serialize.Add(&awsAwsjson11_serializeOpGetRateBasedStatementManagedKeys{}, middleware.After)
	stack.Deserialize.Add(&awsAwsjson11_deserializeOpGetRateBasedStatementManagedKeys{}, middleware.After)
}

func newServiceMetadataMiddleware_opGetRateBasedStatementManagedKeys(region string) awsmiddleware.RegisterServiceMetadata {
	return awsmiddleware.RegisterServiceMetadata{
		Region:        region,
		ServiceID:     ServiceID,
		SigningName:   "wafv2",
		OperationName: "GetRateBasedStatementManagedKeys",
	}
}