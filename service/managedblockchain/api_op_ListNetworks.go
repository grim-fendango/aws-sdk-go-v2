// Code generated by smithy-go-codegen DO NOT EDIT.

package managedblockchain

import (
	"context"
	awsmiddleware "github.com/aws/aws-sdk-go-v2/aws/middleware"
	"github.com/aws/aws-sdk-go-v2/aws/retry"
	"github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/aws/aws-sdk-go-v2/service/managedblockchain/types"
	smithy "github.com/awslabs/smithy-go"
	"github.com/awslabs/smithy-go/middleware"
	smithyhttp "github.com/awslabs/smithy-go/transport/http"
)

// Returns information about the networks in which the current AWS account has
// members.
func (c *Client) ListNetworks(ctx context.Context, params *ListNetworksInput, optFns ...func(*Options)) (*ListNetworksOutput, error) {
	stack := middleware.NewStack("ListNetworks", smithyhttp.NewStackRequest)
	options := c.options.Copy()
	for _, fn := range optFns {
		fn(&options)
	}
	addawsRestjson1_serdeOpListNetworksMiddlewares(stack)
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
	stack.Initialize.Add(newServiceMetadataMiddleware_opListNetworks(options.Region), middleware.Before)

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
			OperationName: "ListNetworks",
			Err:           err,
		}
	}
	out := result.(*ListNetworksOutput)
	out.ResultMetadata = metadata
	return out, nil
}

type ListNetworksInput struct {
	// An optional status specifier. If provided, only networks currently in this
	// status are listed.
	Status types.NetworkStatus
	// An optional framework specifier. If provided, only networks of this framework
	// type are listed.
	Framework types.Framework
	// The name of the network.
	Name *string
	// The maximum number of networks to list.
	MaxResults *int32
	// The pagination token that indicates the next set of results to retrieve.
	NextToken *string
}

type ListNetworksOutput struct {
	// The pagination token that indicates the next set of results to retrieve.
	NextToken *string
	// An array of NetworkSummary objects that contain configuration properties for
	// each network.
	Networks []*types.NetworkSummary

	// Metadata pertaining to the operation's result.
	ResultMetadata middleware.Metadata
}

func addawsRestjson1_serdeOpListNetworksMiddlewares(stack *middleware.Stack) {
	stack.Serialize.Add(&awsRestjson1_serializeOpListNetworks{}, middleware.After)
	stack.Deserialize.Add(&awsRestjson1_deserializeOpListNetworks{}, middleware.After)
}

func newServiceMetadataMiddleware_opListNetworks(region string) awsmiddleware.RegisterServiceMetadata {
	return awsmiddleware.RegisterServiceMetadata{
		Region:        region,
		ServiceID:     ServiceID,
		SigningName:   "managedblockchain",
		OperationName: "ListNetworks",
	}
}