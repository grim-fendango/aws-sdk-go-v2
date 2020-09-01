// Code generated by smithy-go-codegen DO NOT EDIT.

package qldb

import (
	"context"
	awsmiddleware "github.com/aws/aws-sdk-go-v2/aws/middleware"
	"github.com/aws/aws-sdk-go-v2/aws/retry"
	"github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/aws/aws-sdk-go-v2/service/qldb/types"
	smithy "github.com/awslabs/smithy-go"
	"github.com/awslabs/smithy-go/middleware"
	smithyhttp "github.com/awslabs/smithy-go/transport/http"
	"time"
)

// Updates properties on a ledger.
func (c *Client) UpdateLedger(ctx context.Context, params *UpdateLedgerInput, optFns ...func(*Options)) (*UpdateLedgerOutput, error) {
	stack := middleware.NewStack("UpdateLedger", smithyhttp.NewStackRequest)
	options := c.options.Copy()
	for _, fn := range optFns {
		fn(&options)
	}
	addawsRestjson1_serdeOpUpdateLedgerMiddlewares(stack)
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
	addOpUpdateLedgerValidationMiddleware(stack)
	stack.Initialize.Add(newServiceMetadataMiddleware_opUpdateLedger(options.Region), middleware.Before)

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
			OperationName: "UpdateLedger",
			Err:           err,
		}
	}
	out := result.(*UpdateLedgerOutput)
	out.ResultMetadata = metadata
	return out, nil
}

type UpdateLedgerInput struct {
	// The name of the ledger.
	Name *string
	// The flag that prevents a ledger from being deleted by any user. If not provided
	// on ledger creation, this feature is enabled (true) by default. If deletion
	// protection is enabled, you must first disable it before you can delete the
	// ledger using the QLDB API or the AWS Command Line Interface (AWS CLI). You can
	// disable it by calling the UpdateLedger operation to set the flag to false. The
	// QLDB console disables deletion protection for you when you use it to delete a
	// ledger.
	DeletionProtection *bool
}

type UpdateLedgerOutput struct {
	// The Amazon Resource Name (ARN) for the ledger.
	Arn *string
	// The current status of the ledger.
	State types.LedgerState
	// The date and time, in epoch time format, when the ledger was created. (Epoch
	// time format is the number of seconds elapsed since 12:00:00 AM January 1, 1970
	// UTC.)
	CreationDateTime *time.Time
	// The flag that prevents a ledger from being deleted by any user. If not provided
	// on ledger creation, this feature is enabled (true) by default. If deletion
	// protection is enabled, you must first disable it before you can delete the
	// ledger using the QLDB API or the AWS Command Line Interface (AWS CLI). You can
	// disable it by calling the UpdateLedger operation to set the flag to false. The
	// QLDB console disables deletion protection for you when you use it to delete a
	// ledger.
	DeletionProtection *bool
	// The name of the ledger.
	Name *string

	// Metadata pertaining to the operation's result.
	ResultMetadata middleware.Metadata
}

func addawsRestjson1_serdeOpUpdateLedgerMiddlewares(stack *middleware.Stack) {
	stack.Serialize.Add(&awsRestjson1_serializeOpUpdateLedger{}, middleware.After)
	stack.Deserialize.Add(&awsRestjson1_deserializeOpUpdateLedger{}, middleware.After)
}

func newServiceMetadataMiddleware_opUpdateLedger(region string) awsmiddleware.RegisterServiceMetadata {
	return awsmiddleware.RegisterServiceMetadata{
		Region:        region,
		ServiceID:     ServiceID,
		SigningName:   "qldb",
		OperationName: "UpdateLedger",
	}
}