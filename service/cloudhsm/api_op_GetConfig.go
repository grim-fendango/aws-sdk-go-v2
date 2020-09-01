// Code generated by smithy-go-codegen DO NOT EDIT.

package cloudhsm

import (
	"context"
	awsmiddleware "github.com/aws/aws-sdk-go-v2/aws/middleware"
	"github.com/aws/aws-sdk-go-v2/aws/retry"
	"github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/aws/aws-sdk-go-v2/service/cloudhsm/types"
	smithy "github.com/awslabs/smithy-go"
	"github.com/awslabs/smithy-go/middleware"
	smithyhttp "github.com/awslabs/smithy-go/transport/http"
)

// This is documentation for AWS CloudHSM Classic. For more information, see AWS
// CloudHSM Classic FAQs (http://aws.amazon.com/cloudhsm/faqs-classic/), the AWS
// CloudHSM Classic User Guide
// (https://docs.aws.amazon.com/cloudhsm/classic/userguide/), and the AWS CloudHSM
// Classic API Reference
// (https://docs.aws.amazon.com/cloudhsm/classic/APIReference/). For information
// about the current version of AWS CloudHSM, see AWS CloudHSM
// (http://aws.amazon.com/cloudhsm/), the AWS CloudHSM User Guide
// (https://docs.aws.amazon.com/cloudhsm/latest/userguide/), and the AWS CloudHSM
// API Reference (https://docs.aws.amazon.com/cloudhsm/latest/APIReference/). Gets
// the configuration files necessary to connect to all high availability partition
// groups the client is associated with.
func (c *Client) GetConfig(ctx context.Context, params *GetConfigInput, optFns ...func(*Options)) (*GetConfigOutput, error) {
	stack := middleware.NewStack("GetConfig", smithyhttp.NewStackRequest)
	options := c.options.Copy()
	for _, fn := range optFns {
		fn(&options)
	}
	addawsAwsjson11_serdeOpGetConfigMiddlewares(stack)
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
	addOpGetConfigValidationMiddleware(stack)
	stack.Initialize.Add(newServiceMetadataMiddleware_opGetConfig(options.Region), middleware.Before)

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
			OperationName: "GetConfig",
			Err:           err,
		}
	}
	out := result.(*GetConfigOutput)
	out.ResultMetadata = metadata
	return out, nil
}

type GetConfigInput struct {
	// The ARN of the client.
	ClientArn *string
	// A list of ARNs that identify the high-availability partition groups that are
	// associated with the client.
	HapgList []*string
	// The client version.
	ClientVersion types.ClientVersion
}

type GetConfigOutput struct {
	// The type of credentials.
	ConfigType *string
	// The certificate file containing the server.pem files of the HSMs.
	ConfigCred *string
	// The chrystoki.conf configuration file.
	ConfigFile *string

	// Metadata pertaining to the operation's result.
	ResultMetadata middleware.Metadata
}

func addawsAwsjson11_serdeOpGetConfigMiddlewares(stack *middleware.Stack) {
	stack.Serialize.Add(&awsAwsjson11_serializeOpGetConfig{}, middleware.After)
	stack.Deserialize.Add(&awsAwsjson11_deserializeOpGetConfig{}, middleware.After)
}

func newServiceMetadataMiddleware_opGetConfig(region string) awsmiddleware.RegisterServiceMetadata {
	return awsmiddleware.RegisterServiceMetadata{
		Region:        region,
		ServiceID:     ServiceID,
		SigningName:   "cloudhsm",
		OperationName: "GetConfig",
	}
}