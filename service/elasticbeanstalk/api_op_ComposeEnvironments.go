// Code generated by smithy-go-codegen DO NOT EDIT.

package elasticbeanstalk

import (
	"context"
	awsmiddleware "github.com/aws/aws-sdk-go-v2/aws/middleware"
	"github.com/aws/aws-sdk-go-v2/aws/retry"
	"github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/aws/aws-sdk-go-v2/service/elasticbeanstalk/types"
	smithy "github.com/awslabs/smithy-go"
	"github.com/awslabs/smithy-go/middleware"
	smithyhttp "github.com/awslabs/smithy-go/transport/http"
)

// Create or update a group of environments that each run a separate component of a
// single application. Takes a list of version labels that specify application
// source bundles for each of the environments to create or update. The name of
// each environment and other required information must be included in the source
// bundles in an environment manifest named env.yaml. See Compose Environments
// (https://docs.aws.amazon.com/elasticbeanstalk/latest/dg/environment-mgmt-compose.html)
// for details.
func (c *Client) ComposeEnvironments(ctx context.Context, params *ComposeEnvironmentsInput, optFns ...func(*Options)) (*ComposeEnvironmentsOutput, error) {
	stack := middleware.NewStack("ComposeEnvironments", smithyhttp.NewStackRequest)
	options := c.options.Copy()
	for _, fn := range optFns {
		fn(&options)
	}
	addawsAwsquery_serdeOpComposeEnvironmentsMiddlewares(stack)
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
	stack.Initialize.Add(newServiceMetadataMiddleware_opComposeEnvironments(options.Region), middleware.Before)

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
			OperationName: "ComposeEnvironments",
			Err:           err,
		}
	}
	out := result.(*ComposeEnvironmentsOutput)
	out.ResultMetadata = metadata
	return out, nil
}

// Request to create or update a group of environments.
type ComposeEnvironmentsInput struct {
	// A list of version labels, specifying one or more application source bundles that
	// belong to the target application. Each source bundle must include an environment
	// manifest that specifies the name of the environment and the name of the solution
	// stack to use, and optionally can specify environment links to create.
	VersionLabels []*string
	// The name of the application to which the specified source bundles belong.
	ApplicationName *string
	// The name of the group to which the target environments belong. Specify a group
	// name only if the environment name defined in each target environment's manifest
	// ends with a + (plus) character. See Environment Manifest (env.yaml)
	// (https://docs.aws.amazon.com/elasticbeanstalk/latest/dg/environment-cfg-manifest.html)
	// for details.
	GroupName *string
}

// Result message containing a list of environment descriptions.
type ComposeEnvironmentsOutput struct {
	// Returns an EnvironmentDescription () list.
	Environments []*types.EnvironmentDescription
	// In a paginated request, the token that you can pass in a subsequent request to
	// get the next response page.
	NextToken *string

	// Metadata pertaining to the operation's result.
	ResultMetadata middleware.Metadata
}

func addawsAwsquery_serdeOpComposeEnvironmentsMiddlewares(stack *middleware.Stack) {
	stack.Serialize.Add(&awsAwsquery_serializeOpComposeEnvironments{}, middleware.After)
	stack.Deserialize.Add(&awsAwsquery_deserializeOpComposeEnvironments{}, middleware.After)
}

func newServiceMetadataMiddleware_opComposeEnvironments(region string) awsmiddleware.RegisterServiceMetadata {
	return awsmiddleware.RegisterServiceMetadata{
		Region:        region,
		ServiceID:     ServiceID,
		SigningName:   "elasticbeanstalk",
		OperationName: "ComposeEnvironments",
	}
}