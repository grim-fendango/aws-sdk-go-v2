// Code generated by smithy-go-codegen DO NOT EDIT.
package restxml

import (
	"context"
	awsmiddleware "github.com/aws/aws-sdk-go-v2/aws/middleware"
	"github.com/aws/aws-sdk-go-v2/aws/retry"
	smithy "github.com/awslabs/smithy-go"
	"github.com/awslabs/smithy-go/middleware"
	smithyhttp "github.com/awslabs/smithy-go/transport/http"
)

// This example serializes an XML attributes on synthesized document.
func (c *Client) XmlAttributes(ctx context.Context, params *XmlAttributesInput, optFns ...func(*Options)) (*XmlAttributesOutput, error) {
	stack := middleware.NewStack("XmlAttributes", smithyhttp.NewStackRequest)
	options := c.options.Copy()
	for _, fn := range optFns {
		fn(&options)
	}
	awsmiddleware.AddRequestInvocationIDMiddleware(stack)
	awsmiddleware.AddResolveServiceEndpointMiddleware(stack, options)
	retry.AddRetryMiddlewares(stack, options)
	awsmiddleware.AddAttemptClockSkewMiddleware(stack)
	stack.Initialize.Add(newServiceMetadataMiddleware_opXmlAttributes(options.Region), middleware.Before)

	for _, fn := range options.APIOptions {
		if err := fn(stack); err != nil {
			return nil, err
		}
	}
	handler := middleware.DecorateHandler(smithyhttp.NewClientHandler(options.HTTPClient), stack)
	result, metadata, err := handler.Handle(ctx, params)
	if err != nil {
		return nil, &smithy.OperationError{
			ServiceID:     c.ServiceID(),
			OperationName: "XmlAttributes",
			Err:           err,
		}
	}
	out := result.(*XmlAttributesOutput)
	out.ResultMetadata = metadata
	return out, nil
}

type XmlAttributesInput struct {
	Foo  *string
	Attr *string
}

type XmlAttributesOutput struct {
	Foo  *string
	Attr *string

	// Metadata pertaining to the operation's result.
	ResultMetadata middleware.Metadata
}

func newServiceMetadataMiddleware_opXmlAttributes(region string) awsmiddleware.RegisterServiceMetadata {
	return awsmiddleware.RegisterServiceMetadata{
		Region:         region,
		ServiceName:    "Rest Xml Protocol",
		ServiceID:      "restxmlprotocol",
		EndpointPrefix: "restxmlprotocol",
		OperationName:  "XmlAttributes",
	}
}
