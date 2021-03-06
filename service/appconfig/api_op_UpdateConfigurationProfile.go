// Code generated by private/model/cli/gen-api/main.go. DO NOT EDIT.

package appconfig

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/internal/awsutil"
	"github.com/aws/aws-sdk-go-v2/private/protocol"
)

type UpdateConfigurationProfileInput struct {
	_ struct{} `type:"structure"`

	// The application ID.
	//
	// ApplicationId is a required field
	ApplicationId *string `location:"uri" locationName:"ApplicationId" type:"string" required:"true"`

	// The ID of the configuration profile.
	//
	// ConfigurationProfileId is a required field
	ConfigurationProfileId *string `location:"uri" locationName:"ConfigurationProfileId" type:"string" required:"true"`

	// A description of the configuration profile.
	Description *string `type:"string"`

	// The name of the configuration profile.
	Name *string `min:"1" type:"string"`

	// The ARN of an IAM role with permission to access the configuration at the
	// specified LocationUri.
	RetrievalRoleArn *string `min:"20" type:"string"`

	// A list of methods for validating the configuration.
	Validators []Validator `type:"list"`
}

// String returns the string representation
func (s UpdateConfigurationProfileInput) String() string {
	return awsutil.Prettify(s)
}

// Validate inspects the fields of the type to determine if they are valid.
func (s *UpdateConfigurationProfileInput) Validate() error {
	invalidParams := aws.ErrInvalidParams{Context: "UpdateConfigurationProfileInput"}

	if s.ApplicationId == nil {
		invalidParams.Add(aws.NewErrParamRequired("ApplicationId"))
	}

	if s.ConfigurationProfileId == nil {
		invalidParams.Add(aws.NewErrParamRequired("ConfigurationProfileId"))
	}
	if s.Name != nil && len(*s.Name) < 1 {
		invalidParams.Add(aws.NewErrParamMinLen("Name", 1))
	}
	if s.RetrievalRoleArn != nil && len(*s.RetrievalRoleArn) < 20 {
		invalidParams.Add(aws.NewErrParamMinLen("RetrievalRoleArn", 20))
	}
	if s.Validators != nil {
		for i, v := range s.Validators {
			if err := v.Validate(); err != nil {
				invalidParams.AddNested(fmt.Sprintf("%s[%v]", "Validators", i), err.(aws.ErrInvalidParams))
			}
		}
	}

	if invalidParams.Len() > 0 {
		return invalidParams
	}
	return nil
}

// MarshalFields encodes the AWS API shape using the passed in protocol encoder.
func (s UpdateConfigurationProfileInput) MarshalFields(e protocol.FieldEncoder) error {
	e.SetValue(protocol.HeaderTarget, "Content-Type", protocol.StringValue("application/json"), protocol.Metadata{})

	if s.Description != nil {
		v := *s.Description

		metadata := protocol.Metadata{}
		e.SetValue(protocol.BodyTarget, "Description", protocol.QuotedValue{ValueMarshaler: protocol.StringValue(v)}, metadata)
	}
	if s.Name != nil {
		v := *s.Name

		metadata := protocol.Metadata{}
		e.SetValue(protocol.BodyTarget, "Name", protocol.QuotedValue{ValueMarshaler: protocol.StringValue(v)}, metadata)
	}
	if s.RetrievalRoleArn != nil {
		v := *s.RetrievalRoleArn

		metadata := protocol.Metadata{}
		e.SetValue(protocol.BodyTarget, "RetrievalRoleArn", protocol.QuotedValue{ValueMarshaler: protocol.StringValue(v)}, metadata)
	}
	if s.Validators != nil {
		v := s.Validators

		metadata := protocol.Metadata{}
		ls0 := e.List(protocol.BodyTarget, "Validators", metadata)
		ls0.Start()
		for _, v1 := range v {
			ls0.ListAddFields(v1)
		}
		ls0.End()

	}
	if s.ApplicationId != nil {
		v := *s.ApplicationId

		metadata := protocol.Metadata{}
		e.SetValue(protocol.PathTarget, "ApplicationId", protocol.QuotedValue{ValueMarshaler: protocol.StringValue(v)}, metadata)
	}
	if s.ConfigurationProfileId != nil {
		v := *s.ConfigurationProfileId

		metadata := protocol.Metadata{}
		e.SetValue(protocol.PathTarget, "ConfigurationProfileId", protocol.QuotedValue{ValueMarshaler: protocol.StringValue(v)}, metadata)
	}
	return nil
}

type UpdateConfigurationProfileOutput struct {
	_ struct{} `type:"structure"`

	// The application ID.
	ApplicationId *string `type:"string"`

	// The configuration profile description.
	Description *string `type:"string"`

	// The configuration profile ID.
	Id *string `type:"string"`

	// The URI location of the configuration.
	LocationUri *string `min:"1" type:"string"`

	// The name of the configuration profile.
	Name *string `min:"1" type:"string"`

	// The ARN of an IAM role with permission to access the configuration at the
	// specified LocationUri.
	RetrievalRoleArn *string `min:"20" type:"string"`

	// A list of methods for validating the configuration.
	Validators []Validator `type:"list"`
}

// String returns the string representation
func (s UpdateConfigurationProfileOutput) String() string {
	return awsutil.Prettify(s)
}

// MarshalFields encodes the AWS API shape using the passed in protocol encoder.
func (s UpdateConfigurationProfileOutput) MarshalFields(e protocol.FieldEncoder) error {
	if s.ApplicationId != nil {
		v := *s.ApplicationId

		metadata := protocol.Metadata{}
		e.SetValue(protocol.BodyTarget, "ApplicationId", protocol.QuotedValue{ValueMarshaler: protocol.StringValue(v)}, metadata)
	}
	if s.Description != nil {
		v := *s.Description

		metadata := protocol.Metadata{}
		e.SetValue(protocol.BodyTarget, "Description", protocol.QuotedValue{ValueMarshaler: protocol.StringValue(v)}, metadata)
	}
	if s.Id != nil {
		v := *s.Id

		metadata := protocol.Metadata{}
		e.SetValue(protocol.BodyTarget, "Id", protocol.QuotedValue{ValueMarshaler: protocol.StringValue(v)}, metadata)
	}
	if s.LocationUri != nil {
		v := *s.LocationUri

		metadata := protocol.Metadata{}
		e.SetValue(protocol.BodyTarget, "LocationUri", protocol.QuotedValue{ValueMarshaler: protocol.StringValue(v)}, metadata)
	}
	if s.Name != nil {
		v := *s.Name

		metadata := protocol.Metadata{}
		e.SetValue(protocol.BodyTarget, "Name", protocol.QuotedValue{ValueMarshaler: protocol.StringValue(v)}, metadata)
	}
	if s.RetrievalRoleArn != nil {
		v := *s.RetrievalRoleArn

		metadata := protocol.Metadata{}
		e.SetValue(protocol.BodyTarget, "RetrievalRoleArn", protocol.QuotedValue{ValueMarshaler: protocol.StringValue(v)}, metadata)
	}
	if s.Validators != nil {
		v := s.Validators

		metadata := protocol.Metadata{}
		ls0 := e.List(protocol.BodyTarget, "Validators", metadata)
		ls0.Start()
		for _, v1 := range v {
			ls0.ListAddFields(v1)
		}
		ls0.End()

	}
	return nil
}

const opUpdateConfigurationProfile = "UpdateConfigurationProfile"

// UpdateConfigurationProfileRequest returns a request value for making API operation for
// Amazon AppConfig.
//
// Updates a configuration profile.
//
//    // Example sending a request using UpdateConfigurationProfileRequest.
//    req := client.UpdateConfigurationProfileRequest(params)
//    resp, err := req.Send(context.TODO())
//    if err == nil {
//        fmt.Println(resp)
//    }
//
// Please also see https://docs.aws.amazon.com/goto/WebAPI/appconfig-2019-10-09/UpdateConfigurationProfile
func (c *Client) UpdateConfigurationProfileRequest(input *UpdateConfigurationProfileInput) UpdateConfigurationProfileRequest {
	op := &aws.Operation{
		Name:       opUpdateConfigurationProfile,
		HTTPMethod: "PATCH",
		HTTPPath:   "/applications/{ApplicationId}/configurationprofiles/{ConfigurationProfileId}",
	}

	if input == nil {
		input = &UpdateConfigurationProfileInput{}
	}

	req := c.newRequest(op, input, &UpdateConfigurationProfileOutput{})

	return UpdateConfigurationProfileRequest{Request: req, Input: input, Copy: c.UpdateConfigurationProfileRequest}
}

// UpdateConfigurationProfileRequest is the request type for the
// UpdateConfigurationProfile API operation.
type UpdateConfigurationProfileRequest struct {
	*aws.Request
	Input *UpdateConfigurationProfileInput
	Copy  func(*UpdateConfigurationProfileInput) UpdateConfigurationProfileRequest
}

// Send marshals and sends the UpdateConfigurationProfile API request.
func (r UpdateConfigurationProfileRequest) Send(ctx context.Context) (*UpdateConfigurationProfileResponse, error) {
	r.Request.SetContext(ctx)
	err := r.Request.Send()
	if err != nil {
		return nil, err
	}

	resp := &UpdateConfigurationProfileResponse{
		UpdateConfigurationProfileOutput: r.Request.Data.(*UpdateConfigurationProfileOutput),
		response:                         &aws.Response{Request: r.Request},
	}

	return resp, nil
}

// UpdateConfigurationProfileResponse is the response type for the
// UpdateConfigurationProfile API operation.
type UpdateConfigurationProfileResponse struct {
	*UpdateConfigurationProfileOutput

	response *aws.Response
}

// SDKResponseMetdata returns the response metadata for the
// UpdateConfigurationProfile request.
func (r *UpdateConfigurationProfileResponse) SDKResponseMetdata() *aws.Response {
	return r.response
}
