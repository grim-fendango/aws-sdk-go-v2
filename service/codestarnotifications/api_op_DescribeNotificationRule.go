// Code generated by private/model/cli/gen-api/main.go. DO NOT EDIT.

package codestarnotifications

import (
	"context"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/internal/awsutil"
	"github.com/aws/aws-sdk-go-v2/private/protocol"
)

type DescribeNotificationRuleInput struct {
	_ struct{} `type:"structure"`

	// The Amazon Resource Name (ARN) of the notification rule.
	//
	// Arn is a required field
	Arn *string `type:"string" required:"true"`
}

// String returns the string representation
func (s DescribeNotificationRuleInput) String() string {
	return awsutil.Prettify(s)
}

// Validate inspects the fields of the type to determine if they are valid.
func (s *DescribeNotificationRuleInput) Validate() error {
	invalidParams := aws.ErrInvalidParams{Context: "DescribeNotificationRuleInput"}

	if s.Arn == nil {
		invalidParams.Add(aws.NewErrParamRequired("Arn"))
	}

	if invalidParams.Len() > 0 {
		return invalidParams
	}
	return nil
}

// MarshalFields encodes the AWS API shape using the passed in protocol encoder.
func (s DescribeNotificationRuleInput) MarshalFields(e protocol.FieldEncoder) error {
	e.SetValue(protocol.HeaderTarget, "Content-Type", protocol.StringValue("application/json"), protocol.Metadata{})

	if s.Arn != nil {
		v := *s.Arn

		metadata := protocol.Metadata{}
		e.SetValue(protocol.BodyTarget, "Arn", protocol.QuotedValue{ValueMarshaler: protocol.StringValue(v)}, metadata)
	}
	return nil
}

type DescribeNotificationRuleOutput struct {
	_ struct{} `type:"structure"`

	// The Amazon Resource Name (ARN) of the notification rule.
	//
	// Arn is a required field
	Arn *string `type:"string" required:"true"`

	// The name or email alias of the person who created the notification rule.
	CreatedBy *string `min:"1" type:"string"`

	// The date and time the notification rule was created, in timestamp format.
	CreatedTimestamp *time.Time `type:"timestamp"`

	// The level of detail included in the notifications for this resource. BASIC
	// will include only the contents of the event as it would appear in AWS CloudWatch.
	// FULL will include any supplemental information provided by AWS CodeStar Notifications
	// and/or the service for the resource for which the notification is created.
	DetailType DetailType `type:"string" enum:"true"`

	// A list of the event types associated with the notification rule.
	EventTypes []EventTypeSummary `type:"list"`

	// The date and time the notification rule was most recently updated, in timestamp
	// format.
	LastModifiedTimestamp *time.Time `type:"timestamp"`

	// The name of the notification rule.
	Name *string `min:"1" type:"string" sensitive:"true"`

	// The Amazon Resource Name (ARN) of the resource associated with the notification
	// rule.
	Resource *string `type:"string"`

	// The status of the notification rule. Valid statuses are on (sending notifications)
	// or off (not sending notifications).
	Status NotificationRuleStatus `type:"string" enum:"true"`

	// The tags associated with the notification rule.
	Tags map[string]string `type:"map"`

	// A list of the SNS topics associated with the notification rule.
	Targets []TargetSummary `type:"list"`
}

// String returns the string representation
func (s DescribeNotificationRuleOutput) String() string {
	return awsutil.Prettify(s)
}

// MarshalFields encodes the AWS API shape using the passed in protocol encoder.
func (s DescribeNotificationRuleOutput) MarshalFields(e protocol.FieldEncoder) error {
	if s.Arn != nil {
		v := *s.Arn

		metadata := protocol.Metadata{}
		e.SetValue(protocol.BodyTarget, "Arn", protocol.QuotedValue{ValueMarshaler: protocol.StringValue(v)}, metadata)
	}
	if s.CreatedBy != nil {
		v := *s.CreatedBy

		metadata := protocol.Metadata{}
		e.SetValue(protocol.BodyTarget, "CreatedBy", protocol.QuotedValue{ValueMarshaler: protocol.StringValue(v)}, metadata)
	}
	if s.CreatedTimestamp != nil {
		v := *s.CreatedTimestamp

		metadata := protocol.Metadata{}
		e.SetValue(protocol.BodyTarget, "CreatedTimestamp",
			protocol.TimeValue{V: v, Format: protocol.UnixTimeFormatName, QuotedFormatTime: true}, metadata)
	}
	if len(s.DetailType) > 0 {
		v := s.DetailType

		metadata := protocol.Metadata{}
		e.SetValue(protocol.BodyTarget, "DetailType", protocol.QuotedValue{ValueMarshaler: v}, metadata)
	}
	if s.EventTypes != nil {
		v := s.EventTypes

		metadata := protocol.Metadata{}
		ls0 := e.List(protocol.BodyTarget, "EventTypes", metadata)
		ls0.Start()
		for _, v1 := range v {
			ls0.ListAddFields(v1)
		}
		ls0.End()

	}
	if s.LastModifiedTimestamp != nil {
		v := *s.LastModifiedTimestamp

		metadata := protocol.Metadata{}
		e.SetValue(protocol.BodyTarget, "LastModifiedTimestamp",
			protocol.TimeValue{V: v, Format: protocol.UnixTimeFormatName, QuotedFormatTime: true}, metadata)
	}
	if s.Name != nil {
		v := *s.Name

		metadata := protocol.Metadata{}
		e.SetValue(protocol.BodyTarget, "Name", protocol.QuotedValue{ValueMarshaler: protocol.StringValue(v)}, metadata)
	}
	if s.Resource != nil {
		v := *s.Resource

		metadata := protocol.Metadata{}
		e.SetValue(protocol.BodyTarget, "Resource", protocol.QuotedValue{ValueMarshaler: protocol.StringValue(v)}, metadata)
	}
	if len(s.Status) > 0 {
		v := s.Status

		metadata := protocol.Metadata{}
		e.SetValue(protocol.BodyTarget, "Status", protocol.QuotedValue{ValueMarshaler: v}, metadata)
	}
	if s.Tags != nil {
		v := s.Tags

		metadata := protocol.Metadata{}
		ms0 := e.Map(protocol.BodyTarget, "Tags", metadata)
		ms0.Start()
		for k1, v1 := range v {
			ms0.MapSetValue(k1, protocol.QuotedValue{ValueMarshaler: protocol.StringValue(v1)})
		}
		ms0.End()

	}
	if s.Targets != nil {
		v := s.Targets

		metadata := protocol.Metadata{}
		ls0 := e.List(protocol.BodyTarget, "Targets", metadata)
		ls0.Start()
		for _, v1 := range v {
			ls0.ListAddFields(v1)
		}
		ls0.End()

	}
	return nil
}

const opDescribeNotificationRule = "DescribeNotificationRule"

// DescribeNotificationRuleRequest returns a request value for making API operation for
// AWS CodeStar Notifications.
//
// Returns information about a specified notification rule.
//
//    // Example sending a request using DescribeNotificationRuleRequest.
//    req := client.DescribeNotificationRuleRequest(params)
//    resp, err := req.Send(context.TODO())
//    if err == nil {
//        fmt.Println(resp)
//    }
//
// Please also see https://docs.aws.amazon.com/goto/WebAPI/codestar-notifications-2019-10-15/DescribeNotificationRule
func (c *Client) DescribeNotificationRuleRequest(input *DescribeNotificationRuleInput) DescribeNotificationRuleRequest {
	op := &aws.Operation{
		Name:       opDescribeNotificationRule,
		HTTPMethod: "POST",
		HTTPPath:   "/describeNotificationRule",
	}

	if input == nil {
		input = &DescribeNotificationRuleInput{}
	}

	req := c.newRequest(op, input, &DescribeNotificationRuleOutput{})

	return DescribeNotificationRuleRequest{Request: req, Input: input, Copy: c.DescribeNotificationRuleRequest}
}

// DescribeNotificationRuleRequest is the request type for the
// DescribeNotificationRule API operation.
type DescribeNotificationRuleRequest struct {
	*aws.Request
	Input *DescribeNotificationRuleInput
	Copy  func(*DescribeNotificationRuleInput) DescribeNotificationRuleRequest
}

// Send marshals and sends the DescribeNotificationRule API request.
func (r DescribeNotificationRuleRequest) Send(ctx context.Context) (*DescribeNotificationRuleResponse, error) {
	r.Request.SetContext(ctx)
	err := r.Request.Send()
	if err != nil {
		return nil, err
	}

	resp := &DescribeNotificationRuleResponse{
		DescribeNotificationRuleOutput: r.Request.Data.(*DescribeNotificationRuleOutput),
		response:                       &aws.Response{Request: r.Request},
	}

	return resp, nil
}

// DescribeNotificationRuleResponse is the response type for the
// DescribeNotificationRule API operation.
type DescribeNotificationRuleResponse struct {
	*DescribeNotificationRuleOutput

	response *aws.Response
}

// SDKResponseMetdata returns the response metadata for the
// DescribeNotificationRule request.
func (r *DescribeNotificationRuleResponse) SDKResponseMetdata() *aws.Response {
	return r.response
}
