// Code generated by private/model/cli/gen-api/main.go. DO NOT EDIT.

package organizations

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/internal/awsutil"
)

type CreateGovCloudAccountInput struct {
	_ struct{} `type:"structure"`

	// The friendly name of the member account.
	//
	// AccountName is a required field
	AccountName *string `min:"1" type:"string" required:"true" sensitive:"true"`

	// The email address of the owner to assign to the new member account in the
	// commercial Region. This email address must not already be associated with
	// another AWS account. You must use a valid email address to complete account
	// creation. You can't access the root user of the account or remove an account
	// that was created with an invalid email address. Like all request parameters
	// for CreateGovCloudAccount, the request for the email address for the AWS
	// GovCloud (US) account originates from the commercial Region, not from the
	// AWS GovCloud (US) Region.
	//
	// Email is a required field
	Email *string `min:"6" type:"string" required:"true" sensitive:"true"`

	// If set to ALLOW, the new linked account in the commercial Region enables
	// IAM users to access account billing information if they have the required
	// permissions. If set to DENY, only the root user of the new account can access
	// account billing information. For more information, see Activating Access
	// to the Billing and Cost Management Console (https://docs.aws.amazon.com/awsaccountbilling/latest/aboutv2/grantaccess.html#ControllingAccessWebsite-Activate)
	// in the AWS Billing and Cost Management User Guide.
	//
	// If you don't specify this parameter, the value defaults to ALLOW, and IAM
	// users and roles with the required permissions can access billing information
	// for the new account.
	IamUserAccessToBilling IAMUserAccessToBilling `type:"string" enum:"true"`

	// (Optional)
	//
	// The name of an IAM role that AWS Organizations automatically preconfigures
	// in the new member accounts in both the AWS GovCloud (US) Region and in the
	// commercial Region. This role trusts the master account, allowing users in
	// the master account to assume the role, as permitted by the master account
	// administrator. The role has administrator permissions in the new member account.
	//
	// If you don't specify this parameter, the role name defaults to OrganizationAccountAccessRole.
	//
	// For more information about how to use this role to access the member account,
	// see Accessing and Administering the Member Accounts in Your Organization
	// (https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_accounts_access.html#orgs_manage_accounts_create-cross-account-role)
	// in the AWS Organizations User Guide and steps 2 and 3 in Tutorial: Delegate
	// Access Across AWS Accounts Using IAM Roles (https://docs.aws.amazon.com/IAM/latest/UserGuide/tutorial_cross-account-with-roles.html)
	// in the IAM User Guide.
	//
	// The regex pattern (http://wikipedia.org/wiki/regex) that is used to validate
	// this parameter. The pattern can include uppercase letters, lowercase letters,
	// digits with no spaces, and any of the following characters: =,.@-
	RoleName *string `type:"string"`
}

// String returns the string representation
func (s CreateGovCloudAccountInput) String() string {
	return awsutil.Prettify(s)
}

// Validate inspects the fields of the type to determine if they are valid.
func (s *CreateGovCloudAccountInput) Validate() error {
	invalidParams := aws.ErrInvalidParams{Context: "CreateGovCloudAccountInput"}

	if s.AccountName == nil {
		invalidParams.Add(aws.NewErrParamRequired("AccountName"))
	}
	if s.AccountName != nil && len(*s.AccountName) < 1 {
		invalidParams.Add(aws.NewErrParamMinLen("AccountName", 1))
	}

	if s.Email == nil {
		invalidParams.Add(aws.NewErrParamRequired("Email"))
	}
	if s.Email != nil && len(*s.Email) < 6 {
		invalidParams.Add(aws.NewErrParamMinLen("Email", 6))
	}

	if invalidParams.Len() > 0 {
		return invalidParams
	}
	return nil
}

type CreateGovCloudAccountOutput struct {
	_ struct{} `type:"structure"`

	// Contains the status about a CreateAccount or CreateGovCloudAccount request
	// to create an AWS account or an AWS GovCloud (US) account in an organization.
	CreateAccountStatus *CreateAccountStatus `type:"structure"`
}

// String returns the string representation
func (s CreateGovCloudAccountOutput) String() string {
	return awsutil.Prettify(s)
}

const opCreateGovCloudAccount = "CreateGovCloudAccount"

// CreateGovCloudAccountRequest returns a request value for making API operation for
// AWS Organizations.
//
// This action is available if all of the following are true:
//
//    * You're authorized to create accounts in the AWS GovCloud (US) Region.
//    For more information on the AWS GovCloud (US) Region, see the AWS GovCloud
//    User Guide. (http://docs.aws.amazon.com/govcloud-us/latest/UserGuide/welcome.html)
//
//    * You already have an account in the AWS GovCloud (US) Region that is
//    associated with your master account in the commercial Region.
//
//    * You call this action from the master account of your organization in
//    the commercial Region.
//
//    * You have the organizations:CreateGovCloudAccount permission. AWS Organizations
//    creates the required service-linked role named AWSServiceRoleForOrganizations.
//    For more information, see AWS Organizations and Service-Linked Roles (http://docs.aws.amazon.com/organizations/latest/userguide/orgs_integrate_services.html#orgs_integrate_services-using_slrs)
//    in the AWS Organizations User Guide.
//
// AWS automatically enables AWS CloudTrail for AWS GovCloud (US) accounts,
// but you should also do the following:
//
//    * Verify that AWS CloudTrail is enabled to store logs.
//
//    * Create an S3 bucket for AWS CloudTrail log storage. For more information,
//    see Verifying AWS CloudTrail Is Enabled (http://docs.aws.amazon.com/govcloud-us/latest/UserGuide/verifying-cloudtrail.html)
//    in the AWS GovCloud User Guide.
//
// You call this action from the master account of your organization in the
// commercial Region to create a standalone AWS account in the AWS GovCloud
// (US) Region. After the account is created, the master account of an organization
// in the AWS GovCloud (US) Region can invite it to that organization. For more
// information on inviting standalone accounts in the AWS GovCloud (US) to join
// an organization, see AWS Organizations (http://docs.aws.amazon.com/govcloud-us/latest/UserGuide/govcloud-organizations.html)
// in the AWS GovCloud User Guide.
//
// Calling CreateGovCloudAccount is an asynchronous request that AWS performs
// in the background. Because CreateGovCloudAccount operates asynchronously,
// it can return a successful completion message even though account initialization
// might still be in progress. You might need to wait a few minutes before you
// can successfully access the account. To check the status of the request,
// do one of the following:
//
//    * Use the OperationId response element from this operation to provide
//    as a parameter to the DescribeCreateAccountStatus operation.
//
//    * Check the AWS CloudTrail log for the CreateAccountResult event. For
//    information on using AWS CloudTrail with Organizations, see Monitoring
//    the Activity in Your Organization (http://docs.aws.amazon.com/organizations/latest/userguide/orgs_monitoring.html)
//    in the AWS Organizations User Guide.
//
// When you call the CreateGovCloudAccount action, you create two accounts:
// a standalone account in the AWS GovCloud (US) Region and an associated account
// in the commercial Region for billing and support purposes. The account in
// the commercial Region is automatically a member of the organization whose
// credentials made the request. Both accounts are associated with the same
// email address.
//
// A role is created in the new account in the commercial Region that allows
// the master account in the organization in the commercial Region to assume
// it. An AWS GovCloud (US) account is then created and associated with the
// commercial account that you just created. A role is created in the new AWS
// GovCloud (US) account that can be assumed by the AWS GovCloud (US) account
// that is associated with the master account of the commercial organization.
// For more information and to view a diagram that explains how account access
// works, see AWS Organizations (http://docs.aws.amazon.com/govcloud-us/latest/UserGuide/govcloud-organizations.html)
// in the AWS GovCloud User Guide.
//
// For more information about creating accounts, see Creating an AWS Account
// in Your Organization (https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_accounts_create.html)
// in the AWS Organizations User Guide.
//
//    * When you create an account in an organization using the AWS Organizations
//    console, API, or CLI commands, the information required for the account
//    to operate as a standalone account is not automatically collected. This
//    includes a payment method and signing the end user license agreement (EULA).
//    If you must remove an account from your organization later, you can do
//    so only after you provide the missing information. Follow the steps at
//    To leave an organization as a member account (http://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_accounts_remove.html#leave-without-all-info)
//    in the AWS Organizations User Guide.
//
//    * If you get an exception that indicates that you exceeded your account
//    limits for the organization, contact AWS Support (https://console.aws.amazon.com/support/home#/).
//
//    * If you get an exception that indicates that the operation failed because
//    your organization is still initializing, wait one hour and then try again.
//    If the error persists, contact AWS Support (https://console.aws.amazon.com/support/home#/).
//
//    * Using CreateGovCloudAccount to create multiple temporary accounts isn't
//    recommended. You can only close an account from the AWS Billing and Cost
//    Management console, and you must be signed in as the root user. For information
//    on the requirements and process for closing an account, see Closing an
//    AWS Account (http://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_accounts_close.html)
//    in the AWS Organizations User Guide.
//
// When you create a member account with this operation, you can choose whether
// to create the account with the IAM User and Role Access to Billing Information
// switch enabled. If you enable it, IAM users and roles that have appropriate
// permissions can view billing information for the account. If you disable
// it, only the account root user can access billing information. For information
// about how to disable this switch for an account, see Granting Access to Your
// Billing Information and Tools (https://docs.aws.amazon.com/awsaccountbilling/latest/aboutv2/grantaccess.html).
//
//    // Example sending a request using CreateGovCloudAccountRequest.
//    req := client.CreateGovCloudAccountRequest(params)
//    resp, err := req.Send(context.TODO())
//    if err == nil {
//        fmt.Println(resp)
//    }
//
// Please also see https://docs.aws.amazon.com/goto/WebAPI/organizations-2016-11-28/CreateGovCloudAccount
func (c *Client) CreateGovCloudAccountRequest(input *CreateGovCloudAccountInput) CreateGovCloudAccountRequest {
	op := &aws.Operation{
		Name:       opCreateGovCloudAccount,
		HTTPMethod: "POST",
		HTTPPath:   "/",
	}

	if input == nil {
		input = &CreateGovCloudAccountInput{}
	}

	req := c.newRequest(op, input, &CreateGovCloudAccountOutput{})

	return CreateGovCloudAccountRequest{Request: req, Input: input, Copy: c.CreateGovCloudAccountRequest}
}

// CreateGovCloudAccountRequest is the request type for the
// CreateGovCloudAccount API operation.
type CreateGovCloudAccountRequest struct {
	*aws.Request
	Input *CreateGovCloudAccountInput
	Copy  func(*CreateGovCloudAccountInput) CreateGovCloudAccountRequest
}

// Send marshals and sends the CreateGovCloudAccount API request.
func (r CreateGovCloudAccountRequest) Send(ctx context.Context) (*CreateGovCloudAccountResponse, error) {
	r.Request.SetContext(ctx)
	err := r.Request.Send()
	if err != nil {
		return nil, err
	}

	resp := &CreateGovCloudAccountResponse{
		CreateGovCloudAccountOutput: r.Request.Data.(*CreateGovCloudAccountOutput),
		response:                    &aws.Response{Request: r.Request},
	}

	return resp, nil
}

// CreateGovCloudAccountResponse is the response type for the
// CreateGovCloudAccount API operation.
type CreateGovCloudAccountResponse struct {
	*CreateGovCloudAccountOutput

	response *aws.Response
}

// SDKResponseMetdata returns the response metadata for the
// CreateGovCloudAccount request.
func (r *CreateGovCloudAccountResponse) SDKResponseMetdata() *aws.Response {
	return r.response
}