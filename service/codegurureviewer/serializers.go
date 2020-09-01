// Code generated by smithy-go-codegen DO NOT EDIT.

package codegurureviewer

import (
	"bytes"
	"context"
	"fmt"
	"github.com/aws/aws-sdk-go-v2/service/codegurureviewer/types"
	smithy "github.com/awslabs/smithy-go"
	"github.com/awslabs/smithy-go/httpbinding"
	smithyjson "github.com/awslabs/smithy-go/json"
	"github.com/awslabs/smithy-go/middleware"
	smithyhttp "github.com/awslabs/smithy-go/transport/http"
)

type awsRestjson1_serializeOpAssociateRepository struct {
}

func (*awsRestjson1_serializeOpAssociateRepository) ID() string {
	return "OperationSerializer"
}

func (m *awsRestjson1_serializeOpAssociateRepository) HandleSerialize(ctx context.Context, in middleware.SerializeInput, next middleware.SerializeHandler) (
	out middleware.SerializeOutput, metadata middleware.Metadata, err error,
) {
	request, ok := in.Request.(*smithyhttp.Request)
	if !ok {
		return out, metadata, &smithy.SerializationError{Err: fmt.Errorf("unknown transport type %T", in.Request)}
	}

	input, ok := in.Parameters.(*AssociateRepositoryInput)
	_ = input
	if !ok {
		return out, metadata, &smithy.SerializationError{Err: fmt.Errorf("unknown input parameters type %T", in.Parameters)}
	}

	opPath, opQuery := httpbinding.SplitURI("/associations")
	request.URL.Path = opPath
	if len(request.URL.RawQuery) > 0 {
		request.URL.RawQuery = "&" + opQuery
	} else {
		request.URL.RawQuery = opQuery
	}

	request.Method = "POST"
	restEncoder, err := httpbinding.NewEncoder(request.URL.Path, request.URL.RawQuery, request.Header)
	if err != nil {
		return out, metadata, &smithy.SerializationError{Err: err}
	}

	restEncoder.SetHeader("Content-Type").String("application/json")

	jsonEncoder := smithyjson.NewEncoder()
	if err := awsRestjson1_serializeDocumentAssociateRepositoryInput(input, jsonEncoder.Value); err != nil {
		return out, metadata, &smithy.SerializationError{Err: err}
	}

	if request, err = request.SetStream(bytes.NewReader(jsonEncoder.Bytes())); err != nil {
		return out, metadata, &smithy.SerializationError{Err: err}
	}

	if request.Request, err = restEncoder.Encode(request.Request); err != nil {
		return out, metadata, &smithy.SerializationError{Err: err}
	}
	in.Request = request

	return next.HandleSerialize(ctx, in)
}
func awsRestjson1_serializeHttpBindingsAssociateRepositoryInput(v *AssociateRepositoryInput, encoder *httpbinding.Encoder) error {
	if v == nil {
		return fmt.Errorf("unsupported serialization of nil %T", v)
	}

	return nil
}

func awsRestjson1_serializeDocumentAssociateRepositoryInput(v *AssociateRepositoryInput, value smithyjson.Value) error {
	object := value.Object()
	defer object.Close()

	if v.ClientRequestToken != nil {
		ok := object.Key("ClientRequestToken")
		ok.String(*v.ClientRequestToken)
	}

	if v.Repository != nil {
		ok := object.Key("Repository")
		if err := awsRestjson1_serializeDocumentRepository(v.Repository, ok); err != nil {
			return err
		}
	}

	return nil
}

type awsRestjson1_serializeOpDescribeCodeReview struct {
}

func (*awsRestjson1_serializeOpDescribeCodeReview) ID() string {
	return "OperationSerializer"
}

func (m *awsRestjson1_serializeOpDescribeCodeReview) HandleSerialize(ctx context.Context, in middleware.SerializeInput, next middleware.SerializeHandler) (
	out middleware.SerializeOutput, metadata middleware.Metadata, err error,
) {
	request, ok := in.Request.(*smithyhttp.Request)
	if !ok {
		return out, metadata, &smithy.SerializationError{Err: fmt.Errorf("unknown transport type %T", in.Request)}
	}

	input, ok := in.Parameters.(*DescribeCodeReviewInput)
	_ = input
	if !ok {
		return out, metadata, &smithy.SerializationError{Err: fmt.Errorf("unknown input parameters type %T", in.Parameters)}
	}

	opPath, opQuery := httpbinding.SplitURI("/codereviews/{CodeReviewArn}")
	request.URL.Path = opPath
	if len(request.URL.RawQuery) > 0 {
		request.URL.RawQuery = "&" + opQuery
	} else {
		request.URL.RawQuery = opQuery
	}

	request.Method = "GET"
	restEncoder, err := httpbinding.NewEncoder(request.URL.Path, request.URL.RawQuery, request.Header)
	if err != nil {
		return out, metadata, &smithy.SerializationError{Err: err}
	}

	if err := awsRestjson1_serializeHttpBindingsDescribeCodeReviewInput(input, restEncoder); err != nil {
		return out, metadata, &smithy.SerializationError{Err: err}
	}

	if request.Request, err = restEncoder.Encode(request.Request); err != nil {
		return out, metadata, &smithy.SerializationError{Err: err}
	}
	in.Request = request

	return next.HandleSerialize(ctx, in)
}
func awsRestjson1_serializeHttpBindingsDescribeCodeReviewInput(v *DescribeCodeReviewInput, encoder *httpbinding.Encoder) error {
	if v == nil {
		return fmt.Errorf("unsupported serialization of nil %T", v)
	}

	if v.CodeReviewArn != nil {
		if err := encoder.SetURI("CodeReviewArn").String(*v.CodeReviewArn); err != nil {
			return err
		}
	}

	return nil
}

type awsRestjson1_serializeOpDescribeRecommendationFeedback struct {
}

func (*awsRestjson1_serializeOpDescribeRecommendationFeedback) ID() string {
	return "OperationSerializer"
}

func (m *awsRestjson1_serializeOpDescribeRecommendationFeedback) HandleSerialize(ctx context.Context, in middleware.SerializeInput, next middleware.SerializeHandler) (
	out middleware.SerializeOutput, metadata middleware.Metadata, err error,
) {
	request, ok := in.Request.(*smithyhttp.Request)
	if !ok {
		return out, metadata, &smithy.SerializationError{Err: fmt.Errorf("unknown transport type %T", in.Request)}
	}

	input, ok := in.Parameters.(*DescribeRecommendationFeedbackInput)
	_ = input
	if !ok {
		return out, metadata, &smithy.SerializationError{Err: fmt.Errorf("unknown input parameters type %T", in.Parameters)}
	}

	opPath, opQuery := httpbinding.SplitURI("/feedback/{CodeReviewArn}")
	request.URL.Path = opPath
	if len(request.URL.RawQuery) > 0 {
		request.URL.RawQuery = "&" + opQuery
	} else {
		request.URL.RawQuery = opQuery
	}

	request.Method = "GET"
	restEncoder, err := httpbinding.NewEncoder(request.URL.Path, request.URL.RawQuery, request.Header)
	if err != nil {
		return out, metadata, &smithy.SerializationError{Err: err}
	}

	if err := awsRestjson1_serializeHttpBindingsDescribeRecommendationFeedbackInput(input, restEncoder); err != nil {
		return out, metadata, &smithy.SerializationError{Err: err}
	}

	if request.Request, err = restEncoder.Encode(request.Request); err != nil {
		return out, metadata, &smithy.SerializationError{Err: err}
	}
	in.Request = request

	return next.HandleSerialize(ctx, in)
}
func awsRestjson1_serializeHttpBindingsDescribeRecommendationFeedbackInput(v *DescribeRecommendationFeedbackInput, encoder *httpbinding.Encoder) error {
	if v == nil {
		return fmt.Errorf("unsupported serialization of nil %T", v)
	}

	if v.CodeReviewArn != nil {
		if err := encoder.SetURI("CodeReviewArn").String(*v.CodeReviewArn); err != nil {
			return err
		}
	}

	if v.RecommendationId != nil {
		encoder.SetQuery("RecommendationId").String(*v.RecommendationId)
	}

	if v.UserId != nil {
		encoder.SetQuery("UserId").String(*v.UserId)
	}

	return nil
}

type awsRestjson1_serializeOpDescribeRepositoryAssociation struct {
}

func (*awsRestjson1_serializeOpDescribeRepositoryAssociation) ID() string {
	return "OperationSerializer"
}

func (m *awsRestjson1_serializeOpDescribeRepositoryAssociation) HandleSerialize(ctx context.Context, in middleware.SerializeInput, next middleware.SerializeHandler) (
	out middleware.SerializeOutput, metadata middleware.Metadata, err error,
) {
	request, ok := in.Request.(*smithyhttp.Request)
	if !ok {
		return out, metadata, &smithy.SerializationError{Err: fmt.Errorf("unknown transport type %T", in.Request)}
	}

	input, ok := in.Parameters.(*DescribeRepositoryAssociationInput)
	_ = input
	if !ok {
		return out, metadata, &smithy.SerializationError{Err: fmt.Errorf("unknown input parameters type %T", in.Parameters)}
	}

	opPath, opQuery := httpbinding.SplitURI("/associations/{AssociationArn}")
	request.URL.Path = opPath
	if len(request.URL.RawQuery) > 0 {
		request.URL.RawQuery = "&" + opQuery
	} else {
		request.URL.RawQuery = opQuery
	}

	request.Method = "GET"
	restEncoder, err := httpbinding.NewEncoder(request.URL.Path, request.URL.RawQuery, request.Header)
	if err != nil {
		return out, metadata, &smithy.SerializationError{Err: err}
	}

	if err := awsRestjson1_serializeHttpBindingsDescribeRepositoryAssociationInput(input, restEncoder); err != nil {
		return out, metadata, &smithy.SerializationError{Err: err}
	}

	if request.Request, err = restEncoder.Encode(request.Request); err != nil {
		return out, metadata, &smithy.SerializationError{Err: err}
	}
	in.Request = request

	return next.HandleSerialize(ctx, in)
}
func awsRestjson1_serializeHttpBindingsDescribeRepositoryAssociationInput(v *DescribeRepositoryAssociationInput, encoder *httpbinding.Encoder) error {
	if v == nil {
		return fmt.Errorf("unsupported serialization of nil %T", v)
	}

	if v.AssociationArn != nil {
		if err := encoder.SetURI("AssociationArn").String(*v.AssociationArn); err != nil {
			return err
		}
	}

	return nil
}

type awsRestjson1_serializeOpDisassociateRepository struct {
}

func (*awsRestjson1_serializeOpDisassociateRepository) ID() string {
	return "OperationSerializer"
}

func (m *awsRestjson1_serializeOpDisassociateRepository) HandleSerialize(ctx context.Context, in middleware.SerializeInput, next middleware.SerializeHandler) (
	out middleware.SerializeOutput, metadata middleware.Metadata, err error,
) {
	request, ok := in.Request.(*smithyhttp.Request)
	if !ok {
		return out, metadata, &smithy.SerializationError{Err: fmt.Errorf("unknown transport type %T", in.Request)}
	}

	input, ok := in.Parameters.(*DisassociateRepositoryInput)
	_ = input
	if !ok {
		return out, metadata, &smithy.SerializationError{Err: fmt.Errorf("unknown input parameters type %T", in.Parameters)}
	}

	opPath, opQuery := httpbinding.SplitURI("/associations/{AssociationArn}")
	request.URL.Path = opPath
	if len(request.URL.RawQuery) > 0 {
		request.URL.RawQuery = "&" + opQuery
	} else {
		request.URL.RawQuery = opQuery
	}

	request.Method = "DELETE"
	restEncoder, err := httpbinding.NewEncoder(request.URL.Path, request.URL.RawQuery, request.Header)
	if err != nil {
		return out, metadata, &smithy.SerializationError{Err: err}
	}

	if err := awsRestjson1_serializeHttpBindingsDisassociateRepositoryInput(input, restEncoder); err != nil {
		return out, metadata, &smithy.SerializationError{Err: err}
	}

	if request.Request, err = restEncoder.Encode(request.Request); err != nil {
		return out, metadata, &smithy.SerializationError{Err: err}
	}
	in.Request = request

	return next.HandleSerialize(ctx, in)
}
func awsRestjson1_serializeHttpBindingsDisassociateRepositoryInput(v *DisassociateRepositoryInput, encoder *httpbinding.Encoder) error {
	if v == nil {
		return fmt.Errorf("unsupported serialization of nil %T", v)
	}

	if v.AssociationArn != nil {
		if err := encoder.SetURI("AssociationArn").String(*v.AssociationArn); err != nil {
			return err
		}
	}

	return nil
}

type awsRestjson1_serializeOpListCodeReviews struct {
}

func (*awsRestjson1_serializeOpListCodeReviews) ID() string {
	return "OperationSerializer"
}

func (m *awsRestjson1_serializeOpListCodeReviews) HandleSerialize(ctx context.Context, in middleware.SerializeInput, next middleware.SerializeHandler) (
	out middleware.SerializeOutput, metadata middleware.Metadata, err error,
) {
	request, ok := in.Request.(*smithyhttp.Request)
	if !ok {
		return out, metadata, &smithy.SerializationError{Err: fmt.Errorf("unknown transport type %T", in.Request)}
	}

	input, ok := in.Parameters.(*ListCodeReviewsInput)
	_ = input
	if !ok {
		return out, metadata, &smithy.SerializationError{Err: fmt.Errorf("unknown input parameters type %T", in.Parameters)}
	}

	opPath, opQuery := httpbinding.SplitURI("/codereviews")
	request.URL.Path = opPath
	if len(request.URL.RawQuery) > 0 {
		request.URL.RawQuery = "&" + opQuery
	} else {
		request.URL.RawQuery = opQuery
	}

	request.Method = "GET"
	restEncoder, err := httpbinding.NewEncoder(request.URL.Path, request.URL.RawQuery, request.Header)
	if err != nil {
		return out, metadata, &smithy.SerializationError{Err: err}
	}

	if err := awsRestjson1_serializeHttpBindingsListCodeReviewsInput(input, restEncoder); err != nil {
		return out, metadata, &smithy.SerializationError{Err: err}
	}

	if request.Request, err = restEncoder.Encode(request.Request); err != nil {
		return out, metadata, &smithy.SerializationError{Err: err}
	}
	in.Request = request

	return next.HandleSerialize(ctx, in)
}
func awsRestjson1_serializeHttpBindingsListCodeReviewsInput(v *ListCodeReviewsInput, encoder *httpbinding.Encoder) error {
	if v == nil {
		return fmt.Errorf("unsupported serialization of nil %T", v)
	}

	if v.MaxResults != nil {
		encoder.SetQuery("MaxResults").Integer(*v.MaxResults)
	}

	if v.NextToken != nil {
		encoder.SetQuery("NextToken").String(*v.NextToken)
	}

	if v.ProviderTypes != nil {
		for i := range v.ProviderTypes {
			encoder.AddQuery("ProviderTypes").String(string(v.ProviderTypes[i]))
		}
	}

	if v.RepositoryNames != nil {
		for i := range v.RepositoryNames {
			if v.RepositoryNames[i] == nil {
				continue
			}
			encoder.AddQuery("RepositoryNames").String(*v.RepositoryNames[i])
		}
	}

	if v.States != nil {
		for i := range v.States {
			encoder.AddQuery("States").String(string(v.States[i]))
		}
	}

	if len(v.Type) > 0 {
		encoder.SetQuery("Type").String(string(v.Type))
	}

	return nil
}

type awsRestjson1_serializeOpListRecommendationFeedback struct {
}

func (*awsRestjson1_serializeOpListRecommendationFeedback) ID() string {
	return "OperationSerializer"
}

func (m *awsRestjson1_serializeOpListRecommendationFeedback) HandleSerialize(ctx context.Context, in middleware.SerializeInput, next middleware.SerializeHandler) (
	out middleware.SerializeOutput, metadata middleware.Metadata, err error,
) {
	request, ok := in.Request.(*smithyhttp.Request)
	if !ok {
		return out, metadata, &smithy.SerializationError{Err: fmt.Errorf("unknown transport type %T", in.Request)}
	}

	input, ok := in.Parameters.(*ListRecommendationFeedbackInput)
	_ = input
	if !ok {
		return out, metadata, &smithy.SerializationError{Err: fmt.Errorf("unknown input parameters type %T", in.Parameters)}
	}

	opPath, opQuery := httpbinding.SplitURI("/feedback/{CodeReviewArn}/RecommendationFeedback")
	request.URL.Path = opPath
	if len(request.URL.RawQuery) > 0 {
		request.URL.RawQuery = "&" + opQuery
	} else {
		request.URL.RawQuery = opQuery
	}

	request.Method = "GET"
	restEncoder, err := httpbinding.NewEncoder(request.URL.Path, request.URL.RawQuery, request.Header)
	if err != nil {
		return out, metadata, &smithy.SerializationError{Err: err}
	}

	if err := awsRestjson1_serializeHttpBindingsListRecommendationFeedbackInput(input, restEncoder); err != nil {
		return out, metadata, &smithy.SerializationError{Err: err}
	}

	if request.Request, err = restEncoder.Encode(request.Request); err != nil {
		return out, metadata, &smithy.SerializationError{Err: err}
	}
	in.Request = request

	return next.HandleSerialize(ctx, in)
}
func awsRestjson1_serializeHttpBindingsListRecommendationFeedbackInput(v *ListRecommendationFeedbackInput, encoder *httpbinding.Encoder) error {
	if v == nil {
		return fmt.Errorf("unsupported serialization of nil %T", v)
	}

	if v.CodeReviewArn != nil {
		if err := encoder.SetURI("CodeReviewArn").String(*v.CodeReviewArn); err != nil {
			return err
		}
	}

	if v.MaxResults != nil {
		encoder.SetQuery("MaxResults").Integer(*v.MaxResults)
	}

	if v.NextToken != nil {
		encoder.SetQuery("NextToken").String(*v.NextToken)
	}

	if v.RecommendationIds != nil {
		for i := range v.RecommendationIds {
			if v.RecommendationIds[i] == nil {
				continue
			}
			encoder.AddQuery("RecommendationIds").String(*v.RecommendationIds[i])
		}
	}

	if v.UserIds != nil {
		for i := range v.UserIds {
			if v.UserIds[i] == nil {
				continue
			}
			encoder.AddQuery("UserIds").String(*v.UserIds[i])
		}
	}

	return nil
}

type awsRestjson1_serializeOpListRecommendations struct {
}

func (*awsRestjson1_serializeOpListRecommendations) ID() string {
	return "OperationSerializer"
}

func (m *awsRestjson1_serializeOpListRecommendations) HandleSerialize(ctx context.Context, in middleware.SerializeInput, next middleware.SerializeHandler) (
	out middleware.SerializeOutput, metadata middleware.Metadata, err error,
) {
	request, ok := in.Request.(*smithyhttp.Request)
	if !ok {
		return out, metadata, &smithy.SerializationError{Err: fmt.Errorf("unknown transport type %T", in.Request)}
	}

	input, ok := in.Parameters.(*ListRecommendationsInput)
	_ = input
	if !ok {
		return out, metadata, &smithy.SerializationError{Err: fmt.Errorf("unknown input parameters type %T", in.Parameters)}
	}

	opPath, opQuery := httpbinding.SplitURI("/codereviews/{CodeReviewArn}/Recommendations")
	request.URL.Path = opPath
	if len(request.URL.RawQuery) > 0 {
		request.URL.RawQuery = "&" + opQuery
	} else {
		request.URL.RawQuery = opQuery
	}

	request.Method = "GET"
	restEncoder, err := httpbinding.NewEncoder(request.URL.Path, request.URL.RawQuery, request.Header)
	if err != nil {
		return out, metadata, &smithy.SerializationError{Err: err}
	}

	if err := awsRestjson1_serializeHttpBindingsListRecommendationsInput(input, restEncoder); err != nil {
		return out, metadata, &smithy.SerializationError{Err: err}
	}

	if request.Request, err = restEncoder.Encode(request.Request); err != nil {
		return out, metadata, &smithy.SerializationError{Err: err}
	}
	in.Request = request

	return next.HandleSerialize(ctx, in)
}
func awsRestjson1_serializeHttpBindingsListRecommendationsInput(v *ListRecommendationsInput, encoder *httpbinding.Encoder) error {
	if v == nil {
		return fmt.Errorf("unsupported serialization of nil %T", v)
	}

	if v.CodeReviewArn != nil {
		if err := encoder.SetURI("CodeReviewArn").String(*v.CodeReviewArn); err != nil {
			return err
		}
	}

	if v.MaxResults != nil {
		encoder.SetQuery("MaxResults").Integer(*v.MaxResults)
	}

	if v.NextToken != nil {
		encoder.SetQuery("NextToken").String(*v.NextToken)
	}

	return nil
}

type awsRestjson1_serializeOpListRepositoryAssociations struct {
}

func (*awsRestjson1_serializeOpListRepositoryAssociations) ID() string {
	return "OperationSerializer"
}

func (m *awsRestjson1_serializeOpListRepositoryAssociations) HandleSerialize(ctx context.Context, in middleware.SerializeInput, next middleware.SerializeHandler) (
	out middleware.SerializeOutput, metadata middleware.Metadata, err error,
) {
	request, ok := in.Request.(*smithyhttp.Request)
	if !ok {
		return out, metadata, &smithy.SerializationError{Err: fmt.Errorf("unknown transport type %T", in.Request)}
	}

	input, ok := in.Parameters.(*ListRepositoryAssociationsInput)
	_ = input
	if !ok {
		return out, metadata, &smithy.SerializationError{Err: fmt.Errorf("unknown input parameters type %T", in.Parameters)}
	}

	opPath, opQuery := httpbinding.SplitURI("/associations")
	request.URL.Path = opPath
	if len(request.URL.RawQuery) > 0 {
		request.URL.RawQuery = "&" + opQuery
	} else {
		request.URL.RawQuery = opQuery
	}

	request.Method = "GET"
	restEncoder, err := httpbinding.NewEncoder(request.URL.Path, request.URL.RawQuery, request.Header)
	if err != nil {
		return out, metadata, &smithy.SerializationError{Err: err}
	}

	if err := awsRestjson1_serializeHttpBindingsListRepositoryAssociationsInput(input, restEncoder); err != nil {
		return out, metadata, &smithy.SerializationError{Err: err}
	}

	if request.Request, err = restEncoder.Encode(request.Request); err != nil {
		return out, metadata, &smithy.SerializationError{Err: err}
	}
	in.Request = request

	return next.HandleSerialize(ctx, in)
}
func awsRestjson1_serializeHttpBindingsListRepositoryAssociationsInput(v *ListRepositoryAssociationsInput, encoder *httpbinding.Encoder) error {
	if v == nil {
		return fmt.Errorf("unsupported serialization of nil %T", v)
	}

	if v.MaxResults != nil {
		encoder.SetQuery("MaxResults").Integer(*v.MaxResults)
	}

	if v.Names != nil {
		for i := range v.Names {
			if v.Names[i] == nil {
				continue
			}
			encoder.AddQuery("Name").String(*v.Names[i])
		}
	}

	if v.NextToken != nil {
		encoder.SetQuery("NextToken").String(*v.NextToken)
	}

	if v.Owners != nil {
		for i := range v.Owners {
			if v.Owners[i] == nil {
				continue
			}
			encoder.AddQuery("Owner").String(*v.Owners[i])
		}
	}

	if v.ProviderTypes != nil {
		for i := range v.ProviderTypes {
			encoder.AddQuery("ProviderType").String(string(v.ProviderTypes[i]))
		}
	}

	if v.States != nil {
		for i := range v.States {
			encoder.AddQuery("State").String(string(v.States[i]))
		}
	}

	return nil
}

type awsRestjson1_serializeOpPutRecommendationFeedback struct {
}

func (*awsRestjson1_serializeOpPutRecommendationFeedback) ID() string {
	return "OperationSerializer"
}

func (m *awsRestjson1_serializeOpPutRecommendationFeedback) HandleSerialize(ctx context.Context, in middleware.SerializeInput, next middleware.SerializeHandler) (
	out middleware.SerializeOutput, metadata middleware.Metadata, err error,
) {
	request, ok := in.Request.(*smithyhttp.Request)
	if !ok {
		return out, metadata, &smithy.SerializationError{Err: fmt.Errorf("unknown transport type %T", in.Request)}
	}

	input, ok := in.Parameters.(*PutRecommendationFeedbackInput)
	_ = input
	if !ok {
		return out, metadata, &smithy.SerializationError{Err: fmt.Errorf("unknown input parameters type %T", in.Parameters)}
	}

	opPath, opQuery := httpbinding.SplitURI("/feedback")
	request.URL.Path = opPath
	if len(request.URL.RawQuery) > 0 {
		request.URL.RawQuery = "&" + opQuery
	} else {
		request.URL.RawQuery = opQuery
	}

	request.Method = "PUT"
	restEncoder, err := httpbinding.NewEncoder(request.URL.Path, request.URL.RawQuery, request.Header)
	if err != nil {
		return out, metadata, &smithy.SerializationError{Err: err}
	}

	restEncoder.SetHeader("Content-Type").String("application/json")

	jsonEncoder := smithyjson.NewEncoder()
	if err := awsRestjson1_serializeDocumentPutRecommendationFeedbackInput(input, jsonEncoder.Value); err != nil {
		return out, metadata, &smithy.SerializationError{Err: err}
	}

	if request, err = request.SetStream(bytes.NewReader(jsonEncoder.Bytes())); err != nil {
		return out, metadata, &smithy.SerializationError{Err: err}
	}

	if request.Request, err = restEncoder.Encode(request.Request); err != nil {
		return out, metadata, &smithy.SerializationError{Err: err}
	}
	in.Request = request

	return next.HandleSerialize(ctx, in)
}
func awsRestjson1_serializeHttpBindingsPutRecommendationFeedbackInput(v *PutRecommendationFeedbackInput, encoder *httpbinding.Encoder) error {
	if v == nil {
		return fmt.Errorf("unsupported serialization of nil %T", v)
	}

	return nil
}

func awsRestjson1_serializeDocumentPutRecommendationFeedbackInput(v *PutRecommendationFeedbackInput, value smithyjson.Value) error {
	object := value.Object()
	defer object.Close()

	if v.CodeReviewArn != nil {
		ok := object.Key("CodeReviewArn")
		ok.String(*v.CodeReviewArn)
	}

	if v.Reactions != nil {
		ok := object.Key("Reactions")
		if err := awsRestjson1_serializeDocumentReactions(v.Reactions, ok); err != nil {
			return err
		}
	}

	if v.RecommendationId != nil {
		ok := object.Key("RecommendationId")
		ok.String(*v.RecommendationId)
	}

	return nil
}

func awsRestjson1_serializeDocumentCodeCommitRepository(v *types.CodeCommitRepository, value smithyjson.Value) error {
	object := value.Object()
	defer object.Close()

	if v.Name != nil {
		ok := object.Key("Name")
		ok.String(*v.Name)
	}

	return nil
}

func awsRestjson1_serializeDocumentReactions(v []types.Reaction, value smithyjson.Value) error {
	array := value.Array()
	defer array.Close()

	for i := range v {
		av := array.Value()
		av.String(string(v[i]))
	}
	return nil
}

func awsRestjson1_serializeDocumentRepository(v *types.Repository, value smithyjson.Value) error {
	object := value.Object()
	defer object.Close()

	if v.Bitbucket != nil {
		ok := object.Key("Bitbucket")
		if err := awsRestjson1_serializeDocumentThirdPartySourceRepository(v.Bitbucket, ok); err != nil {
			return err
		}
	}

	if v.CodeCommit != nil {
		ok := object.Key("CodeCommit")
		if err := awsRestjson1_serializeDocumentCodeCommitRepository(v.CodeCommit, ok); err != nil {
			return err
		}
	}

	if v.GitHubEnterpriseServer != nil {
		ok := object.Key("GitHubEnterpriseServer")
		if err := awsRestjson1_serializeDocumentThirdPartySourceRepository(v.GitHubEnterpriseServer, ok); err != nil {
			return err
		}
	}

	return nil
}

func awsRestjson1_serializeDocumentThirdPartySourceRepository(v *types.ThirdPartySourceRepository, value smithyjson.Value) error {
	object := value.Object()
	defer object.Close()

	if v.ConnectionArn != nil {
		ok := object.Key("ConnectionArn")
		ok.String(*v.ConnectionArn)
	}

	if v.Name != nil {
		ok := object.Key("Name")
		ok.String(*v.Name)
	}

	if v.Owner != nil {
		ok := object.Key("Owner")
		ok.String(*v.Owner)
	}

	return nil
}