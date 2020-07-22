// Code generated by smithy-go-codegen DO NOT EDIT.

package lexruntimeservice

import (
	"bytes"
	"context"
	"fmt"
	"github.com/aws/aws-sdk-go-v2/service/lexruntimeservice/types"
	smithy "github.com/awslabs/smithy-go"
	"github.com/awslabs/smithy-go/httpbinding"
	smithyjson "github.com/awslabs/smithy-go/json"
	"github.com/awslabs/smithy-go/middleware"
	smithyhttp "github.com/awslabs/smithy-go/transport/http"
)

type awsRestjson1_serializeOpGetSession struct {
}

func (*awsRestjson1_serializeOpGetSession) ID() string {
	return "OperationSerializer"
}

func (m *awsRestjson1_serializeOpGetSession) HandleSerialize(ctx context.Context, in middleware.SerializeInput, next middleware.SerializeHandler) (
	out middleware.SerializeOutput, metadata middleware.Metadata, err error,
) {
	request, ok := in.Request.(*smithyhttp.Request)
	if !ok {
		return out, metadata, &smithy.SerializationError{Err: fmt.Errorf("unknown transport type %T", in.Request)}
	}

	input, ok := in.Parameters.(*GetSessionInput)
	_ = input
	if !ok {
		return out, metadata, &smithy.SerializationError{Err: fmt.Errorf("unknown input parameters type %T", in.Parameters)}
	}

	opPath, opQuery := httpbinding.SplitURI("/bot/{botName}/alias/{botAlias}/user/{userId}/session")
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

	if err := awsRestjson1_serializeHttpBindingsGetSessionInput(input, restEncoder); err != nil {
		return out, metadata, &smithy.SerializationError{Err: err}
	}

	if request.Request, err = restEncoder.Encode(request.Request); err != nil {
		return out, metadata, &smithy.SerializationError{Err: err}
	}
	in.Request = request

	return next.HandleSerialize(ctx, in)
}
func awsRestjson1_serializeHttpBindingsGetSessionInput(v *GetSessionInput, encoder *httpbinding.Encoder) error {
	if v == nil {
		return fmt.Errorf("unsupported serialization of nil %T", v)
	}

	if v.BotAlias != nil {
		if err := encoder.SetURI("botAlias").String(*v.BotAlias); err != nil {
			return err
		}
	}

	if v.BotName != nil {
		if err := encoder.SetURI("botName").String(*v.BotName); err != nil {
			return err
		}
	}

	if v.CheckpointLabelFilter != nil {
		encoder.SetQuery("checkpointLabelFilter").String(*v.CheckpointLabelFilter)
	}

	if v.UserId != nil {
		if err := encoder.SetURI("userId").String(*v.UserId); err != nil {
			return err
		}
	}

	return nil
}

type awsRestjson1_serializeOpDeleteSession struct {
}

func (*awsRestjson1_serializeOpDeleteSession) ID() string {
	return "OperationSerializer"
}

func (m *awsRestjson1_serializeOpDeleteSession) HandleSerialize(ctx context.Context, in middleware.SerializeInput, next middleware.SerializeHandler) (
	out middleware.SerializeOutput, metadata middleware.Metadata, err error,
) {
	request, ok := in.Request.(*smithyhttp.Request)
	if !ok {
		return out, metadata, &smithy.SerializationError{Err: fmt.Errorf("unknown transport type %T", in.Request)}
	}

	input, ok := in.Parameters.(*DeleteSessionInput)
	_ = input
	if !ok {
		return out, metadata, &smithy.SerializationError{Err: fmt.Errorf("unknown input parameters type %T", in.Parameters)}
	}

	opPath, opQuery := httpbinding.SplitURI("/bot/{botName}/alias/{botAlias}/user/{userId}/session")
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

	if err := awsRestjson1_serializeHttpBindingsDeleteSessionInput(input, restEncoder); err != nil {
		return out, metadata, &smithy.SerializationError{Err: err}
	}

	if request.Request, err = restEncoder.Encode(request.Request); err != nil {
		return out, metadata, &smithy.SerializationError{Err: err}
	}
	in.Request = request

	return next.HandleSerialize(ctx, in)
}
func awsRestjson1_serializeHttpBindingsDeleteSessionInput(v *DeleteSessionInput, encoder *httpbinding.Encoder) error {
	if v == nil {
		return fmt.Errorf("unsupported serialization of nil %T", v)
	}

	if v.BotAlias != nil {
		if err := encoder.SetURI("botAlias").String(*v.BotAlias); err != nil {
			return err
		}
	}

	if v.BotName != nil {
		if err := encoder.SetURI("botName").String(*v.BotName); err != nil {
			return err
		}
	}

	if v.UserId != nil {
		if err := encoder.SetURI("userId").String(*v.UserId); err != nil {
			return err
		}
	}

	return nil
}

type awsRestjson1_serializeOpPutSession struct {
}

func (*awsRestjson1_serializeOpPutSession) ID() string {
	return "OperationSerializer"
}

func (m *awsRestjson1_serializeOpPutSession) HandleSerialize(ctx context.Context, in middleware.SerializeInput, next middleware.SerializeHandler) (
	out middleware.SerializeOutput, metadata middleware.Metadata, err error,
) {
	request, ok := in.Request.(*smithyhttp.Request)
	if !ok {
		return out, metadata, &smithy.SerializationError{Err: fmt.Errorf("unknown transport type %T", in.Request)}
	}

	input, ok := in.Parameters.(*PutSessionInput)
	_ = input
	if !ok {
		return out, metadata, &smithy.SerializationError{Err: fmt.Errorf("unknown input parameters type %T", in.Parameters)}
	}

	opPath, opQuery := httpbinding.SplitURI("/bot/{botName}/alias/{botAlias}/user/{userId}/session")
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

	if err := awsRestjson1_serializeHttpBindingsPutSessionInput(input, restEncoder); err != nil {
		return out, metadata, &smithy.SerializationError{Err: err}
	}

	restEncoder.SetHeader("Content-Type").String("application/json")

	jsonEncoder := smithyjson.NewEncoder()
	if err := awsRestjson1_serializeDocumentPutSessionInput(input, jsonEncoder.Value); err != nil {
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
func awsRestjson1_serializeHttpBindingsPutSessionInput(v *PutSessionInput, encoder *httpbinding.Encoder) error {
	if v == nil {
		return fmt.Errorf("unsupported serialization of nil %T", v)
	}

	if v.Accept != nil {
		if len(*v.Accept) > 0 {
			encoder.SetHeader("Accept").String(*v.Accept)
		}
	}

	if v.BotAlias != nil {
		if err := encoder.SetURI("botAlias").String(*v.BotAlias); err != nil {
			return err
		}
	}

	if v.BotName != nil {
		if err := encoder.SetURI("botName").String(*v.BotName); err != nil {
			return err
		}
	}

	if v.UserId != nil {
		if err := encoder.SetURI("userId").String(*v.UserId); err != nil {
			return err
		}
	}

	return nil
}

func awsRestjson1_serializeDocumentPutSessionInput(v *PutSessionInput, value smithyjson.Value) error {
	object := value.Object()
	defer object.Close()

	if v.DialogAction != nil {
		ok := object.Key("dialogAction")
		if err := awsRestjson1_serializeDocumentDialogAction(v.DialogAction, ok); err != nil {
			return err
		}
	}

	if v.RecentIntentSummaryView != nil {
		ok := object.Key("recentIntentSummaryView")
		if err := awsRestjson1_serializeDocumentIntentSummaryList(v.RecentIntentSummaryView, ok); err != nil {
			return err
		}
	}

	if v.SessionAttributes != nil {
		ok := object.Key("sessionAttributes")
		if err := awsRestjson1_serializeDocumentStringMap(v.SessionAttributes, ok); err != nil {
			return err
		}
	}

	return nil
}

type awsRestjson1_serializeOpPostText struct {
}

func (*awsRestjson1_serializeOpPostText) ID() string {
	return "OperationSerializer"
}

func (m *awsRestjson1_serializeOpPostText) HandleSerialize(ctx context.Context, in middleware.SerializeInput, next middleware.SerializeHandler) (
	out middleware.SerializeOutput, metadata middleware.Metadata, err error,
) {
	request, ok := in.Request.(*smithyhttp.Request)
	if !ok {
		return out, metadata, &smithy.SerializationError{Err: fmt.Errorf("unknown transport type %T", in.Request)}
	}

	input, ok := in.Parameters.(*PostTextInput)
	_ = input
	if !ok {
		return out, metadata, &smithy.SerializationError{Err: fmt.Errorf("unknown input parameters type %T", in.Parameters)}
	}

	opPath, opQuery := httpbinding.SplitURI("/bot/{botName}/alias/{botAlias}/user/{userId}/text")
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

	if err := awsRestjson1_serializeHttpBindingsPostTextInput(input, restEncoder); err != nil {
		return out, metadata, &smithy.SerializationError{Err: err}
	}

	restEncoder.SetHeader("Content-Type").String("application/json")

	jsonEncoder := smithyjson.NewEncoder()
	if err := awsRestjson1_serializeDocumentPostTextInput(input, jsonEncoder.Value); err != nil {
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
func awsRestjson1_serializeHttpBindingsPostTextInput(v *PostTextInput, encoder *httpbinding.Encoder) error {
	if v == nil {
		return fmt.Errorf("unsupported serialization of nil %T", v)
	}

	if v.BotAlias != nil {
		if err := encoder.SetURI("botAlias").String(*v.BotAlias); err != nil {
			return err
		}
	}

	if v.BotName != nil {
		if err := encoder.SetURI("botName").String(*v.BotName); err != nil {
			return err
		}
	}

	if v.UserId != nil {
		if err := encoder.SetURI("userId").String(*v.UserId); err != nil {
			return err
		}
	}

	return nil
}

func awsRestjson1_serializeDocumentPostTextInput(v *PostTextInput, value smithyjson.Value) error {
	object := value.Object()
	defer object.Close()

	if v.InputText != nil {
		ok := object.Key("inputText")
		ok.String(*v.InputText)
	}

	if v.RequestAttributes != nil {
		ok := object.Key("requestAttributes")
		if err := awsRestjson1_serializeDocumentStringMap(v.RequestAttributes, ok); err != nil {
			return err
		}
	}

	if v.SessionAttributes != nil {
		ok := object.Key("sessionAttributes")
		if err := awsRestjson1_serializeDocumentStringMap(v.SessionAttributes, ok); err != nil {
			return err
		}
	}

	return nil
}

type awsRestjson1_serializeOpPostContent struct {
}

func (*awsRestjson1_serializeOpPostContent) ID() string {
	return "OperationSerializer"
}

func (m *awsRestjson1_serializeOpPostContent) HandleSerialize(ctx context.Context, in middleware.SerializeInput, next middleware.SerializeHandler) (
	out middleware.SerializeOutput, metadata middleware.Metadata, err error,
) {
	request, ok := in.Request.(*smithyhttp.Request)
	if !ok {
		return out, metadata, &smithy.SerializationError{Err: fmt.Errorf("unknown transport type %T", in.Request)}
	}

	input, ok := in.Parameters.(*PostContentInput)
	_ = input
	if !ok {
		return out, metadata, &smithy.SerializationError{Err: fmt.Errorf("unknown input parameters type %T", in.Parameters)}
	}

	opPath, opQuery := httpbinding.SplitURI("/bot/{botName}/alias/{botAlias}/user/{userId}/content")
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

	if err := awsRestjson1_serializeHttpBindingsPostContentInput(input, restEncoder); err != nil {
		return out, metadata, &smithy.SerializationError{Err: err}
	}

	if input.InputStream != nil {
		if !restEncoder.HasHeader("Content-Type") {
			restEncoder.SetHeader("Content-Type").String("application/octet-stream")
		}

		payload := input.InputStream
		if request, err = request.SetStream(payload); err != nil {
			return out, metadata, &smithy.SerializationError{Err: err}
		}
	}

	if request.Request, err = restEncoder.Encode(request.Request); err != nil {
		return out, metadata, &smithy.SerializationError{Err: err}
	}
	in.Request = request

	return next.HandleSerialize(ctx, in)
}
func awsRestjson1_serializeHttpBindingsPostContentInput(v *PostContentInput, encoder *httpbinding.Encoder) error {
	if v == nil {
		return fmt.Errorf("unsupported serialization of nil %T", v)
	}

	if v.Accept != nil {
		if len(*v.Accept) > 0 {
			encoder.SetHeader("Accept").String(*v.Accept)
		}
	}

	if v.BotAlias != nil {
		if err := encoder.SetURI("botAlias").String(*v.BotAlias); err != nil {
			return err
		}
	}

	if v.BotName != nil {
		if err := encoder.SetURI("botName").String(*v.BotName); err != nil {
			return err
		}
	}

	if v.ContentType != nil {
		if len(*v.ContentType) > 0 {
			encoder.SetHeader("Content-Type").String(*v.ContentType)
		}
	}

	if v.RequestAttributes != nil {
		if len(*v.RequestAttributes) > 0 {
			encoder.SetHeader("x-amz-lex-request-attributes").String(*v.RequestAttributes)
		}
	}

	if v.SessionAttributes != nil {
		if len(*v.SessionAttributes) > 0 {
			encoder.SetHeader("x-amz-lex-session-attributes").String(*v.SessionAttributes)
		}
	}

	if v.UserId != nil {
		if err := encoder.SetURI("userId").String(*v.UserId); err != nil {
			return err
		}
	}

	return nil
}

func awsRestjson1_serializeDocumentDialogAction(v *types.DialogAction, value smithyjson.Value) error {
	object := value.Object()
	defer object.Close()

	if len(v.FulfillmentState) > 0 {
		ok := object.Key("fulfillmentState")
		ok.String(string(v.FulfillmentState))
	}

	if v.IntentName != nil {
		ok := object.Key("intentName")
		ok.String(*v.IntentName)
	}

	if v.Message != nil {
		ok := object.Key("message")
		ok.String(*v.Message)
	}

	if len(v.MessageFormat) > 0 {
		ok := object.Key("messageFormat")
		ok.String(string(v.MessageFormat))
	}

	if v.Slots != nil {
		ok := object.Key("slots")
		if err := awsRestjson1_serializeDocumentStringMap(v.Slots, ok); err != nil {
			return err
		}
	}

	if v.SlotToElicit != nil {
		ok := object.Key("slotToElicit")
		ok.String(*v.SlotToElicit)
	}

	if len(v.Type) > 0 {
		ok := object.Key("type")
		ok.String(string(v.Type))
	}

	return nil
}

func awsRestjson1_serializeDocumentIntentSummary(v *types.IntentSummary, value smithyjson.Value) error {
	object := value.Object()
	defer object.Close()

	if v.CheckpointLabel != nil {
		ok := object.Key("checkpointLabel")
		ok.String(*v.CheckpointLabel)
	}

	if len(v.ConfirmationStatus) > 0 {
		ok := object.Key("confirmationStatus")
		ok.String(string(v.ConfirmationStatus))
	}

	if len(v.DialogActionType) > 0 {
		ok := object.Key("dialogActionType")
		ok.String(string(v.DialogActionType))
	}

	if len(v.FulfillmentState) > 0 {
		ok := object.Key("fulfillmentState")
		ok.String(string(v.FulfillmentState))
	}

	if v.IntentName != nil {
		ok := object.Key("intentName")
		ok.String(*v.IntentName)
	}

	if v.Slots != nil {
		ok := object.Key("slots")
		if err := awsRestjson1_serializeDocumentStringMap(v.Slots, ok); err != nil {
			return err
		}
	}

	if v.SlotToElicit != nil {
		ok := object.Key("slotToElicit")
		ok.String(*v.SlotToElicit)
	}

	return nil
}

func awsRestjson1_serializeDocumentIntentSummaryList(v []*types.IntentSummary, value smithyjson.Value) error {
	array := value.Array()
	defer array.Close()

	for i := range v {
		av := array.Value()
		if vv := v[i]; vv == nil {
			av.Null()
			continue
		}
		if err := awsRestjson1_serializeDocumentIntentSummary(v[i], av); err != nil {
			return err
		}
	}
	return nil
}

func awsRestjson1_serializeDocumentStringMap(v map[string]*string, value smithyjson.Value) error {
	object := value.Object()
	defer object.Close()

	for key := range v {
		om := object.Key(key)
		if vv := v[key]; vv == nil {
			om.Null()
			continue
		}
		om.String(*v[key])
	}
	return nil
}
