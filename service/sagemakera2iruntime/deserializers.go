// Code generated by smithy-go-codegen DO NOT EDIT.

package sagemakera2iruntime

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"github.com/aws/aws-sdk-go-v2/aws/protocol/restjson"
	"github.com/aws/aws-sdk-go-v2/service/sagemakera2iruntime/types"
	smithy "github.com/awslabs/smithy-go"
	smithyio "github.com/awslabs/smithy-go/io"
	smithyjson "github.com/awslabs/smithy-go/json"
	"github.com/awslabs/smithy-go/middleware"
	"github.com/awslabs/smithy-go/ptr"
	smithytime "github.com/awslabs/smithy-go/time"
	smithyhttp "github.com/awslabs/smithy-go/transport/http"
	"io"
	"strings"
)

type awsRestjson1_deserializeOpDeleteHumanLoop struct {
}

func (*awsRestjson1_deserializeOpDeleteHumanLoop) ID() string {
	return "OperationDeserializer"
}

func (m *awsRestjson1_deserializeOpDeleteHumanLoop) HandleDeserialize(ctx context.Context, in middleware.DeserializeInput, next middleware.DeserializeHandler) (
	out middleware.DeserializeOutput, metadata middleware.Metadata, err error,
) {
	out, metadata, err = next.HandleDeserialize(ctx, in)
	if err != nil {
		return out, metadata, err
	}

	response, ok := out.RawResponse.(*smithyhttp.Response)
	if !ok {
		return out, metadata, &smithy.DeserializationError{Err: fmt.Errorf("unknown transport type %T", out.RawResponse)}
	}

	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return out, metadata, awsRestjson1_deserializeOpErrorDeleteHumanLoop(response)
	}
	output := &DeleteHumanLoopOutput{}
	out.Result = output

	return out, metadata, err
}

func awsRestjson1_deserializeOpErrorDeleteHumanLoop(response *smithyhttp.Response) error {
	var errorBuffer bytes.Buffer
	if _, err := io.Copy(&errorBuffer, response.Body); err != nil {
		return &smithy.DeserializationError{Err: fmt.Errorf("failed to copy error response body, %w", err)}
	}
	errorBody := bytes.NewReader(errorBuffer.Bytes())

	errorCode := "UnknownError"
	errorMessage := errorCode

	code := response.Header.Get("X-Amzn-ErrorType")
	if len(code) != 0 {
		errorCode = restjson.SanitizeErrorCode(code)
	}

	buff := make([]byte, 1024)
	ringBuffer := smithyio.NewRingBuffer(buff)

	body := io.TeeReader(errorBody, ringBuffer)
	decoder := json.NewDecoder(body)
	decoder.UseNumber()

	code, message, err := restjson.GetErrorInfo(decoder)
	if err != nil {
		var snapshot bytes.Buffer
		io.Copy(&snapshot, ringBuffer)
		return &smithy.DeserializationError{
			Err:      fmt.Errorf("failed to decode response body, %w", err),
			Snapshot: snapshot.Bytes(),
		}
	}

	errorBody.Seek(0, io.SeekStart)
	if len(code) != 0 {
		errorCode = restjson.SanitizeErrorCode(code)
	}
	if len(message) != 0 {
		errorMessage = message
	}

	switch {
	case strings.EqualFold("InternalServerException", errorCode):
		return awsRestjson1_deserializeErrorInternalServerException(response, errorBody)

	case strings.EqualFold("ResourceNotFoundException", errorCode):
		return awsRestjson1_deserializeErrorResourceNotFoundException(response, errorBody)

	case strings.EqualFold("ThrottlingException", errorCode):
		return awsRestjson1_deserializeErrorThrottlingException(response, errorBody)

	case strings.EqualFold("ValidationException", errorCode):
		return awsRestjson1_deserializeErrorValidationException(response, errorBody)

	default:
		genericError := &smithy.GenericAPIError{
			Code:    errorCode,
			Message: errorMessage,
		}
		return genericError

	}
}

type awsRestjson1_deserializeOpDescribeHumanLoop struct {
}

func (*awsRestjson1_deserializeOpDescribeHumanLoop) ID() string {
	return "OperationDeserializer"
}

func (m *awsRestjson1_deserializeOpDescribeHumanLoop) HandleDeserialize(ctx context.Context, in middleware.DeserializeInput, next middleware.DeserializeHandler) (
	out middleware.DeserializeOutput, metadata middleware.Metadata, err error,
) {
	out, metadata, err = next.HandleDeserialize(ctx, in)
	if err != nil {
		return out, metadata, err
	}

	response, ok := out.RawResponse.(*smithyhttp.Response)
	if !ok {
		return out, metadata, &smithy.DeserializationError{Err: fmt.Errorf("unknown transport type %T", out.RawResponse)}
	}

	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return out, metadata, awsRestjson1_deserializeOpErrorDescribeHumanLoop(response)
	}
	output := &DescribeHumanLoopOutput{}
	out.Result = output

	buff := make([]byte, 1024)
	ringBuffer := smithyio.NewRingBuffer(buff)

	body := io.TeeReader(response.Body, ringBuffer)

	decoder := json.NewDecoder(body)
	decoder.UseNumber()

	err = awsRestjson1_deserializeDocumentDescribeHumanLoopOutput(&output, decoder)
	if err != nil {
		var snapshot bytes.Buffer
		io.Copy(&snapshot, ringBuffer)
		return out, metadata, &smithy.DeserializationError{
			Err:      fmt.Errorf("failed to decode response body with invalid JSON, %w", err),
			Snapshot: snapshot.Bytes(),
		}
	}

	return out, metadata, err
}

func awsRestjson1_deserializeOpErrorDescribeHumanLoop(response *smithyhttp.Response) error {
	var errorBuffer bytes.Buffer
	if _, err := io.Copy(&errorBuffer, response.Body); err != nil {
		return &smithy.DeserializationError{Err: fmt.Errorf("failed to copy error response body, %w", err)}
	}
	errorBody := bytes.NewReader(errorBuffer.Bytes())

	errorCode := "UnknownError"
	errorMessage := errorCode

	code := response.Header.Get("X-Amzn-ErrorType")
	if len(code) != 0 {
		errorCode = restjson.SanitizeErrorCode(code)
	}

	buff := make([]byte, 1024)
	ringBuffer := smithyio.NewRingBuffer(buff)

	body := io.TeeReader(errorBody, ringBuffer)
	decoder := json.NewDecoder(body)
	decoder.UseNumber()

	code, message, err := restjson.GetErrorInfo(decoder)
	if err != nil {
		var snapshot bytes.Buffer
		io.Copy(&snapshot, ringBuffer)
		return &smithy.DeserializationError{
			Err:      fmt.Errorf("failed to decode response body, %w", err),
			Snapshot: snapshot.Bytes(),
		}
	}

	errorBody.Seek(0, io.SeekStart)
	if len(code) != 0 {
		errorCode = restjson.SanitizeErrorCode(code)
	}
	if len(message) != 0 {
		errorMessage = message
	}

	switch {
	case strings.EqualFold("InternalServerException", errorCode):
		return awsRestjson1_deserializeErrorInternalServerException(response, errorBody)

	case strings.EqualFold("ResourceNotFoundException", errorCode):
		return awsRestjson1_deserializeErrorResourceNotFoundException(response, errorBody)

	case strings.EqualFold("ThrottlingException", errorCode):
		return awsRestjson1_deserializeErrorThrottlingException(response, errorBody)

	case strings.EqualFold("ValidationException", errorCode):
		return awsRestjson1_deserializeErrorValidationException(response, errorBody)

	default:
		genericError := &smithy.GenericAPIError{
			Code:    errorCode,
			Message: errorMessage,
		}
		return genericError

	}
}

func awsRestjson1_deserializeDocumentDescribeHumanLoopOutput(v **DescribeHumanLoopOutput, decoder *json.Decoder) error {
	if v == nil {
		return fmt.Errorf("unexpected nil of type %T", v)
	}
	startToken, err := decoder.Token()
	if err == io.EOF {
		return nil
	}
	if err != nil {
		return err
	}
	if startToken == nil {
		return nil
	}
	if t, ok := startToken.(json.Delim); !ok || t != '{' {
		return fmt.Errorf("expect `{` as start token")
	}

	var sv *DescribeHumanLoopOutput
	if *v == nil {
		sv = &DescribeHumanLoopOutput{}
	} else {
		sv = *v
	}

	for decoder.More() {
		t, err := decoder.Token()
		if err != nil {
			return err
		}
		switch t {
		case "CreationTime":
			val, err := decoder.Token()
			if err != nil {
				return err
			}
			if val != nil {
				jtv, ok := val.(json.Number)
				if !ok {
					return fmt.Errorf("expected Timestamp to be json.Number, got %T instead", val)
				}
				f64, err := jtv.Float64()
				if err != nil {
					return err
				}
				sv.CreationTime = ptr.Time(smithytime.ParseEpochSeconds(f64))
			}

		case "FailureCode":
			val, err := decoder.Token()
			if err != nil {
				return err
			}
			if val != nil {
				jtv, ok := val.(string)
				if !ok {
					return fmt.Errorf("expected String to be of type string, got %T instead", val)
				}
				sv.FailureCode = &jtv
			}

		case "FailureReason":
			val, err := decoder.Token()
			if err != nil {
				return err
			}
			if val != nil {
				jtv, ok := val.(string)
				if !ok {
					return fmt.Errorf("expected String to be of type string, got %T instead", val)
				}
				sv.FailureReason = &jtv
			}

		case "FlowDefinitionArn":
			val, err := decoder.Token()
			if err != nil {
				return err
			}
			if val != nil {
				jtv, ok := val.(string)
				if !ok {
					return fmt.Errorf("expected FlowDefinitionArn to be of type string, got %T instead", val)
				}
				sv.FlowDefinitionArn = &jtv
			}

		case "HumanLoopArn":
			val, err := decoder.Token()
			if err != nil {
				return err
			}
			if val != nil {
				jtv, ok := val.(string)
				if !ok {
					return fmt.Errorf("expected HumanLoopArn to be of type string, got %T instead", val)
				}
				sv.HumanLoopArn = &jtv
			}

		case "HumanLoopName":
			val, err := decoder.Token()
			if err != nil {
				return err
			}
			if val != nil {
				jtv, ok := val.(string)
				if !ok {
					return fmt.Errorf("expected HumanLoopName to be of type string, got %T instead", val)
				}
				sv.HumanLoopName = &jtv
			}

		case "HumanLoopOutput":
			if err := awsRestjson1_deserializeDocumentHumanLoopOutput(&sv.HumanLoopOutput, decoder); err != nil {
				return err
			}

		case "HumanLoopStatus":
			val, err := decoder.Token()
			if err != nil {
				return err
			}
			if val != nil {
				jtv, ok := val.(string)
				if !ok {
					return fmt.Errorf("expected HumanLoopStatus to be of type string, got %T instead", val)
				}
				sv.HumanLoopStatus = types.HumanLoopStatus(jtv)
			}

		default:
			err := smithyjson.DiscardUnknownField(decoder)
			if err != nil {
				return err
			}

		}
	}
	endToken, err := decoder.Token()
	if err != nil {
		return err
	}
	if t, ok := endToken.(json.Delim); !ok || t != '}' {
		return fmt.Errorf("expect `}` as end token")
	}

	*v = sv
	return nil
}

type awsRestjson1_deserializeOpListHumanLoops struct {
}

func (*awsRestjson1_deserializeOpListHumanLoops) ID() string {
	return "OperationDeserializer"
}

func (m *awsRestjson1_deserializeOpListHumanLoops) HandleDeserialize(ctx context.Context, in middleware.DeserializeInput, next middleware.DeserializeHandler) (
	out middleware.DeserializeOutput, metadata middleware.Metadata, err error,
) {
	out, metadata, err = next.HandleDeserialize(ctx, in)
	if err != nil {
		return out, metadata, err
	}

	response, ok := out.RawResponse.(*smithyhttp.Response)
	if !ok {
		return out, metadata, &smithy.DeserializationError{Err: fmt.Errorf("unknown transport type %T", out.RawResponse)}
	}

	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return out, metadata, awsRestjson1_deserializeOpErrorListHumanLoops(response)
	}
	output := &ListHumanLoopsOutput{}
	out.Result = output

	buff := make([]byte, 1024)
	ringBuffer := smithyio.NewRingBuffer(buff)

	body := io.TeeReader(response.Body, ringBuffer)

	decoder := json.NewDecoder(body)
	decoder.UseNumber()

	err = awsRestjson1_deserializeDocumentListHumanLoopsOutput(&output, decoder)
	if err != nil {
		var snapshot bytes.Buffer
		io.Copy(&snapshot, ringBuffer)
		return out, metadata, &smithy.DeserializationError{
			Err:      fmt.Errorf("failed to decode response body with invalid JSON, %w", err),
			Snapshot: snapshot.Bytes(),
		}
	}

	return out, metadata, err
}

func awsRestjson1_deserializeOpErrorListHumanLoops(response *smithyhttp.Response) error {
	var errorBuffer bytes.Buffer
	if _, err := io.Copy(&errorBuffer, response.Body); err != nil {
		return &smithy.DeserializationError{Err: fmt.Errorf("failed to copy error response body, %w", err)}
	}
	errorBody := bytes.NewReader(errorBuffer.Bytes())

	errorCode := "UnknownError"
	errorMessage := errorCode

	code := response.Header.Get("X-Amzn-ErrorType")
	if len(code) != 0 {
		errorCode = restjson.SanitizeErrorCode(code)
	}

	buff := make([]byte, 1024)
	ringBuffer := smithyio.NewRingBuffer(buff)

	body := io.TeeReader(errorBody, ringBuffer)
	decoder := json.NewDecoder(body)
	decoder.UseNumber()

	code, message, err := restjson.GetErrorInfo(decoder)
	if err != nil {
		var snapshot bytes.Buffer
		io.Copy(&snapshot, ringBuffer)
		return &smithy.DeserializationError{
			Err:      fmt.Errorf("failed to decode response body, %w", err),
			Snapshot: snapshot.Bytes(),
		}
	}

	errorBody.Seek(0, io.SeekStart)
	if len(code) != 0 {
		errorCode = restjson.SanitizeErrorCode(code)
	}
	if len(message) != 0 {
		errorMessage = message
	}

	switch {
	case strings.EqualFold("InternalServerException", errorCode):
		return awsRestjson1_deserializeErrorInternalServerException(response, errorBody)

	case strings.EqualFold("ResourceNotFoundException", errorCode):
		return awsRestjson1_deserializeErrorResourceNotFoundException(response, errorBody)

	case strings.EqualFold("ThrottlingException", errorCode):
		return awsRestjson1_deserializeErrorThrottlingException(response, errorBody)

	case strings.EqualFold("ValidationException", errorCode):
		return awsRestjson1_deserializeErrorValidationException(response, errorBody)

	default:
		genericError := &smithy.GenericAPIError{
			Code:    errorCode,
			Message: errorMessage,
		}
		return genericError

	}
}

func awsRestjson1_deserializeDocumentListHumanLoopsOutput(v **ListHumanLoopsOutput, decoder *json.Decoder) error {
	if v == nil {
		return fmt.Errorf("unexpected nil of type %T", v)
	}
	startToken, err := decoder.Token()
	if err == io.EOF {
		return nil
	}
	if err != nil {
		return err
	}
	if startToken == nil {
		return nil
	}
	if t, ok := startToken.(json.Delim); !ok || t != '{' {
		return fmt.Errorf("expect `{` as start token")
	}

	var sv *ListHumanLoopsOutput
	if *v == nil {
		sv = &ListHumanLoopsOutput{}
	} else {
		sv = *v
	}

	for decoder.More() {
		t, err := decoder.Token()
		if err != nil {
			return err
		}
		switch t {
		case "HumanLoopSummaries":
			if err := awsRestjson1_deserializeDocumentHumanLoopSummaries(&sv.HumanLoopSummaries, decoder); err != nil {
				return err
			}

		case "NextToken":
			val, err := decoder.Token()
			if err != nil {
				return err
			}
			if val != nil {
				jtv, ok := val.(string)
				if !ok {
					return fmt.Errorf("expected NextToken to be of type string, got %T instead", val)
				}
				sv.NextToken = &jtv
			}

		default:
			err := smithyjson.DiscardUnknownField(decoder)
			if err != nil {
				return err
			}

		}
	}
	endToken, err := decoder.Token()
	if err != nil {
		return err
	}
	if t, ok := endToken.(json.Delim); !ok || t != '}' {
		return fmt.Errorf("expect `}` as end token")
	}

	*v = sv
	return nil
}

type awsRestjson1_deserializeOpStartHumanLoop struct {
}

func (*awsRestjson1_deserializeOpStartHumanLoop) ID() string {
	return "OperationDeserializer"
}

func (m *awsRestjson1_deserializeOpStartHumanLoop) HandleDeserialize(ctx context.Context, in middleware.DeserializeInput, next middleware.DeserializeHandler) (
	out middleware.DeserializeOutput, metadata middleware.Metadata, err error,
) {
	out, metadata, err = next.HandleDeserialize(ctx, in)
	if err != nil {
		return out, metadata, err
	}

	response, ok := out.RawResponse.(*smithyhttp.Response)
	if !ok {
		return out, metadata, &smithy.DeserializationError{Err: fmt.Errorf("unknown transport type %T", out.RawResponse)}
	}

	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return out, metadata, awsRestjson1_deserializeOpErrorStartHumanLoop(response)
	}
	output := &StartHumanLoopOutput{}
	out.Result = output

	buff := make([]byte, 1024)
	ringBuffer := smithyio.NewRingBuffer(buff)

	body := io.TeeReader(response.Body, ringBuffer)

	decoder := json.NewDecoder(body)
	decoder.UseNumber()

	err = awsRestjson1_deserializeDocumentStartHumanLoopOutput(&output, decoder)
	if err != nil {
		var snapshot bytes.Buffer
		io.Copy(&snapshot, ringBuffer)
		return out, metadata, &smithy.DeserializationError{
			Err:      fmt.Errorf("failed to decode response body with invalid JSON, %w", err),
			Snapshot: snapshot.Bytes(),
		}
	}

	return out, metadata, err
}

func awsRestjson1_deserializeOpErrorStartHumanLoop(response *smithyhttp.Response) error {
	var errorBuffer bytes.Buffer
	if _, err := io.Copy(&errorBuffer, response.Body); err != nil {
		return &smithy.DeserializationError{Err: fmt.Errorf("failed to copy error response body, %w", err)}
	}
	errorBody := bytes.NewReader(errorBuffer.Bytes())

	errorCode := "UnknownError"
	errorMessage := errorCode

	code := response.Header.Get("X-Amzn-ErrorType")
	if len(code) != 0 {
		errorCode = restjson.SanitizeErrorCode(code)
	}

	buff := make([]byte, 1024)
	ringBuffer := smithyio.NewRingBuffer(buff)

	body := io.TeeReader(errorBody, ringBuffer)
	decoder := json.NewDecoder(body)
	decoder.UseNumber()

	code, message, err := restjson.GetErrorInfo(decoder)
	if err != nil {
		var snapshot bytes.Buffer
		io.Copy(&snapshot, ringBuffer)
		return &smithy.DeserializationError{
			Err:      fmt.Errorf("failed to decode response body, %w", err),
			Snapshot: snapshot.Bytes(),
		}
	}

	errorBody.Seek(0, io.SeekStart)
	if len(code) != 0 {
		errorCode = restjson.SanitizeErrorCode(code)
	}
	if len(message) != 0 {
		errorMessage = message
	}

	switch {
	case strings.EqualFold("ConflictException", errorCode):
		return awsRestjson1_deserializeErrorConflictException(response, errorBody)

	case strings.EqualFold("InternalServerException", errorCode):
		return awsRestjson1_deserializeErrorInternalServerException(response, errorBody)

	case strings.EqualFold("ServiceQuotaExceededException", errorCode):
		return awsRestjson1_deserializeErrorServiceQuotaExceededException(response, errorBody)

	case strings.EqualFold("ThrottlingException", errorCode):
		return awsRestjson1_deserializeErrorThrottlingException(response, errorBody)

	case strings.EqualFold("ValidationException", errorCode):
		return awsRestjson1_deserializeErrorValidationException(response, errorBody)

	default:
		genericError := &smithy.GenericAPIError{
			Code:    errorCode,
			Message: errorMessage,
		}
		return genericError

	}
}

func awsRestjson1_deserializeDocumentStartHumanLoopOutput(v **StartHumanLoopOutput, decoder *json.Decoder) error {
	if v == nil {
		return fmt.Errorf("unexpected nil of type %T", v)
	}
	startToken, err := decoder.Token()
	if err == io.EOF {
		return nil
	}
	if err != nil {
		return err
	}
	if startToken == nil {
		return nil
	}
	if t, ok := startToken.(json.Delim); !ok || t != '{' {
		return fmt.Errorf("expect `{` as start token")
	}

	var sv *StartHumanLoopOutput
	if *v == nil {
		sv = &StartHumanLoopOutput{}
	} else {
		sv = *v
	}

	for decoder.More() {
		t, err := decoder.Token()
		if err != nil {
			return err
		}
		switch t {
		case "HumanLoopArn":
			val, err := decoder.Token()
			if err != nil {
				return err
			}
			if val != nil {
				jtv, ok := val.(string)
				if !ok {
					return fmt.Errorf("expected HumanLoopArn to be of type string, got %T instead", val)
				}
				sv.HumanLoopArn = &jtv
			}

		default:
			err := smithyjson.DiscardUnknownField(decoder)
			if err != nil {
				return err
			}

		}
	}
	endToken, err := decoder.Token()
	if err != nil {
		return err
	}
	if t, ok := endToken.(json.Delim); !ok || t != '}' {
		return fmt.Errorf("expect `}` as end token")
	}

	*v = sv
	return nil
}

type awsRestjson1_deserializeOpStopHumanLoop struct {
}

func (*awsRestjson1_deserializeOpStopHumanLoop) ID() string {
	return "OperationDeserializer"
}

func (m *awsRestjson1_deserializeOpStopHumanLoop) HandleDeserialize(ctx context.Context, in middleware.DeserializeInput, next middleware.DeserializeHandler) (
	out middleware.DeserializeOutput, metadata middleware.Metadata, err error,
) {
	out, metadata, err = next.HandleDeserialize(ctx, in)
	if err != nil {
		return out, metadata, err
	}

	response, ok := out.RawResponse.(*smithyhttp.Response)
	if !ok {
		return out, metadata, &smithy.DeserializationError{Err: fmt.Errorf("unknown transport type %T", out.RawResponse)}
	}

	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return out, metadata, awsRestjson1_deserializeOpErrorStopHumanLoop(response)
	}
	output := &StopHumanLoopOutput{}
	out.Result = output

	return out, metadata, err
}

func awsRestjson1_deserializeOpErrorStopHumanLoop(response *smithyhttp.Response) error {
	var errorBuffer bytes.Buffer
	if _, err := io.Copy(&errorBuffer, response.Body); err != nil {
		return &smithy.DeserializationError{Err: fmt.Errorf("failed to copy error response body, %w", err)}
	}
	errorBody := bytes.NewReader(errorBuffer.Bytes())

	errorCode := "UnknownError"
	errorMessage := errorCode

	code := response.Header.Get("X-Amzn-ErrorType")
	if len(code) != 0 {
		errorCode = restjson.SanitizeErrorCode(code)
	}

	buff := make([]byte, 1024)
	ringBuffer := smithyio.NewRingBuffer(buff)

	body := io.TeeReader(errorBody, ringBuffer)
	decoder := json.NewDecoder(body)
	decoder.UseNumber()

	code, message, err := restjson.GetErrorInfo(decoder)
	if err != nil {
		var snapshot bytes.Buffer
		io.Copy(&snapshot, ringBuffer)
		return &smithy.DeserializationError{
			Err:      fmt.Errorf("failed to decode response body, %w", err),
			Snapshot: snapshot.Bytes(),
		}
	}

	errorBody.Seek(0, io.SeekStart)
	if len(code) != 0 {
		errorCode = restjson.SanitizeErrorCode(code)
	}
	if len(message) != 0 {
		errorMessage = message
	}

	switch {
	case strings.EqualFold("InternalServerException", errorCode):
		return awsRestjson1_deserializeErrorInternalServerException(response, errorBody)

	case strings.EqualFold("ResourceNotFoundException", errorCode):
		return awsRestjson1_deserializeErrorResourceNotFoundException(response, errorBody)

	case strings.EqualFold("ThrottlingException", errorCode):
		return awsRestjson1_deserializeErrorThrottlingException(response, errorBody)

	case strings.EqualFold("ValidationException", errorCode):
		return awsRestjson1_deserializeErrorValidationException(response, errorBody)

	default:
		genericError := &smithy.GenericAPIError{
			Code:    errorCode,
			Message: errorMessage,
		}
		return genericError

	}
}

func awsRestjson1_deserializeErrorConflictException(response *smithyhttp.Response, errorBody *bytes.Reader) error {
	output := &types.ConflictException{}
	buff := make([]byte, 1024)
	ringBuffer := smithyio.NewRingBuffer(buff)

	body := io.TeeReader(errorBody, ringBuffer)
	decoder := json.NewDecoder(body)
	decoder.UseNumber()

	err := awsRestjson1_deserializeDocumentConflictException(&output, decoder)

	if err != nil {
		var snapshot bytes.Buffer
		io.Copy(&snapshot, ringBuffer)
		return &smithy.DeserializationError{
			Err:      fmt.Errorf("failed to decode response body, %w", err),
			Snapshot: snapshot.Bytes(),
		}
	}

	errorBody.Seek(0, io.SeekStart)

	return output
}

func awsRestjson1_deserializeErrorInternalServerException(response *smithyhttp.Response, errorBody *bytes.Reader) error {
	output := &types.InternalServerException{}
	buff := make([]byte, 1024)
	ringBuffer := smithyio.NewRingBuffer(buff)

	body := io.TeeReader(errorBody, ringBuffer)
	decoder := json.NewDecoder(body)
	decoder.UseNumber()

	err := awsRestjson1_deserializeDocumentInternalServerException(&output, decoder)

	if err != nil {
		var snapshot bytes.Buffer
		io.Copy(&snapshot, ringBuffer)
		return &smithy.DeserializationError{
			Err:      fmt.Errorf("failed to decode response body, %w", err),
			Snapshot: snapshot.Bytes(),
		}
	}

	errorBody.Seek(0, io.SeekStart)

	return output
}

func awsRestjson1_deserializeErrorResourceNotFoundException(response *smithyhttp.Response, errorBody *bytes.Reader) error {
	output := &types.ResourceNotFoundException{}
	buff := make([]byte, 1024)
	ringBuffer := smithyio.NewRingBuffer(buff)

	body := io.TeeReader(errorBody, ringBuffer)
	decoder := json.NewDecoder(body)
	decoder.UseNumber()

	err := awsRestjson1_deserializeDocumentResourceNotFoundException(&output, decoder)

	if err != nil {
		var snapshot bytes.Buffer
		io.Copy(&snapshot, ringBuffer)
		return &smithy.DeserializationError{
			Err:      fmt.Errorf("failed to decode response body, %w", err),
			Snapshot: snapshot.Bytes(),
		}
	}

	errorBody.Seek(0, io.SeekStart)

	return output
}

func awsRestjson1_deserializeErrorServiceQuotaExceededException(response *smithyhttp.Response, errorBody *bytes.Reader) error {
	output := &types.ServiceQuotaExceededException{}
	buff := make([]byte, 1024)
	ringBuffer := smithyio.NewRingBuffer(buff)

	body := io.TeeReader(errorBody, ringBuffer)
	decoder := json.NewDecoder(body)
	decoder.UseNumber()

	err := awsRestjson1_deserializeDocumentServiceQuotaExceededException(&output, decoder)

	if err != nil {
		var snapshot bytes.Buffer
		io.Copy(&snapshot, ringBuffer)
		return &smithy.DeserializationError{
			Err:      fmt.Errorf("failed to decode response body, %w", err),
			Snapshot: snapshot.Bytes(),
		}
	}

	errorBody.Seek(0, io.SeekStart)

	return output
}

func awsRestjson1_deserializeErrorThrottlingException(response *smithyhttp.Response, errorBody *bytes.Reader) error {
	output := &types.ThrottlingException{}
	buff := make([]byte, 1024)
	ringBuffer := smithyio.NewRingBuffer(buff)

	body := io.TeeReader(errorBody, ringBuffer)
	decoder := json.NewDecoder(body)
	decoder.UseNumber()

	err := awsRestjson1_deserializeDocumentThrottlingException(&output, decoder)

	if err != nil {
		var snapshot bytes.Buffer
		io.Copy(&snapshot, ringBuffer)
		return &smithy.DeserializationError{
			Err:      fmt.Errorf("failed to decode response body, %w", err),
			Snapshot: snapshot.Bytes(),
		}
	}

	errorBody.Seek(0, io.SeekStart)

	return output
}

func awsRestjson1_deserializeErrorValidationException(response *smithyhttp.Response, errorBody *bytes.Reader) error {
	output := &types.ValidationException{}
	buff := make([]byte, 1024)
	ringBuffer := smithyio.NewRingBuffer(buff)

	body := io.TeeReader(errorBody, ringBuffer)
	decoder := json.NewDecoder(body)
	decoder.UseNumber()

	err := awsRestjson1_deserializeDocumentValidationException(&output, decoder)

	if err != nil {
		var snapshot bytes.Buffer
		io.Copy(&snapshot, ringBuffer)
		return &smithy.DeserializationError{
			Err:      fmt.Errorf("failed to decode response body, %w", err),
			Snapshot: snapshot.Bytes(),
		}
	}

	errorBody.Seek(0, io.SeekStart)

	return output
}

func awsRestjson1_deserializeDocumentConflictException(v **types.ConflictException, decoder *json.Decoder) error {
	if v == nil {
		return fmt.Errorf("unexpected nil of type %T", v)
	}
	startToken, err := decoder.Token()
	if err == io.EOF {
		return nil
	}
	if err != nil {
		return err
	}
	if startToken == nil {
		return nil
	}
	if t, ok := startToken.(json.Delim); !ok || t != '{' {
		return fmt.Errorf("expect `{` as start token")
	}

	var sv *types.ConflictException
	if *v == nil {
		sv = &types.ConflictException{}
	} else {
		sv = *v
	}

	for decoder.More() {
		t, err := decoder.Token()
		if err != nil {
			return err
		}
		switch t {
		case "Message":
			val, err := decoder.Token()
			if err != nil {
				return err
			}
			if val != nil {
				jtv, ok := val.(string)
				if !ok {
					return fmt.Errorf("expected FailureReason to be of type string, got %T instead", val)
				}
				sv.Message = &jtv
			}

		default:
			err := smithyjson.DiscardUnknownField(decoder)
			if err != nil {
				return err
			}

		}
	}
	endToken, err := decoder.Token()
	if err != nil {
		return err
	}
	if t, ok := endToken.(json.Delim); !ok || t != '}' {
		return fmt.Errorf("expect `}` as end token")
	}

	*v = sv
	return nil
}

func awsRestjson1_deserializeDocumentHumanLoopOutput(v **types.HumanLoopOutput, decoder *json.Decoder) error {
	if v == nil {
		return fmt.Errorf("unexpected nil of type %T", v)
	}
	startToken, err := decoder.Token()
	if err == io.EOF {
		return nil
	}
	if err != nil {
		return err
	}
	if startToken == nil {
		return nil
	}
	if t, ok := startToken.(json.Delim); !ok || t != '{' {
		return fmt.Errorf("expect `{` as start token")
	}

	var sv *types.HumanLoopOutput
	if *v == nil {
		sv = &types.HumanLoopOutput{}
	} else {
		sv = *v
	}

	for decoder.More() {
		t, err := decoder.Token()
		if err != nil {
			return err
		}
		switch t {
		case "OutputS3Uri":
			val, err := decoder.Token()
			if err != nil {
				return err
			}
			if val != nil {
				jtv, ok := val.(string)
				if !ok {
					return fmt.Errorf("expected String to be of type string, got %T instead", val)
				}
				sv.OutputS3Uri = &jtv
			}

		default:
			err := smithyjson.DiscardUnknownField(decoder)
			if err != nil {
				return err
			}

		}
	}
	endToken, err := decoder.Token()
	if err != nil {
		return err
	}
	if t, ok := endToken.(json.Delim); !ok || t != '}' {
		return fmt.Errorf("expect `}` as end token")
	}

	*v = sv
	return nil
}

func awsRestjson1_deserializeDocumentHumanLoopSummaries(v *[]*types.HumanLoopSummary, decoder *json.Decoder) error {
	if v == nil {
		return fmt.Errorf("unexpected nil of type %T", v)
	}
	startToken, err := decoder.Token()
	if err == io.EOF {
		return nil
	}
	if err != nil {
		return err
	}
	if startToken == nil {
		return nil
	}
	if t, ok := startToken.(json.Delim); !ok || t != '[' {
		return fmt.Errorf("expect `[` as start token")
	}

	var cv []*types.HumanLoopSummary
	if *v == nil {
		cv = []*types.HumanLoopSummary{}
	} else {
		cv = *v
	}

	for decoder.More() {
		var col *types.HumanLoopSummary
		if err := awsRestjson1_deserializeDocumentHumanLoopSummary(&col, decoder); err != nil {
			return err
		}
		cv = append(cv, col)

	}
	endToken, err := decoder.Token()
	if err != nil {
		return err
	}
	if t, ok := endToken.(json.Delim); !ok || t != ']' {
		return fmt.Errorf("expect `]` as end token")
	}

	*v = cv
	return nil
}

func awsRestjson1_deserializeDocumentHumanLoopSummary(v **types.HumanLoopSummary, decoder *json.Decoder) error {
	if v == nil {
		return fmt.Errorf("unexpected nil of type %T", v)
	}
	startToken, err := decoder.Token()
	if err == io.EOF {
		return nil
	}
	if err != nil {
		return err
	}
	if startToken == nil {
		return nil
	}
	if t, ok := startToken.(json.Delim); !ok || t != '{' {
		return fmt.Errorf("expect `{` as start token")
	}

	var sv *types.HumanLoopSummary
	if *v == nil {
		sv = &types.HumanLoopSummary{}
	} else {
		sv = *v
	}

	for decoder.More() {
		t, err := decoder.Token()
		if err != nil {
			return err
		}
		switch t {
		case "CreationTime":
			val, err := decoder.Token()
			if err != nil {
				return err
			}
			if val != nil {
				jtv, ok := val.(json.Number)
				if !ok {
					return fmt.Errorf("expected Timestamp to be json.Number, got %T instead", val)
				}
				f64, err := jtv.Float64()
				if err != nil {
					return err
				}
				sv.CreationTime = ptr.Time(smithytime.ParseEpochSeconds(f64))
			}

		case "FailureReason":
			val, err := decoder.Token()
			if err != nil {
				return err
			}
			if val != nil {
				jtv, ok := val.(string)
				if !ok {
					return fmt.Errorf("expected FailureReason to be of type string, got %T instead", val)
				}
				sv.FailureReason = &jtv
			}

		case "FlowDefinitionArn":
			val, err := decoder.Token()
			if err != nil {
				return err
			}
			if val != nil {
				jtv, ok := val.(string)
				if !ok {
					return fmt.Errorf("expected FlowDefinitionArn to be of type string, got %T instead", val)
				}
				sv.FlowDefinitionArn = &jtv
			}

		case "HumanLoopName":
			val, err := decoder.Token()
			if err != nil {
				return err
			}
			if val != nil {
				jtv, ok := val.(string)
				if !ok {
					return fmt.Errorf("expected HumanLoopName to be of type string, got %T instead", val)
				}
				sv.HumanLoopName = &jtv
			}

		case "HumanLoopStatus":
			val, err := decoder.Token()
			if err != nil {
				return err
			}
			if val != nil {
				jtv, ok := val.(string)
				if !ok {
					return fmt.Errorf("expected HumanLoopStatus to be of type string, got %T instead", val)
				}
				sv.HumanLoopStatus = types.HumanLoopStatus(jtv)
			}

		default:
			err := smithyjson.DiscardUnknownField(decoder)
			if err != nil {
				return err
			}

		}
	}
	endToken, err := decoder.Token()
	if err != nil {
		return err
	}
	if t, ok := endToken.(json.Delim); !ok || t != '}' {
		return fmt.Errorf("expect `}` as end token")
	}

	*v = sv
	return nil
}

func awsRestjson1_deserializeDocumentInternalServerException(v **types.InternalServerException, decoder *json.Decoder) error {
	if v == nil {
		return fmt.Errorf("unexpected nil of type %T", v)
	}
	startToken, err := decoder.Token()
	if err == io.EOF {
		return nil
	}
	if err != nil {
		return err
	}
	if startToken == nil {
		return nil
	}
	if t, ok := startToken.(json.Delim); !ok || t != '{' {
		return fmt.Errorf("expect `{` as start token")
	}

	var sv *types.InternalServerException
	if *v == nil {
		sv = &types.InternalServerException{}
	} else {
		sv = *v
	}

	for decoder.More() {
		t, err := decoder.Token()
		if err != nil {
			return err
		}
		switch t {
		case "Message":
			val, err := decoder.Token()
			if err != nil {
				return err
			}
			if val != nil {
				jtv, ok := val.(string)
				if !ok {
					return fmt.Errorf("expected FailureReason to be of type string, got %T instead", val)
				}
				sv.Message = &jtv
			}

		default:
			err := smithyjson.DiscardUnknownField(decoder)
			if err != nil {
				return err
			}

		}
	}
	endToken, err := decoder.Token()
	if err != nil {
		return err
	}
	if t, ok := endToken.(json.Delim); !ok || t != '}' {
		return fmt.Errorf("expect `}` as end token")
	}

	*v = sv
	return nil
}

func awsRestjson1_deserializeDocumentResourceNotFoundException(v **types.ResourceNotFoundException, decoder *json.Decoder) error {
	if v == nil {
		return fmt.Errorf("unexpected nil of type %T", v)
	}
	startToken, err := decoder.Token()
	if err == io.EOF {
		return nil
	}
	if err != nil {
		return err
	}
	if startToken == nil {
		return nil
	}
	if t, ok := startToken.(json.Delim); !ok || t != '{' {
		return fmt.Errorf("expect `{` as start token")
	}

	var sv *types.ResourceNotFoundException
	if *v == nil {
		sv = &types.ResourceNotFoundException{}
	} else {
		sv = *v
	}

	for decoder.More() {
		t, err := decoder.Token()
		if err != nil {
			return err
		}
		switch t {
		case "Message":
			val, err := decoder.Token()
			if err != nil {
				return err
			}
			if val != nil {
				jtv, ok := val.(string)
				if !ok {
					return fmt.Errorf("expected FailureReason to be of type string, got %T instead", val)
				}
				sv.Message = &jtv
			}

		default:
			err := smithyjson.DiscardUnknownField(decoder)
			if err != nil {
				return err
			}

		}
	}
	endToken, err := decoder.Token()
	if err != nil {
		return err
	}
	if t, ok := endToken.(json.Delim); !ok || t != '}' {
		return fmt.Errorf("expect `}` as end token")
	}

	*v = sv
	return nil
}

func awsRestjson1_deserializeDocumentServiceQuotaExceededException(v **types.ServiceQuotaExceededException, decoder *json.Decoder) error {
	if v == nil {
		return fmt.Errorf("unexpected nil of type %T", v)
	}
	startToken, err := decoder.Token()
	if err == io.EOF {
		return nil
	}
	if err != nil {
		return err
	}
	if startToken == nil {
		return nil
	}
	if t, ok := startToken.(json.Delim); !ok || t != '{' {
		return fmt.Errorf("expect `{` as start token")
	}

	var sv *types.ServiceQuotaExceededException
	if *v == nil {
		sv = &types.ServiceQuotaExceededException{}
	} else {
		sv = *v
	}

	for decoder.More() {
		t, err := decoder.Token()
		if err != nil {
			return err
		}
		switch t {
		case "Message":
			val, err := decoder.Token()
			if err != nil {
				return err
			}
			if val != nil {
				jtv, ok := val.(string)
				if !ok {
					return fmt.Errorf("expected FailureReason to be of type string, got %T instead", val)
				}
				sv.Message = &jtv
			}

		default:
			err := smithyjson.DiscardUnknownField(decoder)
			if err != nil {
				return err
			}

		}
	}
	endToken, err := decoder.Token()
	if err != nil {
		return err
	}
	if t, ok := endToken.(json.Delim); !ok || t != '}' {
		return fmt.Errorf("expect `}` as end token")
	}

	*v = sv
	return nil
}

func awsRestjson1_deserializeDocumentThrottlingException(v **types.ThrottlingException, decoder *json.Decoder) error {
	if v == nil {
		return fmt.Errorf("unexpected nil of type %T", v)
	}
	startToken, err := decoder.Token()
	if err == io.EOF {
		return nil
	}
	if err != nil {
		return err
	}
	if startToken == nil {
		return nil
	}
	if t, ok := startToken.(json.Delim); !ok || t != '{' {
		return fmt.Errorf("expect `{` as start token")
	}

	var sv *types.ThrottlingException
	if *v == nil {
		sv = &types.ThrottlingException{}
	} else {
		sv = *v
	}

	for decoder.More() {
		t, err := decoder.Token()
		if err != nil {
			return err
		}
		switch t {
		case "Message":
			val, err := decoder.Token()
			if err != nil {
				return err
			}
			if val != nil {
				jtv, ok := val.(string)
				if !ok {
					return fmt.Errorf("expected FailureReason to be of type string, got %T instead", val)
				}
				sv.Message = &jtv
			}

		default:
			err := smithyjson.DiscardUnknownField(decoder)
			if err != nil {
				return err
			}

		}
	}
	endToken, err := decoder.Token()
	if err != nil {
		return err
	}
	if t, ok := endToken.(json.Delim); !ok || t != '}' {
		return fmt.Errorf("expect `}` as end token")
	}

	*v = sv
	return nil
}

func awsRestjson1_deserializeDocumentValidationException(v **types.ValidationException, decoder *json.Decoder) error {
	if v == nil {
		return fmt.Errorf("unexpected nil of type %T", v)
	}
	startToken, err := decoder.Token()
	if err == io.EOF {
		return nil
	}
	if err != nil {
		return err
	}
	if startToken == nil {
		return nil
	}
	if t, ok := startToken.(json.Delim); !ok || t != '{' {
		return fmt.Errorf("expect `{` as start token")
	}

	var sv *types.ValidationException
	if *v == nil {
		sv = &types.ValidationException{}
	} else {
		sv = *v
	}

	for decoder.More() {
		t, err := decoder.Token()
		if err != nil {
			return err
		}
		switch t {
		case "Message":
			val, err := decoder.Token()
			if err != nil {
				return err
			}
			if val != nil {
				jtv, ok := val.(string)
				if !ok {
					return fmt.Errorf("expected FailureReason to be of type string, got %T instead", val)
				}
				sv.Message = &jtv
			}

		default:
			err := smithyjson.DiscardUnknownField(decoder)
			if err != nil {
				return err
			}

		}
	}
	endToken, err := decoder.Token()
	if err != nil {
		return err
	}
	if t, ok := endToken.(json.Delim); !ok || t != '}' {
		return fmt.Errorf("expect `}` as end token")
	}

	*v = sv
	return nil
}