// Code generated by private/model/cli/gen-api/main.go. DO NOT EDIT.

package rekognition

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/internal/awsutil"
)

type RecognizeCelebritiesInput struct {
	_ struct{} `type:"structure"`

	// The input image as base64-encoded bytes or an S3 object. If you use the AWS
	// CLI to call Amazon Rekognition operations, passing base64-encoded image bytes
	// is not supported.
	//
	// If you are using an AWS SDK to call Amazon Rekognition, you might not need
	// to base64-encode image bytes passed using the Bytes field. For more information,
	// see Images in the Amazon Rekognition developer guide.
	//
	// Image is a required field
	Image *Image `type:"structure" required:"true"`
}

// String returns the string representation
func (s RecognizeCelebritiesInput) String() string {
	return awsutil.Prettify(s)
}

// Validate inspects the fields of the type to determine if they are valid.
func (s *RecognizeCelebritiesInput) Validate() error {
	invalidParams := aws.ErrInvalidParams{Context: "RecognizeCelebritiesInput"}

	if s.Image == nil {
		invalidParams.Add(aws.NewErrParamRequired("Image"))
	}
	if s.Image != nil {
		if err := s.Image.Validate(); err != nil {
			invalidParams.AddNested("Image", err.(aws.ErrInvalidParams))
		}
	}

	if invalidParams.Len() > 0 {
		return invalidParams
	}
	return nil
}

type RecognizeCelebritiesOutput struct {
	_ struct{} `type:"structure"`

	// Details about each celebrity found in the image. Amazon Rekognition can detect
	// a maximum of 15 celebrities in an image.
	CelebrityFaces []Celebrity `type:"list"`

	// The orientation of the input image (counterclockwise direction). If your
	// application displays the image, you can use this value to correct the orientation.
	// The bounding box coordinates returned in CelebrityFaces and UnrecognizedFaces
	// represent face locations before the image orientation is corrected.
	//
	// If the input image is in .jpeg format, it might contain exchangeable image
	// (Exif) metadata that includes the image's orientation. If so, and the Exif
	// metadata for the input image populates the orientation field, the value of
	// OrientationCorrection is null. The CelebrityFaces and UnrecognizedFaces bounding
	// box coordinates represent face locations after Exif metadata is used to correct
	// the image orientation. Images in .png format don't contain Exif metadata.
	OrientationCorrection OrientationCorrection `type:"string" enum:"true"`

	// Details about each unrecognized face in the image.
	UnrecognizedFaces []ComparedFace `type:"list"`
}

// String returns the string representation
func (s RecognizeCelebritiesOutput) String() string {
	return awsutil.Prettify(s)
}

const opRecognizeCelebrities = "RecognizeCelebrities"

// RecognizeCelebritiesRequest returns a request value for making API operation for
// Amazon Rekognition.
//
// Returns an array of celebrities recognized in the input image. For more information,
// see Recognizing Celebrities in the Amazon Rekognition Developer Guide.
//
// RecognizeCelebrities returns the 100 largest faces in the image. It lists
// recognized celebrities in the CelebrityFaces array and unrecognized faces
// in the UnrecognizedFaces array. RecognizeCelebrities doesn't return celebrities
// whose faces aren't among the largest 100 faces in the image.
//
// For each celebrity recognized, RecognizeCelebrities returns a Celebrity object.
// The Celebrity object contains the celebrity name, ID, URL links to additional
// information, match confidence, and a ComparedFace object that you can use
// to locate the celebrity's face on the image.
//
// Amazon Rekognition doesn't retain information about which images a celebrity
// has been recognized in. Your application must store this information and
// use the Celebrity ID property as a unique identifier for the celebrity. If
// you don't store the celebrity name or additional information URLs returned
// by RecognizeCelebrities, you will need the ID to identify the celebrity in
// a call to the GetCelebrityInfo operation.
//
// You pass the input image either as base64-encoded image bytes or as a reference
// to an image in an Amazon S3 bucket. If you use the AWS CLI to call Amazon
// Rekognition operations, passing image bytes is not supported. The image must
// be either a PNG or JPEG formatted file.
//
// For an example, see Recognizing Celebrities in an Image in the Amazon Rekognition
// Developer Guide.
//
// This operation requires permissions to perform the rekognition:RecognizeCelebrities
// operation.
//
//    // Example sending a request using RecognizeCelebritiesRequest.
//    req := client.RecognizeCelebritiesRequest(params)
//    resp, err := req.Send(context.TODO())
//    if err == nil {
//        fmt.Println(resp)
//    }
func (c *Client) RecognizeCelebritiesRequest(input *RecognizeCelebritiesInput) RecognizeCelebritiesRequest {
	op := &aws.Operation{
		Name:       opRecognizeCelebrities,
		HTTPMethod: "POST",
		HTTPPath:   "/",
	}

	if input == nil {
		input = &RecognizeCelebritiesInput{}
	}

	req := c.newRequest(op, input, &RecognizeCelebritiesOutput{})

	return RecognizeCelebritiesRequest{Request: req, Input: input, Copy: c.RecognizeCelebritiesRequest}
}

// RecognizeCelebritiesRequest is the request type for the
// RecognizeCelebrities API operation.
type RecognizeCelebritiesRequest struct {
	*aws.Request
	Input *RecognizeCelebritiesInput
	Copy  func(*RecognizeCelebritiesInput) RecognizeCelebritiesRequest
}

// Send marshals and sends the RecognizeCelebrities API request.
func (r RecognizeCelebritiesRequest) Send(ctx context.Context) (*RecognizeCelebritiesResponse, error) {
	r.Request.SetContext(ctx)
	err := r.Request.Send()
	if err != nil {
		return nil, err
	}

	resp := &RecognizeCelebritiesResponse{
		RecognizeCelebritiesOutput: r.Request.Data.(*RecognizeCelebritiesOutput),
		response:                   &aws.Response{Request: r.Request},
	}

	return resp, nil
}

// RecognizeCelebritiesResponse is the response type for the
// RecognizeCelebrities API operation.
type RecognizeCelebritiesResponse struct {
	*RecognizeCelebritiesOutput

	response *aws.Response
}

// SDKResponseMetdata returns the response metadata for the
// RecognizeCelebrities request.
func (r *RecognizeCelebritiesResponse) SDKResponseMetdata() *aws.Response {
	return r.response
}