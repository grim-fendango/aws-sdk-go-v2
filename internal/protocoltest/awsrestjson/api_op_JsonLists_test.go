// Code generated by smithy-go-codegen DO NOT EDIT.

package awsrestjson

import (
	"bytes"
	"context"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/internal/protocoltest/awsrestjson/types"
	"github.com/awslabs/smithy-go/middleware"
	"github.com/awslabs/smithy-go/ptr"
	smithyrand "github.com/awslabs/smithy-go/rand"
	smithytesting "github.com/awslabs/smithy-go/testing"
	smithytime "github.com/awslabs/smithy-go/time"
	"github.com/google/go-cmp/cmp/cmpopts"
	"io"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"
)

func TestClient_JsonLists_awsRestjson1Serialize(t *testing.T) {
	cases := map[string]struct {
		Params        *JsonListsInput
		ExpectMethod  string
		ExpectURIPath string
		ExpectQuery   []smithytesting.QueryItem
		RequireQuery  []string
		ForbidQuery   []string
		ExpectHeader  http.Header
		RequireHeader []string
		ForbidHeader  []string
		BodyMediaType string
		BodyAssert    func(io.Reader) error
	}{
		// Serializes JSON lists
		"RestJsonLists": {
			Params: &JsonListsInput{
				StringList: []*string{
					ptr.String("foo"),
					ptr.String("bar"),
				},
				StringSet: []*string{
					ptr.String("foo"),
					ptr.String("bar"),
				},
				IntegerList: []*int32{
					ptr.Int32(1),
					ptr.Int32(2),
				},
				BooleanList: []*bool{
					ptr.Bool(true),
					ptr.Bool(false),
				},
				TimestampList: []*time.Time{
					ptr.Time(smithytime.ParseEpochSeconds(1398796238)),
					ptr.Time(smithytime.ParseEpochSeconds(1398796238)),
				},
				EnumList: []types.FooEnum{
					types.FooEnum("Foo"),
					types.FooEnum("0"),
				},
				NestedStringList: [][]*string{
					{
						ptr.String("foo"),
						ptr.String("bar"),
					},
					{
						ptr.String("baz"),
						ptr.String("qux"),
					},
				},
				StructureList: []*types.StructureListMember{
					{
						A: ptr.String("1"),
						B: ptr.String("2"),
					},
					{
						A: ptr.String("3"),
						B: ptr.String("4"),
					},
				},
			},
			ExpectMethod:  "PUT",
			ExpectURIPath: "/JsonLists",
			ExpectQuery:   []smithytesting.QueryItem{},
			ExpectHeader: http.Header{
				"Content-Type": []string{"application/json"},
			},
			BodyMediaType: "application/json",
			BodyAssert: func(actual io.Reader) error {
				return smithytesting.CompareJSONReaderBytes(actual, []byte(`{
			    "stringList": [
			        "foo",
			        "bar"
			    ],
			    "stringSet": [
			        "foo",
			        "bar"
			    ],
			    "integerList": [
			        1,
			        2
			    ],
			    "booleanList": [
			        true,
			        false
			    ],
			    "timestampList": [
			        1398796238,
			        1398796238
			    ],
			    "enumList": [
			        "Foo",
			        "0"
			    ],
			    "nestedStringList": [
			        [
			            "foo",
			            "bar"
			        ],
			        [
			            "baz",
			            "qux"
			        ]
			    ],
			    "myStructureList": [
			        {
			            "value": "1",
			            "other": "2"
			        },
			        {
			            "value": "3",
			            "other": "4"
			        }
			    ]
			}`))
			},
		},
		// Serializes empty JSON lists
		"RestJsonListsEmpty": {
			Params: &JsonListsInput{
				StringList: []*string{},
			},
			ExpectMethod:  "PUT",
			ExpectURIPath: "/JsonLists",
			ExpectQuery:   []smithytesting.QueryItem{},
			ExpectHeader: http.Header{
				"Content-Type": []string{"application/json"},
			},
			BodyMediaType: "application/json",
			BodyAssert: func(actual io.Reader) error {
				return smithytesting.CompareJSONReaderBytes(actual, []byte(`{
			    "stringList": []
			}`))
			},
		},
		// Serializes null values in lists
		"RestJsonListsSerializeNull": {
			Params: &JsonListsInput{
				StringList: []*string{
					nil,
				},
			},
			ExpectMethod:  "PUT",
			ExpectURIPath: "/JsonLists",
			ExpectQuery:   []smithytesting.QueryItem{},
			ExpectHeader: http.Header{
				"Content-Type": []string{"application/json"},
			},
			BodyMediaType: "application/json",
			BodyAssert: func(actual io.Reader) error {
				return smithytesting.CompareJSONReaderBytes(actual, []byte(`{
			    "stringList": [
			        null
			    ]
			}`))
			},
		},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			var actualReq *http.Request
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				actualReq = r.Clone(r.Context())
				if len(actualReq.URL.RawPath) == 0 {
					actualReq.URL.RawPath = actualReq.URL.Path
				}
				if v := actualReq.ContentLength; v != 0 {
					actualReq.Header.Set("Content-Length", strconv.FormatInt(v, 10))
				}
				var buf bytes.Buffer
				if _, err := io.Copy(&buf, r.Body); err != nil {
					t.Errorf("failed to read request body, %v", err)
				}
				actualReq.Body = ioutil.NopCloser(&buf)

				w.WriteHeader(200)
			}))
			defer server.Close()
			client := New(Options{
				APIOptions: []APIOptionFunc{
					func(s *middleware.Stack) error {
						s.Finalize.Clear()
						return nil
					},
				},
				EndpointResolver: EndpointResolverFunc(func(region string, options ResolverOptions) (e aws.Endpoint, err error) {
					e.URL = server.URL
					e.SigningRegion = "us-west-2"
					return e, err
				}),
				HTTPClient:               aws.NewBuildableHTTPClient(),
				IdempotencyTokenProvider: smithyrand.NewUUIDIdempotencyToken(&smithytesting.ByteLoop{}),
				Region:                   "us-west-2",
			})
			result, err := client.JsonLists(context.Background(), c.Params)
			if err != nil {
				t.Fatalf("expect nil err, got %v", err)
			}
			if result == nil {
				t.Fatalf("expect not nil result")
			}
			if e, a := c.ExpectMethod, actualReq.Method; e != a {
				t.Errorf("expect %v method, got %v", e, a)
			}
			if e, a := c.ExpectURIPath, actualReq.URL.RawPath; e != a {
				t.Errorf("expect %v path, got %v", e, a)
			}
			queryItems := smithytesting.ParseRawQuery(actualReq.URL.RawQuery)
			smithytesting.AssertHasQuery(t, c.ExpectQuery, queryItems)
			smithytesting.AssertHasQueryKeys(t, c.RequireQuery, queryItems)
			smithytesting.AssertNotHaveQueryKeys(t, c.ForbidQuery, queryItems)
			smithytesting.AssertHasHeader(t, c.ExpectHeader, actualReq.Header)
			smithytesting.AssertHasHeaderKeys(t, c.RequireHeader, actualReq.Header)
			smithytesting.AssertNotHaveHeaderKeys(t, c.ForbidHeader, actualReq.Header)
			if actualReq.Body != nil {
				defer actualReq.Body.Close()
			}
			if c.BodyAssert != nil {
				if err := c.BodyAssert(actualReq.Body); err != nil {
					t.Errorf("expect body equal, got %v", err)
				}
			}
		})
	}
}

func TestClient_JsonLists_awsRestjson1Deserialize(t *testing.T) {
	cases := map[string]struct {
		StatusCode    int
		Header        http.Header
		BodyMediaType string
		Body          []byte
		ExpectResult  *JsonListsOutput
	}{
		// Serializes JSON lists
		"RestJsonLists": {
			StatusCode: 200,
			Header: http.Header{
				"Content-Type": []string{"application/json"},
			},
			BodyMediaType: "application/json",
			Body: []byte(`{
			    "stringList": [
			        "foo",
			        "bar"
			    ],
			    "stringSet": [
			        "foo",
			        "bar"
			    ],
			    "integerList": [
			        1,
			        2
			    ],
			    "booleanList": [
			        true,
			        false
			    ],
			    "timestampList": [
			        1398796238,
			        1398796238
			    ],
			    "enumList": [
			        "Foo",
			        "0"
			    ],
			    "nestedStringList": [
			        [
			            "foo",
			            "bar"
			        ],
			        [
			            "baz",
			            "qux"
			        ]
			    ],
			    "myStructureList": [
			        {
			            "value": "1",
			            "other": "2"
			        },
			        {
			            "value": "3",
			            "other": "4"
			        }
			    ]
			}`),
			ExpectResult: &JsonListsOutput{
				StringList: []*string{
					ptr.String("foo"),
					ptr.String("bar"),
				},
				StringSet: []*string{
					ptr.String("foo"),
					ptr.String("bar"),
				},
				IntegerList: []*int32{
					ptr.Int32(1),
					ptr.Int32(2),
				},
				BooleanList: []*bool{
					ptr.Bool(true),
					ptr.Bool(false),
				},
				TimestampList: []*time.Time{
					ptr.Time(smithytime.ParseEpochSeconds(1398796238)),
					ptr.Time(smithytime.ParseEpochSeconds(1398796238)),
				},
				EnumList: []types.FooEnum{
					types.FooEnum("Foo"),
					types.FooEnum("0"),
				},
				NestedStringList: [][]*string{
					{
						ptr.String("foo"),
						ptr.String("bar"),
					},
					{
						ptr.String("baz"),
						ptr.String("qux"),
					},
				},
				StructureList: []*types.StructureListMember{
					{
						A: ptr.String("1"),
						B: ptr.String("2"),
					},
					{
						A: ptr.String("3"),
						B: ptr.String("4"),
					},
				},
			},
		},
		// Serializes empty JSON lists
		"RestJsonListsEmpty": {
			StatusCode: 200,
			Header: http.Header{
				"Content-Type": []string{"application/json"},
			},
			BodyMediaType: "application/json",
			Body: []byte(`{
			    "stringList": []
			}`),
			ExpectResult: &JsonListsOutput{
				StringList: []*string{},
			},
		},
		// Serializes null values in lists
		"RestJsonListsSerializeNull": {
			StatusCode: 200,
			Header: http.Header{
				"Content-Type": []string{"application/json"},
			},
			BodyMediaType: "application/json",
			Body: []byte(`{
			    "stringList": [
			        null
			    ]
			}`),
			ExpectResult: &JsonListsOutput{
				StringList: []*string{
					nil,
				},
			},
		},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				for k, vs := range c.Header {
					for _, v := range vs {
						w.Header().Add(k, v)
					}
				}
				if len(c.BodyMediaType) != 0 && len(w.Header().Values("Content-Type")) == 0 {
					w.Header().Set("Content-Type", c.BodyMediaType)
				}
				if len(c.Body) != 0 {
					w.Header().Set("Content-Length", strconv.Itoa(len(c.Body)))
				}
				w.WriteHeader(c.StatusCode)
				if len(c.Body) != 0 {
					if _, err := io.Copy(w, bytes.NewReader(c.Body)); err != nil {
						t.Errorf("failed to write response body, %v", err)
					}
				}
			}))
			defer server.Close()
			client := New(Options{
				APIOptions: []APIOptionFunc{
					func(s *middleware.Stack) error {
						s.Finalize.Clear()
						return nil
					},
				},
				EndpointResolver: EndpointResolverFunc(func(region string, options ResolverOptions) (e aws.Endpoint, err error) {
					e.URL = server.URL
					e.SigningRegion = "us-west-2"
					return e, err
				}),
				HTTPClient:               aws.NewBuildableHTTPClient(),
				IdempotencyTokenProvider: smithyrand.NewUUIDIdempotencyToken(&smithytesting.ByteLoop{}),
				Region:                   "us-west-2",
			})
			var params JsonListsInput
			result, err := client.JsonLists(context.Background(), &params)
			if err != nil {
				t.Fatalf("expect nil err, got %v", err)
			}
			if result == nil {
				t.Fatalf("expect not nil result")
			}
			if err := smithytesting.CompareValues(c.ExpectResult, result, cmpopts.IgnoreUnexported(middleware.Metadata{})); err != nil {
				t.Errorf("expect c.ExpectResult value match:\n%v", err)
			}
		})
	}
}
