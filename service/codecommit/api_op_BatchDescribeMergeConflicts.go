// Code generated by smithy-go-codegen DO NOT EDIT.

package codecommit

import (
	"context"
	awsmiddleware "github.com/aws/aws-sdk-go-v2/aws/middleware"
	"github.com/aws/aws-sdk-go-v2/aws/retry"
	"github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/aws/aws-sdk-go-v2/service/codecommit/types"
	smithy "github.com/awslabs/smithy-go"
	"github.com/awslabs/smithy-go/middleware"
	smithyhttp "github.com/awslabs/smithy-go/transport/http"
)

// Returns information about one or more merge conflicts in the attempted merge of
// two commit specifiers using the squash or three-way merge strategy.
func (c *Client) BatchDescribeMergeConflicts(ctx context.Context, params *BatchDescribeMergeConflictsInput, optFns ...func(*Options)) (*BatchDescribeMergeConflictsOutput, error) {
	stack := middleware.NewStack("BatchDescribeMergeConflicts", smithyhttp.NewStackRequest)
	options := c.options.Copy()
	for _, fn := range optFns {
		fn(&options)
	}
	addawsAwsjson11_serdeOpBatchDescribeMergeConflictsMiddlewares(stack)
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
	addOpBatchDescribeMergeConflictsValidationMiddleware(stack)
	stack.Initialize.Add(newServiceMetadataMiddleware_opBatchDescribeMergeConflicts(options.Region), middleware.Before)

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
			OperationName: "BatchDescribeMergeConflicts",
			Err:           err,
		}
	}
	out := result.(*BatchDescribeMergeConflictsOutput)
	out.ResultMetadata = metadata
	return out, nil
}

type BatchDescribeMergeConflictsInput struct {
	// The branch, tag, HEAD, or other fully qualified reference used to identify a
	// commit (for example, a branch name or a full commit ID).
	DestinationCommitSpecifier *string
	// The maximum number of merge hunks to include in the output.
	MaxMergeHunks *int32
	// The branch, tag, HEAD, or other fully qualified reference used to identify a
	// commit (for example, a branch name or a full commit ID).
	SourceCommitSpecifier *string
	// The level of conflict detail to use. If unspecified, the default FILE_LEVEL is
	// used, which returns a not-mergeable result if the same file has differences in
	// both branches. If LINE_LEVEL is specified, a conflict is considered not
	// mergeable if the same file in both branches has differences on the same line.
	ConflictDetailLevel types.ConflictDetailLevelTypeEnum
	// An enumeration token that, when provided in a request, returns the next batch of
	// the results.
	NextToken *string
	// The merge option or strategy you want to use to merge the code.
	MergeOption types.MergeOptionTypeEnum
	// The name of the repository that contains the merge conflicts you want to review.
	RepositoryName *string
	// Specifies which branch to use when resolving conflicts, or whether to attempt
	// automatically merging two versions of a file. The default is NONE, which
	// requires any conflicts to be resolved manually before the merge operation is
	// successful.
	ConflictResolutionStrategy types.ConflictResolutionStrategyTypeEnum
	// The maximum number of files to include in the output.
	MaxConflictFiles *int32
	// The path of the target files used to describe the conflicts. If not specified,
	// the default is all conflict files.
	FilePaths []*string
}

type BatchDescribeMergeConflictsOutput struct {
	// The commit ID of the merge base.
	BaseCommitId *string
	// A list of conflicts for each file, including the conflict metadata and the hunks
	// of the differences between the files.
	Conflicts []*types.Conflict
	// The commit ID of the source commit specifier that was used in the merge
	// evaluation.
	SourceCommitId *string
	// An enumeration token that can be used in a request to return the next batch of
	// the results.
	NextToken *string
	// A list of any errors returned while describing the merge conflicts for each
	// file.
	Errors []*types.BatchDescribeMergeConflictsError
	// The commit ID of the destination commit specifier that was used in the merge
	// evaluation.
	DestinationCommitId *string

	// Metadata pertaining to the operation's result.
	ResultMetadata middleware.Metadata
}

func addawsAwsjson11_serdeOpBatchDescribeMergeConflictsMiddlewares(stack *middleware.Stack) {
	stack.Serialize.Add(&awsAwsjson11_serializeOpBatchDescribeMergeConflicts{}, middleware.After)
	stack.Deserialize.Add(&awsAwsjson11_deserializeOpBatchDescribeMergeConflicts{}, middleware.After)
}

func newServiceMetadataMiddleware_opBatchDescribeMergeConflicts(region string) awsmiddleware.RegisterServiceMetadata {
	return awsmiddleware.RegisterServiceMetadata{
		Region:        region,
		ServiceID:     ServiceID,
		SigningName:   "codecommit",
		OperationName: "BatchDescribeMergeConflicts",
	}
}