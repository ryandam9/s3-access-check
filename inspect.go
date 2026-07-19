package main

import (
	"context"
	"errors"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/smithy-go"
)

// InspectResult is the authenticated view of why a resource is or is not
// public. Each field is best-effort: a nil pointer or a non-empty Error means
// that particular check could not be completed (missing permission, no policy,
// etc.), which is reported rather than treated as failure.
type InspectResult struct {
	Target Target

	PublicAccessBlock *PublicAccessBlock `json:"publicAccessBlock,omitempty"`
	PolicyIsPublic    *bool              `json:"policyIsPublic,omitempty"`
	ACLGrantsPublic   *bool              `json:"aclGrantsPublic,omitempty"`
	ACLGrantees       []string           `json:"aclPublicGrantees,omitempty"`

	Errors map[string]string `json:"errors,omitempty"`
}

// PublicAccessBlock mirrors the four S3 Block Public Access settings.
type PublicAccessBlock struct {
	BlockPublicACLs       bool `json:"blockPublicAcls"`
	IgnorePublicACLs      bool `json:"ignorePublicAcls"`
	BlockPublicPolicy     bool `json:"blockPublicPolicy"`
	RestrictPublicBuckets bool `json:"restrictPublicBuckets"`
}

const (
	allUsersURI           = "http://acs.amazonaws.com/groups/global/AllUsers"
	authenticatedUsersURI = "http://acs.amazonaws.com/groups/global/AuthenticatedUsers"
)

// Inspect uses AWS credentials to read the configuration that governs public
// access. It requires read permissions (s3:GetBucketPolicyStatus,
// s3:GetBucketPublicAccessBlock, s3:GetBucketAcl, s3:GetObjectAcl) and only
// works for buckets in the caller's account.
func Inspect(ctx context.Context, t Target, region string) (InspectResult, error) {
	res := InspectResult{Target: t, Errors: map[string]string{}}

	opts := []func(*awsconfig.LoadOptions) error{}
	if region != "" {
		opts = append(opts, awsconfig.WithRegion(region))
	}
	cfg, err := awsconfig.LoadDefaultConfig(ctx, opts...)
	if err != nil {
		return res, fmt.Errorf("loading AWS config: %w", err)
	}
	if _, err := cfg.Credentials.Retrieve(ctx); err != nil {
		return res, fmt.Errorf("no usable AWS credentials found: %w", err)
	}

	client := s3.NewFromConfig(cfg)

	// Block Public Access settings.
	if pab, err := client.GetPublicAccessBlock(ctx, &s3.GetPublicAccessBlockInput{
		Bucket: aws.String(t.Bucket),
	}); err != nil {
		res.Errors["publicAccessBlock"] = friendlyErr(err)
	} else if c := pab.PublicAccessBlockConfiguration; c != nil {
		res.PublicAccessBlock = &PublicAccessBlock{
			BlockPublicACLs:       aws.ToBool(c.BlockPublicAcls),
			IgnorePublicACLs:      aws.ToBool(c.IgnorePublicAcls),
			BlockPublicPolicy:     aws.ToBool(c.BlockPublicPolicy),
			RestrictPublicBuckets: aws.ToBool(c.RestrictPublicBuckets),
		}
	}

	// Bucket policy status.
	if st, err := client.GetBucketPolicyStatus(ctx, &s3.GetBucketPolicyStatusInput{
		Bucket: aws.String(t.Bucket),
	}); err != nil {
		res.Errors["policyStatus"] = friendlyErr(err)
	} else if st.PolicyStatus != nil {
		res.PolicyIsPublic = aws.Bool(aws.ToBool(st.PolicyStatus.IsPublic))
	}

	// ACL grants — object ACL when targeting an object, otherwise bucket ACL.
	var grants []types.Grant
	if t.IsObject() {
		acl, err := client.GetObjectAcl(ctx, &s3.GetObjectAclInput{
			Bucket: aws.String(t.Bucket),
			Key:    aws.String(t.Key),
		})
		if err != nil {
			res.Errors["objectAcl"] = friendlyErr(err)
		} else {
			grants = acl.Grants
		}
	} else {
		acl, err := client.GetBucketAcl(ctx, &s3.GetBucketAclInput{
			Bucket: aws.String(t.Bucket),
		})
		if err != nil {
			res.Errors["bucketAcl"] = friendlyErr(err)
		} else {
			grants = acl.Grants
		}
	}
	if grants != nil {
		public := false
		for _, g := range grants {
			if g.Grantee == nil || g.Grantee.URI == nil {
				continue
			}
			switch aws.ToString(g.Grantee.URI) {
			case allUsersURI:
				public = true
				res.ACLGrantees = append(res.ACLGrantees, "AllUsers("+string(g.Permission)+")")
			case authenticatedUsersURI:
				res.ACLGrantees = append(res.ACLGrantees, "AuthenticatedUsers("+string(g.Permission)+")")
			}
		}
		res.ACLGrantsPublic = aws.Bool(public)
	}

	if len(res.Errors) == 0 {
		res.Errors = nil
	}
	return res, nil
}

// friendlyErr turns an AWS API error into a short, readable string.
func friendlyErr(err error) string {
	var apiErr smithy.APIError
	if errors.As(err, &apiErr) {
		return apiErr.ErrorCode()
	}
	return err.Error()
}
