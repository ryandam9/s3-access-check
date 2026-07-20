package main

import (
	"context"
	"errors"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/aws-sdk-go-v2/service/s3control"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/aws/smithy-go"
)

// InspectResult is the authenticated view of why a resource is or is not
// public. Each field is best-effort: a failed check is recorded in Errors
// (permission/service failures) or normalized into an explicit "absent" state,
// so a missing bucket policy is not reported as an error.
type InspectResult struct {
	Target Target `json:"target"`

	BucketPublicAccessBlock  *PublicAccessBlock `json:"bucketPublicAccessBlock,omitempty"`
	AccountPublicAccessBlock *PublicAccessBlock `json:"accountPublicAccessBlock,omitempty"`
	BucketPolicy             PolicyInfo         `json:"bucketPolicy"`
	ACL                      ACLInfo            `json:"acl"`

	Errors   map[string]string `json:"errors,omitempty"`
	Warnings []string          `json:"warnings,omitempty"`
}

// PublicAccessBlock mirrors the four S3 Block Public Access settings. Configured
// distinguishes "all four are false" from "no configuration is set".
type PublicAccessBlock struct {
	Configured            bool `json:"configured"`
	BlockPublicACLs       bool `json:"blockPublicAcls"`
	IgnorePublicACLs      bool `json:"ignorePublicAcls"`
	BlockPublicPolicy     bool `json:"blockPublicPolicy"`
	RestrictPublicBuckets bool `json:"restrictPublicBuckets"`
}

// PolicyInfo reports whether a bucket policy exists and, if so, whether S3
// considers it public.
type PolicyInfo struct {
	Present bool  `json:"present"`
	Public  *bool `json:"public,omitempty"`
}

// ACLInfo reports ACL grants relevant to public access, evaluated against the
// operation being checked. Anonymous (AllUsers) and any-authenticated-AWS-user
// (AuthenticatedUsers) grants are reported separately because only the former
// is anonymous internet access.
type ACLInfo struct {
	AllowsAnonymousOperation    *bool    `json:"allowsAnonymousOperation,omitempty"`
	AnonymousGrants             []string `json:"anonymousGrants,omitempty"`
	AuthenticatedAWSUsersGrants []string `json:"authenticatedAwsUsersGrants,omitempty"`
}

const (
	allUsersURI           = "http://acs.amazonaws.com/groups/global/AllUsers"
	authenticatedUsersURI = "http://acs.amazonaws.com/groups/global/AuthenticatedUsers"
)

// Inspect uses AWS credentials to read the configuration that governs public
// access. It requires read permissions (s3:GetBucketPolicyStatus,
// s3:GetBucketPublicAccessBlock, s3:GetBucketAcl, s3:GetObjectAcl, and — for
// account-level Block Public Access — s3:GetAccountPublicAccessBlock plus
// sts:GetCallerIdentity) and only works for buckets in the caller's account.
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

	inspectBucketPAB(ctx, client, t, &res)
	inspectAccountPAB(ctx, cfg, &res)
	inspectPolicyStatus(ctx, client, t, &res)
	inspectACL(ctx, client, t, &res)

	if len(res.Errors) == 0 {
		res.Errors = nil
	}
	return res, nil
}

func inspectBucketPAB(ctx context.Context, client *s3.Client, t Target, res *InspectResult) {
	pab, err := client.GetPublicAccessBlock(ctx, &s3.GetPublicAccessBlockInput{Bucket: aws.String(t.Bucket)})
	if err != nil {
		if isAWSCode(err, "NoSuchPublicAccessBlockConfiguration") {
			res.BucketPublicAccessBlock = &PublicAccessBlock{Configured: false}
			return
		}
		res.Errors["bucketPublicAccessBlock"] = friendlyErr(err)
		return
	}
	if c := pab.PublicAccessBlockConfiguration; c != nil {
		res.BucketPublicAccessBlock = &PublicAccessBlock{
			Configured:            true,
			BlockPublicACLs:       aws.ToBool(c.BlockPublicAcls),
			IgnorePublicACLs:      aws.ToBool(c.IgnorePublicAcls),
			BlockPublicPolicy:     aws.ToBool(c.BlockPublicPolicy),
			RestrictPublicBuckets: aws.ToBool(c.RestrictPublicBuckets),
		}
	}
}

func inspectAccountPAB(ctx context.Context, cfg aws.Config, res *InspectResult) {
	id, err := sts.NewFromConfig(cfg).GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err != nil {
		res.Warnings = append(res.Warnings, "account-level Block Public Access not inspected: "+friendlyErr(err))
		return
	}
	acct := aws.ToString(id.Account)
	pab, err := s3control.NewFromConfig(cfg).GetPublicAccessBlock(ctx, &s3control.GetPublicAccessBlockInput{
		AccountId: aws.String(acct),
	})
	if err != nil {
		if isAWSCode(err, "NoSuchPublicAccessBlockConfiguration") {
			res.AccountPublicAccessBlock = &PublicAccessBlock{Configured: false}
			return
		}
		res.Warnings = append(res.Warnings, "account-level Block Public Access not inspected: "+friendlyErr(err))
		return
	}
	if c := pab.PublicAccessBlockConfiguration; c != nil {
		res.AccountPublicAccessBlock = &PublicAccessBlock{
			Configured:            true,
			BlockPublicACLs:       aws.ToBool(c.BlockPublicAcls),
			IgnorePublicACLs:      aws.ToBool(c.IgnorePublicAcls),
			BlockPublicPolicy:     aws.ToBool(c.BlockPublicPolicy),
			RestrictPublicBuckets: aws.ToBool(c.RestrictPublicBuckets),
		}
	}
	res.Warnings = append(res.Warnings, "account-level results may still inherit stricter organization (SCP) policy that is not visible here")
}

func inspectPolicyStatus(ctx context.Context, client *s3.Client, t Target, res *InspectResult) {
	st, err := client.GetBucketPolicyStatus(ctx, &s3.GetBucketPolicyStatusInput{Bucket: aws.String(t.Bucket)})
	if err != nil {
		if isAWSCode(err, "NoSuchBucketPolicy") {
			res.BucketPolicy = PolicyInfo{Present: false}
			return
		}
		res.Errors["bucketPolicy"] = friendlyErr(err)
		return
	}
	res.BucketPolicy.Present = true
	if st.PolicyStatus != nil {
		res.BucketPolicy.Public = aws.Bool(aws.ToBool(st.PolicyStatus.IsPublic))
	}
}

func inspectACL(ctx context.Context, client *s3.Client, t Target, res *InspectResult) {
	var grants []s3types.Grant
	if t.IsObject() {
		acl, err := client.GetObjectAcl(ctx, &s3.GetObjectAclInput{Bucket: aws.String(t.Bucket), Key: aws.String(t.Key)})
		if err != nil {
			res.Errors["objectAcl"] = friendlyErr(err)
			return
		}
		grants = acl.Grants
	} else {
		acl, err := client.GetBucketAcl(ctx, &s3.GetBucketAclInput{Bucket: aws.String(t.Bucket)})
		if err != nil {
			res.Errors["bucketAcl"] = friendlyErr(err)
			return
		}
		grants = acl.Grants
	}

	anonymousOperation := false
	for _, g := range grants {
		if g.Grantee == nil || g.Grantee.URI == nil {
			continue
		}
		switch aws.ToString(g.Grantee.URI) {
		case allUsersURI:
			res.ACL.AnonymousGrants = append(res.ACL.AnonymousGrants, string(g.Permission))
			if aclPermissionAllowsRead(g.Permission) {
				anonymousOperation = true
			}
		case authenticatedUsersURI:
			res.ACL.AuthenticatedAWSUsersGrants = append(res.ACL.AuthenticatedAWSUsersGrants, string(g.Permission))
		}
	}
	res.ACL.AllowsAnonymousOperation = aws.Bool(anonymousOperation)
}

// aclPermissionAllowsRead reports whether an ACL permission grants the read
// operation this tool checks (object download or bucket listing). READ_ACP and
// WRITE_ACP grant ACL access only and do not imply anonymous read, so they are
// recorded but do not set AllowsAnonymousOperation. For both objects and
// buckets, READ maps to the checked read operation.
func aclPermissionAllowsRead(p s3types.Permission) bool {
	return p == s3types.PermissionRead || p == s3types.PermissionFullControl
}

// isAWSCode reports whether err is an AWS API error with one of the given codes.
func isAWSCode(err error, codes ...string) bool {
	var apiErr smithy.APIError
	if !errors.As(err, &apiErr) {
		return false
	}
	for _, c := range codes {
		if apiErr.ErrorCode() == c {
			return true
		}
	}
	return false
}

// friendlyErr turns an AWS API error into a short, readable string.
func friendlyErr(err error) string {
	var apiErr smithy.APIError
	if errors.As(err, &apiErr) {
		return apiErr.ErrorCode()
	}
	return err.Error()
}
