package cloud

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/aws/smithy-go"
)

// AWSSTSAPI defines the STS operations required by the AWS collector.
type AWSSTSAPI interface {
	GetCallerIdentity(
		ctx context.Context,
		params *sts.GetCallerIdentityInput,
		optFns ...func(*sts.Options),
	) (*sts.GetCallerIdentityOutput, error)
}

// AWSEC2API defines the EC2 operations required by the AWS collector.
type AWSEC2API interface {
	DescribeInstances(
		ctx context.Context,
		params *ec2.DescribeInstancesInput,
		optFns ...func(*ec2.Options),
	) (*ec2.DescribeInstancesOutput, error)
}

// AWSCollector discovers AWS account and EC2 resources.
type AWSCollector struct {
	STSClient AWSSTSAPI
	EC2Client AWSEC2API
	Region    string
}

// NewAWSCollector creates an AWS collector using the default credential chain.
func NewAWSCollector(
	ctx context.Context,
	region string,
) (*AWSCollector, error) {
	region = strings.TrimSpace(region)

	cfg, err := awsconfig.LoadDefaultConfig(ctx)
	if err != nil {
		return nil, fmt.Errorf("load AWS configuration: %w", err)
	}

	if region != "" {
		cfg.Region = region
	}

	if cfg.Region == "" {
		return nil, fmt.Errorf(
			"AWS region is required; configure AWS_REGION or provide a region",
		)
	}

	return &AWSCollector{
		STSClient: sts.NewFromConfig(cfg),
		EC2Client: ec2.NewFromConfig(cfg),
		Region:    cfg.Region,
	}, nil
}

// Discover collects AWS account identity and EC2 instance inventory.
func (c *AWSCollector) Discover(
	ctx context.Context,
	config Config,
) (Inventory, error) {
	inv := Inventory{
		Provider:  ProviderAWS,
		Resources: []Resource{},
		Coverage:  []Coverage{},
	}

	if c == nil || c.STSClient == nil || c.EC2Client == nil {
		return inv, fmt.Errorf("AWS collector clients are not configured")
	}

	region := strings.TrimSpace(c.Region)
	if region == "" {
		return inv, fmt.Errorf("AWS region is not configured")
	}

	if config.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, config.Timeout)
		defer cancel()
	}

	identity, err := c.STSClient.GetCallerIdentity(
		ctx,
		&sts.GetCallerIdentityInput{},
	)
	if err != nil {
		return inv, fmt.Errorf("get AWS account identity: %w", err)
	}

	if identity.Account != nil {
		inv.AccountID = *identity.Account
	}

	started := time.Now().UTC()

	var nextToken *string

	for {
		output, err := c.EC2Client.DescribeInstances(
			ctx,
			&ec2.DescribeInstancesInput{
				NextToken: nextToken,
			},
		)
		if err != nil {
			completed := time.Now().UTC()

			coverage := Coverage{
				Provider:      ProviderAWS,
				Category:      "ec2_instances",
				Status:        classifyAWSError(err),
				ResourceCount: int64(len(inv.Resources)),
				Message:       err.Error(),
				StartedAt:     started,
				CompletedAt:   completed,
				DurationMs:    completed.Sub(started).Milliseconds(),
			}
			inv.Coverage = append(inv.Coverage, coverage)

			return inv, fmt.Errorf("describe AWS EC2 instances: %w", err)
		}

		for _, reservation := range output.Reservations {
			for _, instance := range reservation.Instances {
				resource := awsInstanceResource(instance, region)
				inv.Resources = append(inv.Resources, resource)
			}
		}

		nextToken = output.NextToken
		if nextToken == nil || strings.TrimSpace(*nextToken) == "" {
			break
		}
	}

	completed := time.Now().UTC()

	status := CoverageCompleted
	if len(inv.Resources) == 0 {
		status = CoverageNoData
	}

	inv.Coverage = append(inv.Coverage, Coverage{
		Provider:      ProviderAWS,
		Category:      "ec2_instances",
		Status:        status,
		ResourceCount: int64(len(inv.Resources)),
		StartedAt:     started,
		CompletedAt:   completed,
		DurationMs:    completed.Sub(started).Milliseconds(),
	})

	return inv, nil
}

// awsInstanceResource converts an AWS EC2 instance into a normalized resource.
func awsInstanceResource(
	instance types.Instance,
	region string,
) Resource {
	id := aws.ToString(instance.InstanceId)

	name := ""
	labels := make(map[string]string)

	for _, tag := range instance.Tags {
		key := aws.ToString(tag.Key)
		value := aws.ToString(tag.Value)

		if key == "" {
			continue
		}

		labels[key] = value

		if key == "Name" {
			name = value
		}
	}

	securityGroups := make([]map[string]string, 0, len(instance.SecurityGroups))

	for _, group := range instance.SecurityGroups {
		securityGroups = append(securityGroups, map[string]string{
			"id":   aws.ToString(group.GroupId),
			"name": aws.ToString(group.GroupName),
		})
	}

	state := ""
	if instance.State != nil {
		state = string(instance.State.Name)
	}

	launchTime := ""
	if instance.LaunchTime != nil {
		launchTime = instance.LaunchTime.UTC().Format(time.RFC3339)
	}

	zone := ""
	if instance.Placement != nil {
		zone = aws.ToString(instance.Placement.AvailabilityZone)
	}

	properties := map[string]any{
		"instance_id":       id,
		"instance_type":     string(instance.InstanceType),
		"state":             state,
		"private_ip":        aws.ToString(instance.PrivateIpAddress),
		"public_ip":         aws.ToString(instance.PublicIpAddress),
		"vpc_id":            aws.ToString(instance.VpcId),
		"subnet_id":         aws.ToString(instance.SubnetId),
		"availability_zone": zone,
		"launch_time":       launchTime,
		"security_groups":   securityGroups,
	}

	return Resource{
		ID:         id,
		Name:       name,
		Type:       "aws.ec2.instance",
		Provider:   ProviderAWS,
		Region:     region,
		Zone:       zone,
		Labels:     labels,
		Properties: properties,
	}
}

// classifyAWSError converts AWS API errors into inventory coverage statuses.
func classifyAWSError(err error) CoverageStatus {
	if err == nil {
		return CoverageCompleted
	}

	var apiError smithy.APIError
	if !errors.As(err, &apiError) {
		return CoverageError
	}

	switch apiError.ErrorCode() {
	case "UnauthorizedOperation", "AccessDenied", "AccessDeniedException":
		return CoveragePermissionDenied

	case "AuthFailure", "ExpiredToken", "ExpiredTokenException":
		return CoverageNotConfigured

	case "OptInRequired", "UnsupportedOperation":
		return CoverageUnsupported

	default:
		return CoverageError
	}
}
