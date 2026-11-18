package checks

import (
	"fmt"
	"strings"

	"github.com/cloudbusket/ai-auditor/audit-engine/internal/cloud"
)

// RunAWSChecks adds evidence-based AWS security findings.
func RunAWSChecks(report *Report, inv cloud.Inventory) {
	if report == nil || inv.Provider != cloud.ProviderAWS {
		return
	}

	if awsCoverageComplete(inv, "ec2_instances") {
		checkAWSPublicIPs(report, inv)
	}
}

// awsCoverageComplete ensures the inventory category was collected completely.
func awsCoverageComplete(inv cloud.Inventory, category string) bool {
	found := false

	for _, item := range inv.Coverage {
		if item.Provider != cloud.ProviderAWS ||
			item.Category != category {
			continue
		}

		found = true

		if item.Status != cloud.CoverageCompleted &&
			item.Status != cloud.CoverageNoData {
			return false
		}
	}

	return found
}

// checkAWSPublicIPs identifies EC2 instances assigned public IPv4 addresses.
// A public IP alone does not prove internet reachability.
func checkAWSPublicIPs(report *Report, inv cloud.Inventory) {
	for _, resource := range inv.Resources {
		if resource.Type != "aws.ec2.instance" {
			continue
		}

		publicIP, _ := resource.Properties["public_ip"].(string)
		publicIP = strings.TrimSpace(publicIP)

		if publicIP == "" {
			continue
		}

		instanceID := resource.ID
		if instanceID == "" {
			instanceID = resource.Name
		}

		report.Add(Finding{
			ID:       "AWS001",
			Source:   "aws",
			Category: "network_exposure",
			Asset:    instanceID,
			Status:   StatusWarning,
			Severity: "medium",
			Message: fmt.Sprintf(
				"EC2 instance %s has a public IPv4 address (%s)",
				instanceID,
				publicIP,
			),
			Description: "The instance is assigned a public IPv4 address. " +
				"This does not necessarily mean it is reachable from the internet; " +
				"reachability also depends on security groups, network ACLs, routes, " +
				"and host firewall rules.",
			Recommendation: "Review whether public access is required. " +
				"Where possible, use private subnets, a load balancer, " +
				"or controlled access through a bastion or VPN.",
			Evidence: map[string]any{
				"instance_id":       instanceID,
				"instance_name":     resource.Name,
				"public_ip":         publicIP,
				"instance_type":     resource.Properties["instance_type"],
				"state":             resource.Properties["state"],
				"vpc_id":            resource.Properties["vpc_id"],
				"subnet_id":         resource.Properties["subnet_id"],
				"security_groups":   resource.Properties["security_groups"],
				"availability_zone": resource.Properties["availability_zone"],
				"region":            resource.Region,
			},
		})
	}
}
