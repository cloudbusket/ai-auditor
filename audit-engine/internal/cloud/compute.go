package cloud

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type gcpAggregatedInstancesResponse struct {
	Items map[string]struct {
		Instances []gcpInstance `json:"instances"`
	} `json:"items"`
	NextPageToken string `json:"nextPageToken"`
}

type gcpInstance struct {
	ID                string                `json:"id"`
	Name              string                `json:"name"`
	SelfLink          string                `json:"selfLink"`
	MachineType       string                `json:"machineType"`
	Zone              string                `json:"zone"`
	Status            string                `json:"status"`
	Labels            map[string]string     `json:"labels"`
	NetworkInterfaces []gcpNetworkInterface `json:"networkInterfaces"`
	CreationTimestamp string                `json:"creationTimestamp"`
}

type gcpNetworkInterface struct {
	Name          string `json:"name"`
	NetworkIP     string `json:"networkIP"`
	AccessConfigs []struct {
		NatIP string `json:"natIP"`
	} `json:"accessConfigs"`
}

type gcpAggregatedDisksResponse struct {
	Items map[string]struct {
		Disks []gcpDisk `json:"disks"`
	} `json:"items"`
	NextPageToken string `json:"nextPageToken"`
}

type gcpDisk struct {
	ID                string            `json:"id"`
	Name              string            `json:"name"`
	SelfLink          string            `json:"selfLink"`
	Zone              string            `json:"zone"`
	Region            string            `json:"region"`
	SizeGb            string            `json:"sizeGb"`
	Type              string            `json:"type"`
	Status            string            `json:"status"`
	Users             []string          `json:"users"`
	Labels            map[string]string `json:"labels"`
	CreationTimestamp string            `json:"creationTimestamp"`
}

func (c *GCPCollector) collectComputeInstances(
	ctx context.Context,
	client *http.Client,
	baseURL string,
	projectID string,
	inv *Inventory,
) (int64, error) {
	var count int64
	pageToken := ""

	for {
		endpoint := strings.TrimRight(baseURL, "/") +
			"/projects/" + url.PathEscape(projectID) +
			"/aggregated/instances?maxResults=500"

		if pageToken != "" {
			endpoint += "&pageToken=" + url.QueryEscape(pageToken)
		}

		var response gcpAggregatedInstancesResponse
		if err := c.getJSON(ctx, client, endpoint, &response); err != nil {
			return count, fmt.Errorf("list Compute Engine instances: %w", err)
		}

		for scope, scoped := range response.Items {
			for _, instance := range scoped.Instances {
				zone := resourceNameFromURL(instance.Zone)
				if zone == "" {
					zone = resourceNameFromURL(scope)
				}

				region := regionFromZone(zone)

				networkInterfaces := make([]map[string]any, 0, len(instance.NetworkInterfaces))
				for _, nic := range instance.NetworkInterfaces {
					externalIPs := make([]string, 0, len(nic.AccessConfigs))
					for _, access := range nic.AccessConfigs {
						if access.NatIP != "" {
							externalIPs = append(externalIPs, access.NatIP)
						}
					}

					networkInterfaces = append(networkInterfaces, map[string]any{
						"name":         nic.Name,
						"internal_ip":  nic.NetworkIP,
						"external_ips": externalIPs,
					})
				}

				resourceID := instance.SelfLink
				if resourceID == "" {
					resourceID = fmt.Sprintf(
						"projects/%s/zones/%s/instances/%s",
						projectID, zone, instance.Name,
					)
				}

				inv.Resources = append(inv.Resources, Resource{
					ID:        resourceID,
					Name:      instance.Name,
					Type:      "gcp.compute.instance",
					Provider:  ProviderGCP,
					ProjectID: projectID,
					Region:    region,
					Zone:      zone,
					Labels:    instance.Labels,
					Properties: map[string]any{
						"instance_id":        instance.ID,
						"machine_type":       resourceNameFromURL(instance.MachineType),
						"machine_type_uri":   instance.MachineType,
						"status":             instance.Status,
						"creation_timestamp": instance.CreationTimestamp,
						"network_interfaces": networkInterfaces,
					},
				})
				count++
			}
		}

		pageToken = response.NextPageToken
		if pageToken == "" {
			return count, nil
		}
	}
}

func (c *GCPCollector) collectComputeDisks(
	ctx context.Context,
	client *http.Client,
	baseURL string,
	projectID string,
	inv *Inventory,
) (int64, error) {
	var count int64
	pageToken := ""

	for {
		endpoint := strings.TrimRight(baseURL, "/") +
			"/projects/" + url.PathEscape(projectID) +
			"/aggregated/disks?maxResults=500"

		if pageToken != "" {
			endpoint += "&pageToken=" + url.QueryEscape(pageToken)
		}

		var response gcpAggregatedDisksResponse
		if err := c.getJSON(ctx, client, endpoint, &response); err != nil {
			return count, fmt.Errorf("list Compute Engine disks: %w", err)
		}

		for scope, scoped := range response.Items {
			for _, disk := range scoped.Disks {
				zone := resourceNameFromURL(disk.Zone)
				if zone == "" && strings.HasPrefix(scope, "zones/") {
					zone = resourceNameFromURL(scope)
				}

				region := regionFromZone(zone)
				if disk.Region != "" {
					region = resourceNameFromURL(disk.Region)
				}

				resourceID := disk.SelfLink
				if resourceID == "" {
					if zone != "" {
						resourceID = fmt.Sprintf(
							"projects/%s/zones/%s/disks/%s",
							projectID, zone, disk.Name,
						)
					} else {
						resourceID = fmt.Sprintf(
							"projects/%s/disks/%s",
							projectID, disk.Name,
						)
					}
				}

				inv.Resources = append(inv.Resources, Resource{
					ID:        resourceID,
					Name:      disk.Name,
					Type:      "gcp.compute.disk",
					Provider:  ProviderGCP,
					ProjectID: projectID,
					Region:    region,
					Zone:      zone,
					Labels:    disk.Labels,
					Properties: map[string]any{
						"disk_id":            disk.ID,
						"size_gb":            disk.SizeGb,
						"disk_type":          resourceNameFromURL(disk.Type),
						"disk_type_uri":      disk.Type,
						"status":             disk.Status,
						"attached_to":        disk.Users,
						"attached_vm_count":  len(disk.Users),
						"creation_timestamp": disk.CreationTimestamp,
					},
				})
				count++
			}
		}

		pageToken = response.NextPageToken
		if pageToken == "" {
			return count, nil
		}
	}
}

func resourceNameFromURL(value string) string {
	value = strings.TrimRight(value, "/")
	if value == "" {
		return ""
	}

	if index := strings.LastIndex(value, "/"); index >= 0 {
		return value[index+1:]
	}

	return value
}

func regionFromZone(zone string) string {
	zone = resourceNameFromURL(zone)
	if zone == "" {
		return ""
	}

	index := strings.LastIndex(zone, "-")
	if index <= 0 {
		return ""
	}

	return zone[:index]
}

func makeComputeCoverage(
	category string,
	count int64,
	err error,
	started time.Time,
	completed time.Time,
) Coverage {
	coverage := Coverage{
		Provider:      ProviderGCP,
		Category:      category,
		Status:        CoverageCompleted,
		ResourceCount: count,
		StartedAt:     started,
		CompletedAt:   completed,
		DurationMs:    completed.Sub(started).Milliseconds(),
	}

	if err != nil {
		coverage.Message = err.Error()
		if count > 0 {
			coverage.Status = CoveragePartial
		} else {
			coverage.Status = classifyGCPError(err)
		}
	} else if count == 0 {
		coverage.Status = CoverageNoData
	}

	return coverage
}
