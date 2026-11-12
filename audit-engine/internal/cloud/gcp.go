package cloud

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

const (
	gcpReadOnlyScope = "https://www.googleapis.com/auth/cloud-platform.read-only"

	resourceManagerURL = "https://cloudresourcemanager.googleapis.com/v3"
	serviceUsageURL    = "https://serviceusage.googleapis.com/v1"
	computeAPIURL      = "https://compute.googleapis.com/compute/v1"
)

// GCPCollector discovers GCP project metadata and enabled services.
type GCPCollector struct {
	HTTPClient         *http.Client
	TokenSource        oauth2.TokenSource
	ResourceManagerURL string
	ServiceUsageURL    string
	ComputeURL         string
}

// NewGCPCollector creates a collector using Application Default Credentials.
func NewGCPCollector(ctx context.Context) (*GCPCollector, error) {
	tokenSource, err := google.DefaultTokenSource(ctx, gcpReadOnlyScope)
	if err != nil {
		return nil, fmt.Errorf("initialize GCP application credentials: %w", err)
	}

	return &GCPCollector{
		HTTPClient: &http.Client{
			Timeout: 30 * time.Second,
		},
		TokenSource:        tokenSource,
		ResourceManagerURL: resourceManagerURL,
		ServiceUsageURL:    serviceUsageURL,
		ComputeURL:         computeAPIURL,
	}, nil
}

type gcpProjectResponse struct {
	Name       string            `json:"name"`
	ProjectID  string            `json:"projectId"`
	State      string            `json:"state"`
	Parent     string            `json:"parent"`
	CreateTime string            `json:"createTime"`
	Labels     map[string]string `json:"labels"`
}

type gcpServiceResponse struct {
	Name  string `json:"name"`
	State string `json:"state"`
}

type gcpServicesResponse struct {
	Services      []gcpServiceResponse `json:"services"`
	NextPageToken string               `json:"nextPageToken"`
}

type gcpAPIError struct {
	Error struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
		Status  string `json:"status"`
		Errors  []struct {
			Reason string `json:"reason"`
		} `json:"errors"`
	} `json:"error"`
}

func (c *GCPCollector) Discover(
	ctx context.Context,
	config Config,
) (Inventory, error) {
	inv := Inventory{
		Provider:  ProviderGCP,
		ProjectID: strings.TrimSpace(config.ProjectID),
		Resources: []Resource{},
		Coverage:  []Coverage{},
	}

	if inv.ProjectID == "" {
		return inv, fmt.Errorf("GCP project ID is required")
	}

	if c == nil || c.TokenSource == nil {
		return inv, fmt.Errorf("GCP credentials are not configured")
	}

	client := c.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}

	if config.Timeout > 0 {
		// Copy the client so the caller's original configuration is preserved.
		clientCopy := *client
		clientCopy.Timeout = config.Timeout
		client = &clientCopy
	}

	rmURL := strings.TrimRight(c.ResourceManagerURL, "/")
	if rmURL == "" {
		rmURL = resourceManagerURL
	}

	suURL := strings.TrimRight(c.ServiceUsageURL, "/")
	if suURL == "" {
		suURL = serviceUsageURL
	}

	projectStarted := time.Now().UTC()

	var project gcpProjectResponse
	projectErr := c.getJSON(
		ctx,
		client,
		rmURL+"/projects/"+url.PathEscape(inv.ProjectID),
		&project,
	)

	projectCompleted := time.Now().UTC()

	projectCoverage := Coverage{
		Provider:      ProviderGCP,
		Category:      "project_metadata",
		Status:        CoverageCompleted,
		ResourceCount: 1,
		StartedAt:     projectStarted,
		CompletedAt:   projectCompleted,
		DurationMs:    projectCompleted.Sub(projectStarted).Milliseconds(),
	}

	if projectErr != nil {
		projectCoverage.Status = classifyGCPError(projectErr)
		projectCoverage.ResourceCount = 0
		projectCoverage.Message = projectErr.Error()
		inv.Coverage = append(inv.Coverage, projectCoverage)

		return inv, fmt.Errorf("collect GCP project metadata: %w", projectErr)
	}

	projectID := project.ProjectID
	if projectID == "" {
		projectID = inv.ProjectID
	}
	inv.ProjectID = projectID

	projectNumber := strings.TrimPrefix(project.Name, "projects/")
	inv.AccountID = projectNumber

	inv.Resources = append(inv.Resources, Resource{
		ID:        project.Name,
		Name:      projectID,
		Type:      "gcp.project",
		Provider:  ProviderGCP,
		ProjectID: projectID,
		Labels:    project.Labels,
		Properties: map[string]any{
			"project_number": projectNumber,
			"state":          project.State,
			"parent":         project.Parent,
			"create_time":    project.CreateTime,
		},
	})

	inv.Coverage = append(inv.Coverage, projectCoverage)

	servicesStarted := time.Now().UTC()

	serviceErr := c.collectEnabledServices(
		ctx,
		client,
		suURL,
		&inv,
	)

	servicesCompleted := time.Now().UTC()

	serviceCount := countGCPResources(inv, "gcp.service")

	serviceCoverage := Coverage{
		Provider:      ProviderGCP,
		Category:      "enabled_services",
		Status:        CoverageCompleted,
		ResourceCount: serviceCount,
		StartedAt:     servicesStarted,
		CompletedAt:   servicesCompleted,
		DurationMs:    servicesCompleted.Sub(servicesStarted).Milliseconds(),
	}

	if serviceErr != nil {
		serviceCoverage.ResourceCount = serviceCount
		serviceCoverage.Message = serviceErr.Error()

		if serviceCount > 0 {
			serviceCoverage.Status = CoveragePartial
		} else {
			serviceCoverage.Status = classifyGCPError(serviceErr)
		}
	}

	inv.Coverage = append(inv.Coverage, serviceCoverage)

	// Compute discovery depends on knowing whether its API is enabled.
	computeURL := strings.TrimRight(c.ComputeURL, "/")
	if computeURL == "" {
		computeURL = computeAPIURL
	}

	if serviceErr != nil {
		message := "Compute discovery skipped because enabled-service discovery was incomplete: " +
			serviceErr.Error()

		for _, category := range []string{"compute_instances", "compute_disks"} {
			now := time.Now().UTC()
			inv.Coverage = append(inv.Coverage, Coverage{
				Provider:    ProviderGCP,
				Category:    category,
				Status:      CoverageNotConfigured,
				Message:     message,
				StartedAt:   now,
				CompletedAt: now,
			})
		}
	} else if !gcpServiceEnabled(inv, "compute.googleapis.com") {
		for _, category := range []string{"compute_instances", "compute_disks"} {
			now := time.Now().UTC()
			inv.Coverage = append(inv.Coverage, Coverage{
				Provider:    ProviderGCP,
				Category:    category,
				Status:      CoverageAPIDisabled,
				Message:     "Compute Engine API is not enabled; collection was skipped.",
				StartedAt:   now,
				CompletedAt: now,
			})
		}
	} else {
		instancesStarted := time.Now().UTC()
		instanceCount, instanceErr := c.collectComputeInstances(
			ctx, client, computeURL, inv.ProjectID, &inv,
		)
		instancesCompleted := time.Now().UTC()
		inv.Coverage = append(inv.Coverage, makeComputeCoverage(
			"compute_instances",
			instanceCount,
			instanceErr,
			instancesStarted,
			instancesCompleted,
		))

		disksStarted := time.Now().UTC()
		diskCount, diskErr := c.collectComputeDisks(
			ctx, client, computeURL, inv.ProjectID, &inv,
		)
		disksCompleted := time.Now().UTC()
		inv.Coverage = append(inv.Coverage, makeComputeCoverage(
			"compute_disks",
			diskCount,
			diskErr,
			disksStarted,
			disksCompleted,
		))
	}

	// Coverage gaps do not discard successfully collected inventory.
	return inv, nil
}

func (c *GCPCollector) collectEnabledServices(
	ctx context.Context,
	client *http.Client,
	baseURL string,
	inv *Inventory,
) error {
	pageToken := ""

	for {
		endpoint := baseURL +
			"/projects/" + url.PathEscape(inv.ProjectID) +
			"/services?filter=state%3AENABLED&pageSize=200"

		if pageToken != "" {
			endpoint += "&pageToken=" + url.QueryEscape(pageToken)
		}

		var response gcpServicesResponse

		if err := c.getJSON(ctx, client, endpoint, &response); err != nil {
			return fmt.Errorf("list enabled GCP services: %w", err)
		}

		for _, service := range response.Services {
			inv.Resources = append(inv.Resources, Resource{
				ID:        service.Name,
				Name:      service.Name,
				Type:      "gcp.service",
				Provider:  ProviderGCP,
				ProjectID: inv.ProjectID,
				Properties: map[string]any{
					"state": service.State,
				},
			})
		}

		pageToken = response.NextPageToken
		if pageToken == "" {
			return nil
		}
	}
}

func (c *GCPCollector) getJSON(
	ctx context.Context,
	client *http.Client,
	endpoint string,
	destination any,
) error {
	token, err := c.TokenSource.Token()
	if err != nil {
		return fmt.Errorf("obtain GCP access token: %w", err)
	}

	req, err := http.NewRequestWithContext(
		ctx,
		http.MethodGet,
		endpoint,
		nil,
	)
	if err != nil {
		return fmt.Errorf("create GCP request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+token.AccessToken)
	req.Header.Set("Accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("GCP API request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		var apiErr gcpAPIError

		if err := json.NewDecoder(resp.Body).Decode(&apiErr); err == nil {
			message := apiErr.Error.Message
			if message == "" {
				message = resp.Status
			}

			reason := ""
			if len(apiErr.Error.Errors) > 0 {
				reason = apiErr.Error.Errors[0].Reason
			}

			return &gcpRequestError{
				StatusCode: resp.StatusCode,
				Reason:     reason,
				Message:    message,
			}
		}

		return &gcpRequestError{
			StatusCode: resp.StatusCode,
			Message:    resp.Status,
		}
	}

	if err := json.NewDecoder(resp.Body).Decode(destination); err != nil {
		return fmt.Errorf("decode GCP API response: %w", err)
	}

	return nil
}

type gcpRequestError struct {
	StatusCode int
	Reason     string
	Message    string
}

func (e *gcpRequestError) Error() string {
	return fmt.Sprintf(
		"GCP API returned HTTP %d: %s",
		e.StatusCode,
		e.Message,
	)
}

func classifyGCPError(err error) CoverageStatus {
	var apiErr *gcpRequestError

	if !errors.As(err, &apiErr) {
		return CoverageError
	}

	switch {
	case apiErr.Reason == "SERVICE_DISABLED",
		apiErr.Reason == "accessNotConfigured":
		return CoverageAPIDisabled

	case apiErr.StatusCode == http.StatusForbidden:
		return CoveragePermissionDenied

	case apiErr.StatusCode == http.StatusNotFound:
		return CoverageNoData

	default:
		return CoverageError
	}
}

// Keep this helper available for callers that need to inspect GCP API errors.
func asGCPRequestError(err error, target **gcpRequestError) bool {
	return errors.As(err, target)
}

// Keep project number parsing explicit and reject malformed resource names.
func parseGCPProjectNumber(name string) (string, error) {
	const prefix = "projects/"

	if !strings.HasPrefix(name, prefix) {
		return "", fmt.Errorf("unexpected GCP project resource name %q", name)
	}

	number := strings.TrimPrefix(name, prefix)
	if number == "" {
		return "", fmt.Errorf("GCP project number is missing from %q", name)
	}

	if _, err := strconv.ParseUint(number, 10, 64); err != nil {
		return "", fmt.Errorf("invalid GCP project number %q: %w", number, err)
	}

	return number, nil
}

func countGCPResources(inv Inventory, resourceType string) int64 {
	var count int64
	for _, resource := range inv.Resources {
		if resource.Type == resourceType {
			count++
		}
	}
	return count
}

func gcpServiceEnabled(inv Inventory, serviceName string) bool {
	for _, resource := range inv.Resources {
		if resource.Type != "gcp.service" {
			continue
		}

		name := strings.TrimSpace(resource.Name)
		if name == serviceName ||
			strings.HasSuffix(name, "/services/"+serviceName) {
			return true
		}
	}
	return false
}
