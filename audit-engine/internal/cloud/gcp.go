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

	resourceManagerURL    = "https://cloudresourcemanager.googleapis.com/v3"
	serviceUsageURL       = "https://serviceusage.googleapis.com/v1"
	computeAPIURL         = "https://compute.googleapis.com/compute/v1"
	iamAPIURL             = "https://iam.googleapis.com/v1"
	resourceManagerIAMURL = "https://cloudresourcemanager.googleapis.com/v3"
)

// GCPCollector discovers GCP project metadata and enabled services.
type GCPCollector struct {
	HTTPClient            *http.Client
	TokenSource           oauth2.TokenSource
	ResourceManagerURL    string
	ServiceUsageURL       string
	ComputeURL            string
	IAMResourceManagerURL string
	IAMURL                string
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
		TokenSource:           tokenSource,
		ResourceManagerURL:    resourceManagerURL,
		ServiceUsageURL:       serviceUsageURL,
		ComputeURL:            computeAPIURL,
		IAMResourceManagerURL: resourceManagerIAMURL,
		IAMURL:                iamAPIURL,
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

type gcpIAMPolicyRequest struct {
	OptionsRequestedPolicyVersion int `json:"optionsRequestedPolicyVersion"`
}

type gcpIAMPolicyResponse struct {
	Version  int    `json:"version"`
	Etag     string `json:"etag"`
	Bindings []struct {
		Role      string   `json:"role"`
		Members   []string `json:"members"`
		Condition *struct {
			Title       string `json:"title"`
			Description string `json:"description"`
			Expression  string `json:"expression"`
		} `json:"condition"`
	} `json:"bindings"`
}

type gcpServiceAccount struct {
	Name           string `json:"name"`
	ProjectID      string `json:"projectId"`
	UniqueID       string `json:"uniqueId"`
	Email          string `json:"email"`
	DisplayName    string `json:"displayName"`
	OAuth2ClientID string `json:"oauth2ClientId"`
	Disabled       bool   `json:"disabled"`
}

type gcpServiceAccountsResponse struct {
	Accounts      []gcpServiceAccount `json:"accounts"`
	NextPageToken string              `json:"nextPageToken"`
}

type gcpServiceAccountKey struct {
	Name            string `json:"name"`
	KeyType         string `json:"keyType"`
	KeyOrigin       string `json:"keyOrigin"`
	ValidAfterTime  string `json:"validAfterTime"`
	ValidBeforeTime string `json:"validBeforeTime"`
	Disabled        bool   `json:"disabled"`
	DisableReason   string `json:"disableReason"`
}

type gcpServiceAccountKeysResponse struct {
	Keys          []gcpServiceAccountKey `json:"keys"`
	NextPageToken string                 `json:"nextPageToken"`
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

	// Project IAM policy is collected independently of service discovery.
	iamStarted := time.Now().UTC()
	iamURL := strings.TrimRight(c.IAMResourceManagerURL, "/")
	if iamURL == "" {
		iamURL = resourceManagerIAMURL
	}

	iamErr := c.collectProjectIAMPolicy(
		ctx,
		client,
		iamURL,
		inv.ProjectID,
		&inv,
	)
	iamCompleted := time.Now().UTC()

	iamCount := countGCPResources(inv, "gcp.iam.binding")
	iamCoverage := Coverage{
		Provider:      ProviderGCP,
		Category:      "iam_policy",
		Status:        CoverageCompleted,
		ResourceCount: iamCount,
		StartedAt:     iamStarted,
		CompletedAt:   iamCompleted,
		DurationMs:    iamCompleted.Sub(iamStarted).Milliseconds(),
	}
	if iamErr != nil {
		iamCoverage.Status = classifyGCPError(iamErr)
		iamCoverage.Message = iamErr.Error()
	}
	inv.Coverage = append(inv.Coverage, iamCoverage)

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

	// Service-account discovery depends on the IAM API being enabled.
	iamAPIBaseURL := strings.TrimRight(c.IAMURL, "/")
	if iamAPIBaseURL == "" {
		iamAPIBaseURL = iamAPIURL
	}

	saStarted := time.Now().UTC()
	var saErr error
	var saCount int64

	if serviceErr != nil {
		saErr = fmt.Errorf(
			"service-account discovery skipped because enabled-service discovery was incomplete: %w",
			serviceErr,
		)
	} else if !gcpServiceEnabled(inv, "iam.googleapis.com") {
		saErr = &gcpRequestError{
			StatusCode: http.StatusNotFound,
			Message:    "IAM API is not enabled",
		}
	} else {
		saCount, saErr = c.collectServiceAccounts(
			ctx, client, iamAPIBaseURL, inv.ProjectID, &inv,
		)
	}

	saCompleted := time.Now().UTC()
	saCoverage := Coverage{
		Provider:      ProviderGCP,
		Category:      "iam_service_accounts",
		Status:        CoverageCompleted,
		ResourceCount: saCount,
		StartedAt:     saStarted,
		CompletedAt:   saCompleted,
		DurationMs:    saCompleted.Sub(saStarted).Milliseconds(),
	}

	if saErr != nil {
		saCoverage.Message = saErr.Error()
		if serviceErr != nil {
			saCoverage.Status = CoverageNotConfigured
		} else if !gcpServiceEnabled(inv, "iam.googleapis.com") {
			saCoverage.Status = CoverageAPIDisabled
		} else if saCount > 0 {
			saCoverage.Status = CoveragePartial
		} else {
			saCoverage.Status = classifyGCPError(saErr)
		}
	}

	inv.Coverage = append(inv.Coverage, saCoverage)

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

func (c *GCPCollector) collectServiceAccounts(
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
			"/serviceAccounts?pageSize=100"

		if pageToken != "" {
			endpoint += "&pageToken=" + url.QueryEscape(pageToken)
		}

		var response gcpServiceAccountsResponse
		if err := c.getJSON(ctx, client, endpoint, &response); err != nil {
			return count, fmt.Errorf("list GCP service accounts: %w", err)
		}

		for _, account := range response.Accounts {
			accountID := account.Name
			if accountID == "" {
				accountID = account.Email
			}

			inv.Resources = append(inv.Resources, Resource{
				ID:        accountID,
				Name:      account.Email,
				Type:      "gcp.iam.service_account",
				Provider:  ProviderGCP,
				ProjectID: projectID,
				Properties: map[string]any{
					"email":            account.Email,
					"unique_id":        account.UniqueID,
					"display_name":     account.DisplayName,
					"disabled":         account.Disabled,
					"oauth2_client_id": account.OAuth2ClientID,
				},
			})
			count++
		}

		pageToken = response.NextPageToken
		if pageToken == "" {
			return count, nil
		}
	}
}

func (c *GCPCollector) collectServiceAccountKeys(
	ctx context.Context,
	client *http.Client,
	baseURL string,
	projectID string,
	inv *Inventory,
) (int64, int64, error) {
	var keyCount int64
	var successfulAccounts int64
	var failures []string

	accounts := make([]Resource, 0)
	for _, resource := range inv.Resources {
		if resource.Type == "gcp.iam.service_account" {
			accounts = append(accounts, resource)
		}
	}

	for _, account := range accounts {
		accountEmail, _ := account.Properties["email"].(string)
		if accountEmail == "" {
			accountEmail = account.Name
		}
		if accountEmail == "" {
			failures = append(failures, "service account has no email or name")
			continue
		}

		pageToken := ""

		for {
			endpoint := strings.TrimRight(baseURL, "/") +
				"/projects/" + url.PathEscape(projectID) +
				"/serviceAccounts/" + url.PathEscape(accountEmail) +
				"/keys?keyTypes=USER_MANAGED&pageSize=100"

			if pageToken != "" {
				endpoint += "&pageToken=" + url.QueryEscape(pageToken)
			}

			var response gcpServiceAccountKeysResponse
			if err := c.getJSON(ctx, client, endpoint, &response); err != nil {
				failures = append(
					failures,
					fmt.Sprintf("list keys for %s: %v", accountEmail, err),
				)
				break
			}

			successfulAccounts++

			for _, key := range response.Keys {
				inv.Resources = append(inv.Resources, Resource{
					ID:        key.Name,
					Name:      key.Name,
					Type:      "gcp.iam.service_account_key",
					Provider:  ProviderGCP,
					ProjectID: projectID,
					Properties: map[string]any{
						"service_account_email": accountEmail,
						"key_type":              key.KeyType,
						"key_origin":            key.KeyOrigin,
						"valid_after_time":      key.ValidAfterTime,
						"valid_before_time":     key.ValidBeforeTime,
						"disabled":              key.Disabled,
						"disable_reason":        key.DisableReason,
					},
				})
				keyCount++
			}

			pageToken = response.NextPageToken
			if pageToken == "" {
				break
			}
		}
	}

	if len(failures) > 0 {
		return keyCount, successfulAccounts,
			fmt.Errorf("GCP service-account key discovery incomplete: %s",
				strings.Join(failures, "; "))
	}

	return keyCount, successfulAccounts, nil
}

func (c *GCPCollector) collectProjectIAMPolicy(
	ctx context.Context,
	client *http.Client,
	baseURL string,
	projectID string,
	inv *Inventory,
) error {
	endpoint := strings.TrimRight(baseURL, "/") +
		"/projects/" + url.PathEscape(projectID) + ":getIamPolicy"

	requestBody := gcpIAMPolicyRequest{
		OptionsRequestedPolicyVersion: 3,
	}

	var policy gcpIAMPolicyResponse
	if err := c.postJSON(ctx, client, endpoint, requestBody, &policy); err != nil {
		return fmt.Errorf("get GCP project IAM policy: %w", err)
	}

	for _, binding := range policy.Bindings {
		properties := map[string]any{
			"role":    binding.Role,
			"members": binding.Members,
		}
		if binding.Condition != nil {
			properties["condition"] = map[string]any{
				"title":       binding.Condition.Title,
				"description": binding.Condition.Description,
				"expression":  binding.Condition.Expression,
			}
		}

		inv.Resources = append(inv.Resources, Resource{
			ID:         projectID + "/" + binding.Role,
			Name:       binding.Role,
			Type:       "gcp.iam.binding",
			Provider:   ProviderGCP,
			ProjectID:  projectID,
			Properties: properties,
		})
	}

	return nil
}

func (c *GCPCollector) postJSON(
	ctx context.Context,
	client *http.Client,
	endpoint string,
	body any,
	destination any,
) error {
	token, err := c.TokenSource.Token()
	if err != nil {
		return fmt.Errorf("obtain GCP access token: %w", err)
	}

	payload, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("encode GCP request: %w", err)
	}

	req, err := http.NewRequestWithContext(
		ctx,
		http.MethodPost,
		endpoint,
		strings.NewReader(string(payload)),
	)
	if err != nil {
		return fmt.Errorf("create GCP request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+token.AccessToken)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")

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
