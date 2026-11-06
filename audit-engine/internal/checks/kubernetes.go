package checks

import (
	"fmt"
	"strings"

	"github.com/cloudbusket/ai-auditor/audit-engine/internal/inventory"
	k8sinventory "github.com/cloudbusket/ai-auditor/audit-engine/internal/kubernetes"
)

func checkKubernetes(report *Report, inv *inventory.Inventory) {
	if inv == nil || inv.Kubernetes == nil {
		report.Add(Finding{
			ID:          "K8S001",
			Category:    "kubernetes",
			Asset:       "cluster",
			Status:      StatusPass,
			Severity:    "info",
			Message:     "Kubernetes inventory is unavailable; Kubernetes checks were skipped.",
			Description: "No Kubernetes inventory was provided to the checks engine.",
		})
		return
	}

	k8s := inv.Kubernetes

	if !k8s.Configured {
		report.Add(Finding{
			ID:          "K8S001",
			Category:    "kubernetes",
			Asset:       "cluster",
			Status:      StatusPass,
			Severity:    "info",
			Message:     "Kubernetes is not configured; Kubernetes checks were skipped.",
			Description: "No kubeconfig or in-cluster configuration was detected. This is informational because Kubernetes is optional.",
			Evidence: map[string]any{
				"configured": false,
				"connected":  false,
			},
		})
		return
	}

	if !k8s.Connected {
		report.Add(Finding{
			ID:             "K8S001",
			Category:       "kubernetes",
			Asset:          "cluster",
			Status:         StatusWarning,
			Severity:       "medium",
			Message:        "Kubernetes configuration was found, but the API server is unreachable.",
			Description:    "Kubernetes security checks could not run because the auditor could not connect to the configured cluster.",
			Recommendation: "Verify the kubeconfig context, network connectivity, API server availability, and auditor permissions.",
			Evidence: map[string]any{
				"configured": true,
				"connected":  false,
				"context":    k8s.Context,
				"error":      k8s.Error,
			},
		})
		return
	}

	report.Add(Finding{
		ID:          "K8S001",
		Category:    "kubernetes",
		Asset:       "cluster",
		Status:      StatusPass,
		Severity:    "info",
		Message:     "Kubernetes cluster connection is available.",
		Description: "The auditor connected to the configured Kubernetes API server.",
		Evidence: map[string]any{
			"configured":       true,
			"connected":        true,
			"context":          k8s.Context,
			"server_version":   k8s.ServerVersion,
			"platform_version": k8s.PlatformVersion,
		},
	})

	checkKubernetesCollection(report, k8s)
	checkKubernetesPods(report, k8s)
	checkKubernetesDeployments(report, k8s)
	checkKubernetesServices(report, k8s)
}

func checkKubernetesCollection(report *Report, k8s *k8sinventory.Inventory) {
	if len(k8s.CollectionErrors) == 0 {
		report.Add(Finding{
			ID:          "K8S002",
			Category:    "kubernetes",
			Asset:       "cluster inventory",
			Status:      StatusPass,
			Severity:    "info",
			Message:     "Kubernetes inventory collection completed without reported errors.",
			Description: "The configured Kubernetes collectors did not report collection errors.",
		})
		return
	}

	report.Add(Finding{
		ID:             "K8S002",
		Category:       "kubernetes",
		Asset:          "cluster inventory",
		Status:         StatusWarning,
		Severity:       "medium",
		Message:        fmt.Sprintf("Kubernetes inventory collection reported %d error(s).", len(k8s.CollectionErrors)),
		Description:    "Some Kubernetes resources may be missing from this assessment. Missing resources must not be interpreted as proof that no security issues exist.",
		Recommendation: "Review the collection errors and verify that the auditor's Kubernetes identity has the required read-only permissions.",
		Evidence: map[string]any{
			"collection_errors": k8s.CollectionErrors,
		},
	})
}

func checkKubernetesPods(report *Report, k8s *k8sinventory.Inventory) {
	failed := 0
	pending := 0
	highRestarts := 0

	for _, pod := range k8s.Pods {
		asset := pod.Namespace + "/" + pod.Name

		switch strings.ToLower(pod.Phase) {
		case "failed":
			failed++
			report.Add(Finding{
				ID:             "K8S003",
				Category:       "kubernetes",
				Asset:          asset,
				Status:         StatusCritical,
				Severity:       "high",
				Message:        fmt.Sprintf("Pod %s is in Failed phase.", asset),
				Description:    "The Kubernetes API reports this pod as failed.",
				Recommendation: "Inspect the pod with kubectl describe pod and review its events and container logs.",
				Evidence: map[string]any{
					"namespace":        pod.Namespace,
					"name":             pod.Name,
					"phase":            pod.Phase,
					"node":             pod.NodeName,
					"restart_count":    pod.RestartCount,
					"ready_containers": pod.ReadyContainers,
					"total_containers": pod.TotalContainers,
				},
			})

		case "pending":
			pending++
			report.Add(Finding{
				ID:             "K8S004",
				Category:       "kubernetes",
				Asset:          asset,
				Status:         StatusWarning,
				Severity:       "medium",
				Message:        fmt.Sprintf("Pod %s is still Pending.", asset),
				Description:    "The pod has not reached the Running or Succeeded phase.",
				Recommendation: "Inspect scheduling events, resource requests, node capacity, and volume attachment status.",
				Evidence: map[string]any{
					"namespace": pod.Namespace,
					"name":      pod.Name,
					"phase":     pod.Phase,
					"node":      pod.NodeName,
				},
			})
		}

		if pod.RestartCount >= 5 {
			highRestarts++
			report.Add(Finding{
				ID:             "K8S005",
				Category:       "kubernetes",
				Asset:          asset,
				Status:         StatusWarning,
				Severity:       "medium",
				Message:        fmt.Sprintf("Pod %s has restarted %d times.", asset, pod.RestartCount),
				Description:    "A high container restart count may indicate crashes, resource pressure, or application instability.",
				Recommendation: "Inspect container logs, previous container logs, pod events, and resource limits.",
				Evidence: map[string]any{
					"namespace":     pod.Namespace,
					"name":          pod.Name,
					"restart_count": pod.RestartCount,
				},
			})
		}
	}

	if failed == 0 && len(k8s.CollectionErrors) == 0 {
		report.Add(Finding{
			ID:       "K8S003",
			Category: "kubernetes",
			Asset:    "cluster pods",
			Status:   StatusPass,
			Severity: "info",
			Message:  "No failed pods were found in the collected inventory.",
			Evidence: map[string]any{
				"checked_pods": len(k8s.Pods),
				"failed_pods":  0,
			},
		})
	}

	if pending == 0 && len(k8s.CollectionErrors) == 0 {
		report.Add(Finding{
			ID:       "K8S004",
			Category: "kubernetes",
			Asset:    "cluster pods",
			Status:   StatusPass,
			Severity: "info",
			Message:  "No Pending pods were found in the collected inventory.",
			Evidence: map[string]any{
				"checked_pods": len(k8s.Pods),
				"pending_pods": 0,
			},
		})
	}

	if highRestarts == 0 && len(k8s.CollectionErrors) == 0 {
		report.Add(Finding{
			ID:       "K8S005",
			Category: "kubernetes",
			Asset:    "cluster pods",
			Status:   StatusPass,
			Severity: "info",
			Message:  "No pods with five or more restarts were found.",
			Evidence: map[string]any{
				"checked_pods":      len(k8s.Pods),
				"high_restart_pods": 0,
				"restart_threshold": 5,
			},
		})
	}
}

func checkKubernetesDeployments(report *Report, k8s *k8sinventory.Inventory) {
	underReplicated := 0

	for _, deployment := range k8s.Deployments {
		if deployment.ReadyReplicas >= deployment.Replicas {
			continue
		}

		underReplicated++
		asset := deployment.Namespace + "/" + deployment.Name

		report.Add(Finding{
			ID:       "K8S006",
			Category: "kubernetes",
			Asset:    asset,
			Status:   StatusWarning,
			Severity: "medium",
			Message: fmt.Sprintf(
				"Deployment %s has %d ready replicas out of %d desired replicas.",
				asset, deployment.ReadyReplicas, deployment.Replicas,
			),
			Description:    "The deployment currently has fewer ready replicas than its desired replica count.",
			Recommendation: "Inspect deployment events, pod readiness probes, scheduling constraints, and resource availability.",
			Evidence: map[string]any{
				"namespace":          deployment.Namespace,
				"name":               deployment.Name,
				"desired_replicas":   deployment.Replicas,
				"ready_replicas":     deployment.ReadyReplicas,
				"available_replicas": deployment.AvailableReplicas,
			},
		})
	}

	if underReplicated == 0 && len(k8s.CollectionErrors) == 0 {
		report.Add(Finding{
			ID:       "K8S006",
			Category: "kubernetes",
			Asset:    "cluster deployments",
			Status:   StatusPass,
			Severity: "info",
			Message:  "No under-replicated deployments were found in the collected inventory.",
			Evidence: map[string]any{
				"checked_deployments": len(k8s.Deployments),
				"under_replicated":    0,
			},
		})
	}
}

func checkKubernetesServices(report *Report, k8s *k8sinventory.Inventory) {
	exposed := 0

	for _, service := range k8s.Services {
		reasons := make([]string, 0)

		if strings.EqualFold(service.Type, "NodePort") {
			reasons = append(reasons, "NodePort")
		}
		if strings.EqualFold(service.Type, "LoadBalancer") {
			reasons = append(reasons, "LoadBalancer")
		}
		if len(service.ExternalIPs) > 0 {
			reasons = append(reasons, "ExternalIPs")
		}

		if len(reasons) == 0 {
			continue
		}

		exposed++
		asset := service.Namespace + "/" + service.Name

		report.Add(Finding{
			ID:             "K8S007",
			Category:       "kubernetes",
			Asset:          asset,
			Status:         StatusWarning,
			Severity:       "medium",
			Message:        fmt.Sprintf("Service %s has an externally reachable service configuration (%s).", asset, strings.Join(reasons, ", ")),
			Description:    "NodePort, LoadBalancer, or ExternalIP configurations may expose workloads outside the cluster. Confirm that this exposure is intentional and protected.",
			Recommendation: "Review the service's business requirement, allowed source ranges, cloud firewall rules, and authentication controls. Prefer internal services when external access is not required.",
			Evidence: map[string]any{
				"namespace":        service.Namespace,
				"name":             service.Name,
				"type":             service.Type,
				"cluster_ip":       service.ClusterIP,
				"external_ips":     service.ExternalIPs,
				"exposure_reasons": reasons,
				"ports":            service.Ports,
			},
		})
	}

	if exposed == 0 && len(k8s.CollectionErrors) == 0 {
		report.Add(Finding{
			ID:       "K8S007",
			Category: "kubernetes",
			Asset:    "cluster services",
			Status:   StatusPass,
			Severity: "info",
			Message:  "No NodePort, LoadBalancer, or ExternalIP services were found in the collected inventory.",
			Evidence: map[string]any{
				"checked_services": len(k8s.Services),
				"exposed_services": 0,
			},
		})
	}
}
