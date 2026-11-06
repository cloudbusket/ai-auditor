package checks

import (
	"testing"

	"github.com/cloudbusket/ai-auditor/audit-engine/internal/inventory"
	k8sinventory "github.com/cloudbusket/ai-auditor/audit-engine/internal/kubernetes"
)

func kubernetesTestInventory() *inventory.Inventory {
	return &inventory.Inventory{
		Kubernetes: &k8sinventory.Inventory{
			Configured: true,
			Connected:  true,
			Context:    "test-context",
		},
	}
}

func findKubernetesFinding(t *testing.T, r Report, id string) Finding {
	t.Helper()

	for _, finding := range r.Findings {
		if finding.ID == id {
			return finding
		}
	}

	t.Fatalf("finding %s not found", id)
	return Finding{}
}

func TestCheckKubernetesNotConfigured(t *testing.T) {
	r := NewReport()
	inv := kubernetesTestInventory()
	inv.Kubernetes.Configured = false
	inv.Kubernetes.Connected = false

	checkKubernetes(&r, inv)

	f := findKubernetesFinding(t, r, "K8S001")
	if f.Status != StatusPass {
		t.Errorf("expected pass for unconfigured Kubernetes, got %q", f.Status)
	}
	if f.Severity != "info" {
		t.Errorf("expected info severity, got %q", f.Severity)
	}
}

func TestCheckKubernetesAPIUnreachable(t *testing.T) {
	r := NewReport()
	inv := kubernetesTestInventory()
	inv.Kubernetes.Connected = false
	inv.Kubernetes.Error = "connection refused"

	checkKubernetes(&r, inv)

	f := findKubernetesFinding(t, r, "K8S001")
	if f.Status != StatusWarning {
		t.Errorf("expected warning for unreachable API, got %q", f.Status)
	}
	if f.Evidence["error"] != "connection refused" {
		t.Errorf("expected connection error evidence, got %v", f.Evidence["error"])
	}
}

func TestCheckKubernetesIncompleteInventory(t *testing.T) {
	r := NewReport()
	inv := kubernetesTestInventory()
	inv.Kubernetes.CollectionErrors = []string{
		"unable to list pods",
	}

	checkKubernetes(&r, inv)

	f := findKubernetesFinding(t, r, "K8S002")
	if f.Status != StatusWarning {
		t.Errorf("expected warning for incomplete inventory, got %q", f.Status)
	}
	if f.Evidence["collection_errors"] == nil {
		t.Error("expected collection errors in evidence")
	}
}

func TestCheckKubernetesFailedPod(t *testing.T) {
	r := NewReport()
	inv := kubernetesTestInventory()
	inv.Kubernetes.Pods = []k8sinventory.Pod{
		{
			Name:         "api",
			Namespace:    "production",
			Phase:        "Failed",
			RestartCount: 2,
		},
	}

	checkKubernetes(&r, inv)

	f := findKubernetesFinding(t, r, "K8S003")
	if f.Status != StatusCritical {
		t.Errorf("expected critical status for failed pod, got %q", f.Status)
	}
	if f.Asset != "production/api" {
		t.Errorf("unexpected asset: %q", f.Asset)
	}
}

func TestCheckKubernetesPendingPod(t *testing.T) {
	r := NewReport()
	inv := kubernetesTestInventory()
	inv.Kubernetes.Pods = []k8sinventory.Pod{
		{
			Name:      "worker",
			Namespace: "jobs",
			Phase:     "Pending",
		},
	}

	checkKubernetes(&r, inv)

	f := findKubernetesFinding(t, r, "K8S004")
	if f.Status != StatusWarning {
		t.Errorf("expected warning status for pending pod, got %q", f.Status)
	}
}

func TestCheckKubernetesHighRestartCount(t *testing.T) {
	r := NewReport()
	inv := kubernetesTestInventory()
	inv.Kubernetes.Pods = []k8sinventory.Pod{
		{
			Name:         "api",
			Namespace:    "production",
			Phase:        "Running",
			RestartCount: 5,
		},
	}

	checkKubernetes(&r, inv)

	f := findKubernetesFinding(t, r, "K8S005")
	if f.Status != StatusWarning {
		t.Errorf("expected warning status for high restart count, got %q", f.Status)
	}
	if f.Evidence["restart_count"] != int32(5) {
		t.Errorf("expected restart count 5, got %v", f.Evidence["restart_count"])
	}
}

func TestCheckKubernetesUnderReplicatedDeployment(t *testing.T) {
	r := NewReport()
	inv := kubernetesTestInventory()
	inv.Kubernetes.Deployments = []k8sinventory.Deployment{
		{
			Name:              "api",
			Namespace:         "production",
			Replicas:          3,
			ReadyReplicas:     2,
			AvailableReplicas: 2,
		},
	}

	checkKubernetes(&r, inv)

	f := findKubernetesFinding(t, r, "K8S006")
	if f.Status != StatusWarning {
		t.Errorf("expected warning status for under-replicated deployment, got %q", f.Status)
	}
	if f.Evidence["desired_replicas"] != int32(3) {
		t.Errorf("expected 3 desired replicas, got %v", f.Evidence["desired_replicas"])
	}
}

func TestCheckKubernetesExposedService(t *testing.T) {
	r := NewReport()
	inv := kubernetesTestInventory()
	inv.Kubernetes.Services = []k8sinventory.Service{
		{
			Name:        "public-api",
			Namespace:   "production",
			Type:        "LoadBalancer",
			ClusterIP:   "10.0.0.10",
			ExternalIPs: []string{"203.0.113.10"},
			Ports: []k8sinventory.ServicePort{
				{
					Protocol: "TCP",
					Port:     443,
				},
			},
		},
	}

	checkKubernetes(&r, inv)

	f := findKubernetesFinding(t, r, "K8S007")
	if f.Status != StatusWarning {
		t.Errorf("expected warning status for exposed service, got %q", f.Status)
	}
	if f.Asset != "production/public-api" {
		t.Errorf("unexpected asset: %q", f.Asset)
	}
}

func TestCheckKubernetesZeroDesiredReplicas(t *testing.T) {
	r := NewReport()
	inv := kubernetesTestInventory()
	inv.Kubernetes.Deployments = []k8sinventory.Deployment{
		{
			Name:          "scaled-down",
			Namespace:     "production",
			Replicas:      0,
			ReadyReplicas: 0,
		},
	}

	checkKubernetes(&r, inv)

	f := findKubernetesFinding(t, r, "K8S006")
	if f.Status != StatusPass {
		t.Errorf("expected pass for zero desired replicas, got %q", f.Status)
	}
}

func TestCheckKubernetesIncompleteInventoryDoesNotReportCleanResults(t *testing.T) {
	r := NewReport()
	inv := kubernetesTestInventory()
	inv.Kubernetes.CollectionErrors = []string{
		"unable to list pods",
	}

	checkKubernetes(&r, inv)

	collection := findKubernetesFinding(t, r, "K8S002")
	if collection.Status != StatusWarning {
		t.Errorf("expected K8S002 warning, got %q", collection.Status)
	}

	for _, finding := range r.Findings {
		switch finding.ID {
		case "K8S003", "K8S004", "K8S005", "K8S006", "K8S007":
			if finding.Status == StatusPass {
				t.Errorf(
					"%s should not report pass when inventory is incomplete",
					finding.ID,
				)
			}
		}
	}
}
