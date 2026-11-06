package inventory

import (
	"github.com/cloudbusket/ai-auditor/audit-engine/internal/docker"
	k8sinventory "github.com/cloudbusket/ai-auditor/audit-engine/internal/kubernetes"
)

func Collect() (*Inventory, error) {
	inv := &Inventory{}

	collectors := []func(*Inventory) error{
		collectHostname,
		collectCloud,
		collectOS,
		collectKernel,
		collectCPU,
		collectMemory,
		collectDisk,
		collectNetwork,
		collectListeningPorts,
		collectServices,
		collectVirtualization,
	}

	for _, c := range collectors {
		if err := c(inv); err != nil {
			return nil, err
		}
	}

	// Docker is optional.
	if d, err := docker.Collect(); err == nil {
		inv.Docker = d
	}

	// Kubernetes is optional. An absent configuration or unreachable
	// cluster must not prevent the host audit from completing.
	client, k8sInv, err := k8sinventory.NewClient()

	if k8sInv != nil {
		inv.Kubernetes = k8sInv
	}

	if err != nil {
		if inv.Kubernetes == nil {
			inv.Kubernetes = &k8sinventory.Inventory{}
		}
		inv.Kubernetes.CollectionErrors = append(
			inv.Kubernetes.CollectionErrors,
			err.Error(),
		)
	}

	if client != nil && inv.Kubernetes != nil && inv.Kubernetes.Connected {
		k8sCollectors := []func(*k8sinventory.Client, *k8sinventory.Inventory) error{
			k8sinventory.CollectNodes,
			k8sinventory.CollectNamespaces,
			k8sinventory.CollectPods,
			k8sinventory.CollectDeployments,
			k8sinventory.CollectServices,
			k8sinventory.CollectStorage,
		}

		for _, collect := range k8sCollectors {
			if err := collect(client, inv.Kubernetes); err != nil {
				inv.Kubernetes.CollectionErrors = append(
					inv.Kubernetes.CollectionErrors,
					err.Error(),
				)
			}
		}
	}

	return inv, nil
}
