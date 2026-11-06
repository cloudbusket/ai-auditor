package kubernetes

import (
	"context"
	"fmt"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func CollectNodes(client *Client, inv *Inventory) error {
	if client == nil || client.Clientset == nil {
		return fmt.Errorf("Kubernetes client is not initialized")
	}
	if inv == nil {
		return fmt.Errorf("Kubernetes inventory is nil")
	}

	ctx, cancel := context.WithTimeout(context.Background(), requestTimeout)
	defer cancel()

	nodes, err := client.Clientset.CoreV1().Nodes().List(ctx, metav1.ListOptions{})
	if err != nil {
		return fmt.Errorf("unable to collect Kubernetes nodes: %w", err)
	}

	inv.Nodes = make([]Node, 0, len(nodes.Items))

	for _, item := range nodes.Items {
		ready := false
		status := "Unknown"

		for _, condition := range item.Status.Conditions {
			if condition.Type == corev1.NodeReady {
				ready = condition.Status == corev1.ConditionTrue
				if ready {
					status = "Ready"
				} else {
					status = "NotReady"
				}
				break
			}
		}

		inv.Nodes = append(inv.Nodes, Node{
			Name:            item.Name,
			Status:          status,
			KubeletVersion:  item.Status.NodeInfo.KubeletVersion,
			OperatingSystem: item.Status.NodeInfo.OperatingSystem,
			Architecture:    item.Status.NodeInfo.Architecture,
			Ready:           ready,
			Unschedulable:   item.Spec.Unschedulable,
		})
	}

	inv.CollectedAt = time.Now().UTC()
	return nil
}
