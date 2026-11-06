package kubernetes

import (
	"context"
	"fmt"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func CollectPods(client *Client, inv *Inventory) error {
	if client == nil || client.Clientset == nil {
		return fmt.Errorf("Kubernetes client is not initialized")
	}
	if inv == nil {
		return fmt.Errorf("Kubernetes inventory is nil")
	}

	ctx, cancel := context.WithTimeout(context.Background(), requestTimeout)
	defer cancel()

	pods, err := client.Clientset.CoreV1().Pods("").List(ctx, metav1.ListOptions{})
	if err != nil {
		return fmt.Errorf("unable to collect Kubernetes pods: %w", err)
	}

	inv.Pods = make([]Pod, 0, len(pods.Items))

	for _, item := range pods.Items {
		pod := Pod{
			Name:            item.Name,
			Namespace:       item.Namespace,
			Phase:           string(item.Status.Phase),
			NodeName:        item.Spec.NodeName,
			TotalContainers: int32(len(item.Spec.Containers)),
		}

		for _, status := range item.Status.ContainerStatuses {
			if status.Ready {
				pod.ReadyContainers++
			}
			pod.RestartCount += status.RestartCount
		}

		inv.Pods = append(inv.Pods, pod)
	}

	inv.CollectedAt = time.Now().UTC()
	return nil
}
