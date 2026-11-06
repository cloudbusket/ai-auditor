package kubernetes

import (
	"context"
	"fmt"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func CollectNamespaces(client *Client, inv *Inventory) error {
	if client == nil || client.Clientset == nil {
		return fmt.Errorf("Kubernetes client is not initialized")
	}
	if inv == nil {
		return fmt.Errorf("Kubernetes inventory is nil")
	}

	ctx, cancel := context.WithTimeout(context.Background(), requestTimeout)
	defer cancel()

	namespaces, err := client.Clientset.CoreV1().Namespaces().List(ctx, metav1.ListOptions{})
	if err != nil {
		return fmt.Errorf("unable to collect Kubernetes namespaces: %w", err)
	}

	inv.Namespaces = make([]Namespace, 0, len(namespaces.Items))

	for _, item := range namespaces.Items {
		inv.Namespaces = append(inv.Namespaces, Namespace{
			Name:   item.Name,
			Status: string(item.Status.Phase),
		})
	}

	inv.CollectedAt = time.Now().UTC()
	return nil
}
