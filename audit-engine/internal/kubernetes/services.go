package kubernetes

import (
	"context"
	"fmt"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func CollectServices(client *Client, inv *Inventory) error {
	if client == nil || client.Clientset == nil {
		return fmt.Errorf("Kubernetes client is not initialized")
	}
	if inv == nil {
		return fmt.Errorf("Kubernetes inventory is nil")
	}

	ctx, cancel := context.WithTimeout(context.Background(), requestTimeout)
	defer cancel()

	services, err := client.Clientset.CoreV1().Services("").List(ctx, metav1.ListOptions{})
	if err != nil {
		return fmt.Errorf("unable to collect Kubernetes services: %w", err)
	}

	inv.Services = make([]Service, 0, len(services.Items))

	for _, item := range services.Items {
		service := Service{
			Name:        item.Name,
			Namespace:   item.Namespace,
			Type:        string(item.Spec.Type),
			ClusterIP:   item.Spec.ClusterIP,
			ExternalIPs: item.Spec.ExternalIPs,
		}

		for _, port := range item.Spec.Ports {
			service.Ports = append(service.Ports, ServicePort{
				Name:       port.Name,
				Protocol:   string(port.Protocol),
				Port:       port.Port,
				TargetPort: port.TargetPort.String(),
				NodePort:   port.NodePort,
			})
		}

		// Keep the output deterministic when service ports are empty.
		if service.Ports == nil {
			service.Ports = []ServicePort{}
		}

		inv.Services = append(inv.Services, service)
	}

	inv.CollectedAt = time.Now().UTC()
	return nil
}
