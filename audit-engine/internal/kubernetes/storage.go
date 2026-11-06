package kubernetes

import (
	"context"
	"fmt"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func CollectStorage(client *Client, inv *Inventory) error {
	if client == nil || client.Clientset == nil {
		return fmt.Errorf("Kubernetes client is not initialized")
	}
	if inv == nil {
		return fmt.Errorf("Kubernetes inventory is nil")
	}

	ctx, cancel := context.WithTimeout(context.Background(), requestTimeout)
	defer cancel()

	volumes, err := client.Clientset.CoreV1().PersistentVolumes().List(ctx, metav1.ListOptions{})
	if err != nil {
		return fmt.Errorf("unable to collect Kubernetes persistent volumes: %w", err)
	}

	inv.PersistentVolumes = make([]PersistentVolume, 0, len(volumes.Items))

	for _, item := range volumes.Items {
		accessModes := make([]string, 0, len(item.Spec.AccessModes))
		for _, mode := range item.Spec.AccessModes {
			accessModes = append(accessModes, string(mode))
		}

		inv.PersistentVolumes = append(inv.PersistentVolumes, PersistentVolume{
			Name:          item.Name,
			Capacity:      item.Spec.Capacity.Storage().String(),
			AccessModes:   accessModes,
			ReclaimPolicy: string(item.Spec.PersistentVolumeReclaimPolicy),
			Phase:         string(item.Status.Phase),
			StorageClass:  item.Spec.StorageClassName,
		})
	}

	classes, err := client.Clientset.StorageV1().StorageClasses().List(ctx, metav1.ListOptions{})
	if err != nil {
		return fmt.Errorf("unable to collect Kubernetes storage classes: %w", err)
	}

	inv.StorageClasses = make([]StorageClass, 0, len(classes.Items))

	for _, item := range classes.Items {
		reclaimPolicy := ""
		if item.ReclaimPolicy != nil {
			reclaimPolicy = string(*item.ReclaimPolicy)
		}

		bindingMode := ""
		if item.VolumeBindingMode != nil {
			bindingMode = string(*item.VolumeBindingMode)
		}

		inv.StorageClasses = append(inv.StorageClasses, StorageClass{
			Name:              item.Name,
			Provisioner:       item.Provisioner,
			ReclaimPolicy:     reclaimPolicy,
			VolumeBindingMode: bindingMode,
		})
	}

	inv.CollectedAt = time.Now().UTC()
	return nil
}
