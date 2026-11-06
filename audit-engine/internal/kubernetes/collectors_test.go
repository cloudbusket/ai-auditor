package kubernetes

import (
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	storagev1 "k8s.io/api/storage/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/client-go/kubernetes/fake"
)

func TestCollectNodes(t *testing.T) {
	clientset := fake.NewSimpleClientset(
		&corev1.Node{
			ObjectMeta: metav1.ObjectMeta{Name: "worker-1"},
			Spec:       corev1.NodeSpec{Unschedulable: true},
			Status: corev1.NodeStatus{
				NodeInfo: corev1.NodeSystemInfo{
					KubeletVersion:  "v1.30.0",
					OperatingSystem: "linux",
					Architecture:    "amd64",
				},
				Conditions: []corev1.NodeCondition{
					{Type: corev1.NodeReady, Status: corev1.ConditionTrue},
				},
			},
		},
	)

	client := &Client{Clientset: clientset}
	inv := &Inventory{}

	if err := CollectNodes(client, inv); err != nil {
		t.Fatalf("CollectNodes returned an error: %v", err)
	}

	if len(inv.Nodes) != 1 {
		t.Fatalf("expected 1 node, got %d", len(inv.Nodes))
	}

	node := inv.Nodes[0]
	if node.Name != "worker-1" || !node.Ready || !node.Unschedulable {
		t.Errorf("unexpected node inventory: %+v", node)
	}
	if node.KubeletVersion != "v1.30.0" {
		t.Errorf("unexpected kubelet version: %s", node.KubeletVersion)
	}
}

func TestCollectNamespaces(t *testing.T) {
	clientset := fake.NewSimpleClientset(
		&corev1.Namespace{
			ObjectMeta: metav1.ObjectMeta{Name: "production"},
			Status:     corev1.NamespaceStatus{Phase: corev1.NamespaceActive},
		},
	)

	client := &Client{Clientset: clientset}
	inv := &Inventory{}

	if err := CollectNamespaces(client, inv); err != nil {
		t.Fatalf("CollectNamespaces returned an error: %v", err)
	}

	if len(inv.Namespaces) != 1 {
		t.Fatalf("expected 1 namespace, got %d", len(inv.Namespaces))
	}

	ns := inv.Namespaces[0]
	if ns.Name != "production" || ns.Status != "Active" {
		t.Errorf("unexpected namespace inventory: %+v", ns)
	}
}

func TestCollectPods(t *testing.T) {
	clientset := fake.NewSimpleClientset(
		&corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "web-1",
				Namespace: "production",
			},
			Spec: corev1.PodSpec{
				NodeName: "worker-1",
				Containers: []corev1.Container{
					{Name: "web"},
					{Name: "sidecar"},
				},
			},
			Status: corev1.PodStatus{
				Phase: corev1.PodRunning,
				ContainerStatuses: []corev1.ContainerStatus{
					{Ready: true, RestartCount: 2},
					{Ready: false, RestartCount: 1},
				},
			},
		},
	)

	client := &Client{Clientset: clientset}
	inv := &Inventory{}

	if err := CollectPods(client, inv); err != nil {
		t.Fatalf("CollectPods returned an error: %v", err)
	}

	if len(inv.Pods) != 1 {
		t.Fatalf("expected 1 pod, got %d", len(inv.Pods))
	}

	pod := inv.Pods[0]
	if pod.Name != "web-1" || pod.Namespace != "production" {
		t.Errorf("unexpected pod identity: %+v", pod)
	}
	if pod.Phase != "Running" || pod.NodeName != "worker-1" {
		t.Errorf("unexpected pod placement/status: %+v", pod)
	}
	if pod.ReadyContainers != 1 || pod.TotalContainers != 2 {
		t.Errorf("unexpected container readiness: %+v", pod)
	}
	if pod.RestartCount != 3 {
		t.Errorf("expected 3 restarts, got %d", pod.RestartCount)
	}
}

func TestCollectDeployments(t *testing.T) {
	replicas := int32(3)

	clientset := fake.NewSimpleClientset(
		&appsv1.Deployment{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "web",
				Namespace: "production",
			},
			Spec: appsv1.DeploymentSpec{
				Replicas: &replicas,
			},
			Status: appsv1.DeploymentStatus{
				ReadyReplicas:     2,
				AvailableReplicas: 2,
			},
		},
	)

	client := &Client{Clientset: clientset}
	inv := &Inventory{}

	if err := CollectDeployments(client, inv); err != nil {
		t.Fatalf("CollectDeployments returned an error: %v", err)
	}

	if len(inv.Deployments) != 1 {
		t.Fatalf("expected 1 deployment, got %d", len(inv.Deployments))
	}

	deployment := inv.Deployments[0]
	if deployment.Name != "web" || deployment.Namespace != "production" {
		t.Errorf("unexpected deployment identity: %+v", deployment)
	}
	if deployment.Replicas != 3 ||
		deployment.ReadyReplicas != 2 ||
		deployment.AvailableReplicas != 2 {
		t.Errorf("unexpected deployment replica counts: %+v", deployment)
	}
}

func TestCollectServices(t *testing.T) {
	clientset := fake.NewSimpleClientset(
		&corev1.Service{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "web-service",
				Namespace: "production",
			},
			Spec: corev1.ServiceSpec{
				Type:      corev1.ServiceTypeNodePort,
				ClusterIP: "10.0.0.10",
				ExternalIPs: []string{
					"203.0.113.10",
				},
				Ports: []corev1.ServicePort{
					{
						Name:       "http",
						Protocol:   corev1.ProtocolTCP,
						Port:       80,
						TargetPort: intstr.FromInt32(8080),
						NodePort:   30080,
					},
				},
			},
		},
	)

	client := &Client{Clientset: clientset}
	inv := &Inventory{}

	if err := CollectServices(client, inv); err != nil {
		t.Fatalf("CollectServices returned an error: %v", err)
	}

	if len(inv.Services) != 1 {
		t.Fatalf("expected 1 service, got %d", len(inv.Services))
	}

	service := inv.Services[0]
	if service.Name != "web-service" || service.Type != "NodePort" {
		t.Errorf("unexpected service identity/type: %+v", service)
	}
	if service.ClusterIP != "10.0.0.10" || len(service.ExternalIPs) != 1 {
		t.Errorf("unexpected service addressing: %+v", service)
	}
	if len(service.Ports) != 1 {
		t.Fatalf("expected 1 service port, got %d", len(service.Ports))
	}

	port := service.Ports[0]
	if port.Port != 80 || port.TargetPort != "8080" || port.NodePort != 30080 {
		t.Errorf("unexpected service port: %+v", port)
	}
}

func TestCollectStorage(t *testing.T) {
	reclaimPolicy := corev1.PersistentVolumeReclaimRetain
	bindingMode := storagev1.VolumeBindingImmediate

	clientset := fake.NewSimpleClientset(
		&corev1.PersistentVolume{
			ObjectMeta: metav1.ObjectMeta{Name: "data-volume"},
			Spec: corev1.PersistentVolumeSpec{
				Capacity: corev1.ResourceList{
					corev1.ResourceStorage: resource.MustParse("20Gi"),
				},
				AccessModes: []corev1.PersistentVolumeAccessMode{
					corev1.ReadWriteOnce,
				},
				PersistentVolumeReclaimPolicy: reclaimPolicy,
				StorageClassName:              "fast-storage",
			},
			Status: corev1.PersistentVolumeStatus{
				Phase: corev1.VolumeBound,
			},
		},
		&storagev1.StorageClass{
			ObjectMeta:        metav1.ObjectMeta{Name: "fast-storage"},
			Provisioner:       "kubernetes.io/gce-pd",
			ReclaimPolicy:     &reclaimPolicy,
			VolumeBindingMode: &bindingMode,
		},
	)

	client := &Client{Clientset: clientset}
	inv := &Inventory{}

	if err := CollectStorage(client, inv); err != nil {
		t.Fatalf("CollectStorage returned an error: %v", err)
	}

	if len(inv.PersistentVolumes) != 1 {
		t.Fatalf("expected 1 persistent volume, got %d", len(inv.PersistentVolumes))
	}

	pv := inv.PersistentVolumes[0]
	if pv.Name != "data-volume" || pv.Capacity != "20Gi" {
		t.Errorf("unexpected persistent volume: %+v", pv)
	}
	if pv.Phase != "Bound" || pv.StorageClass != "fast-storage" {
		t.Errorf("unexpected persistent volume status: %+v", pv)
	}
	if len(pv.AccessModes) != 1 || pv.AccessModes[0] != "ReadWriteOnce" {
		t.Errorf("unexpected access modes: %+v", pv.AccessModes)
	}

	if len(inv.StorageClasses) != 1 {
		t.Fatalf("expected 1 storage class, got %d", len(inv.StorageClasses))
	}

	sc := inv.StorageClasses[0]
	if sc.Name != "fast-storage" || sc.Provisioner != "kubernetes.io/gce-pd" {
		t.Errorf("unexpected storage class: %+v", sc)
	}
	if sc.ReclaimPolicy != "Retain" || sc.VolumeBindingMode != "Immediate" {
		t.Errorf("unexpected storage class policies: %+v", sc)
	}
}
