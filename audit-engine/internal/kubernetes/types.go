package kubernetes

import "time"

type Inventory struct {
	Configured      bool      `json:"configured"`
	Connected       bool      `json:"connected"`
	Context         string    `json:"context,omitempty"`
	ServerVersion   string    `json:"server_version,omitempty"`
	PlatformVersion string    `json:"platform_version,omitempty"`
	Error           string    `json:"error,omitempty"`
	CollectedAt     time.Time `json:"collected_at,omitempty"`

	Nodes             []Node             `json:"nodes,omitempty"`
	Namespaces        []Namespace        `json:"namespaces,omitempty"`
	Pods              []Pod              `json:"pods,omitempty"`
	Deployments       []Deployment       `json:"deployments,omitempty"`
	Services          []Service          `json:"services,omitempty"`
	PersistentVolumes []PersistentVolume `json:"persistent_volumes,omitempty"`
	StorageClasses    []StorageClass     `json:"storage_classes,omitempty"`
	CollectionErrors  []string           `json:"collection_errors,omitempty"`
}

type Node struct {
	Name            string `json:"name"`
	Status          string `json:"status"`
	KubeletVersion  string `json:"kubelet_version,omitempty"`
	OperatingSystem string `json:"operating_system,omitempty"`
	Architecture    string `json:"architecture,omitempty"`
	Ready           bool   `json:"ready"`
	Unschedulable   bool   `json:"unschedulable"`
}

type Namespace struct {
	Name   string `json:"name"`
	Status string `json:"status"`
}

type Pod struct {
	Name            string `json:"name"`
	Namespace       string `json:"namespace"`
	Phase           string `json:"phase"`
	NodeName        string `json:"node_name,omitempty"`
	ReadyContainers int32  `json:"ready_containers"`
	TotalContainers int32  `json:"total_containers"`
	RestartCount    int32  `json:"restart_count"`
}

type Deployment struct {
	Name              string `json:"name"`
	Namespace         string `json:"namespace"`
	Replicas          int32  `json:"replicas"`
	ReadyReplicas     int32  `json:"ready_replicas"`
	AvailableReplicas int32  `json:"available_replicas"`
}

type Service struct {
	Name        string        `json:"name"`
	Namespace   string        `json:"namespace"`
	Type        string        `json:"type"`
	ClusterIP   string        `json:"cluster_ip,omitempty"`
	ExternalIPs []string      `json:"external_ips,omitempty"`
	Ports       []ServicePort `json:"ports,omitempty"`
}

type ServicePort struct {
	Name       string `json:"name,omitempty"`
	Protocol   string `json:"protocol"`
	Port       int32  `json:"port"`
	TargetPort string `json:"target_port,omitempty"`
	NodePort   int32  `json:"node_port,omitempty"`
}

type PersistentVolume struct {
	Name          string   `json:"name"`
	Capacity      string   `json:"capacity,omitempty"`
	AccessModes   []string `json:"access_modes,omitempty"`
	ReclaimPolicy string   `json:"reclaim_policy,omitempty"`
	Phase         string   `json:"phase"`
	StorageClass  string   `json:"storage_class,omitempty"`
}

type StorageClass struct {
	Name              string `json:"name"`
	Provisioner       string `json:"provisioner"`
	ReclaimPolicy     string `json:"reclaim_policy,omitempty"`
	VolumeBindingMode string `json:"volume_binding_mode,omitempty"`
}
