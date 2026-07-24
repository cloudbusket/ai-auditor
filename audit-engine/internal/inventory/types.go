package inventory

import (
	"github.com/cloudbusket/ai-auditor/audit-engine/internal/docker"
)

type Inventory struct {
	Hostname       string            `json:"hostname"`
	Cloud          CloudInfo         `json:"cloud,omitempty"`
	OS             OSInfo            `json:"os"`
	Kernel         KernelInfo        `json:"kernel"`
	CPU            CPUInfo           `json:"cpu"`
	Memory         MemoryInfo        `json:"memory"`
	Disk           []DiskInfo        `json:"disk,omitempty"`
	Network        []NetworkInfo     `json:"network,omitempty"`
	Virtualization Virtualization    `json:"virtualization,omitempty"`
	Docker         *docker.Inventory `json:"docker,omitempty"`
}

type OSInfo struct {
	Platform string `json:"platform"`
	Version  string `json:"version"`
	Family   string `json:"family"`
}

type KernelInfo struct {
	Version string `json:"version"`
	Arch    string `json:"arch"`
}

type CPUInfo struct {
	Model   string `json:"model"`
	Vendor  string `json:"vendor"`
	Cores   int    `json:"cores"`
	Threads int    `json:"threads"`
}

type MemoryInfo struct {
	TotalGB uint64 `json:"total_gb"`
}

type DiskInfo struct {
	Device      string `json:"device"`
	Mount       string `json:"mount"`
	FSType      string `json:"fstype"`
	SizeGB      uint64 `json:"size_gb"`
	UsedGB      uint64 `json:"used_gb"`
	FreeGB      uint64 `json:"free_gb"`
	UsedPercent uint64 `json:"used_percent"`
}

type NetworkInfo struct {
	Name  string   `json:"name"`
	MAC   string   `json:"mac"`
	MTU   int      `json:"mtu"`
	State string   `json:"state"`
	IPv4  []string `json:"ipv4,omitempty"`
	IPv6  []string `json:"ipv6,omitempty"`
}

type Virtualization struct {
	Type     string `json:"type"`
	Vendor   string `json:"vendor,omitempty"`
	Role     string `json:"role,omitempty"`
	Hostname string `json:"hostname,omitempty"`
}

type CloudInfo struct {
	Provider       string            `json:"provider,omitempty"`
	ProjectID      string            `json:"project_id,omitempty"`
	ProjectNumber  string            `json:"project_number,omitempty"`
	InstanceName   string            `json:"instance_name,omitempty"`
	InstanceID     string            `json:"instance_id,omitempty"`
	Zone           string            `json:"zone,omitempty"`
	Region         string            `json:"region,omitempty"`
	MachineType    string            `json:"machine_type,omitempty"`
	InternalIP     string            `json:"internal_ip,omitempty"`
	ExternalIP     string            `json:"external_ip,omitempty"`
	ServiceAccount string            `json:"service_account,omitempty"`
	Hostname       string            `json:"hostname,omitempty"`
	Tags           []string          `json:"tags,omitempty"`
	Labels         map[string]string `json:"labels,omitempty"`
}
