package inventory

type Inventory struct {
	Hostname       string         `json:"hostname"`
	OS             OSInfo         `json:"os"`
	Kernel         KernelInfo     `json:"kernel"`
	CPU            CPUInfo        `json:"cpu"`
	Memory         MemoryInfo     `json:"memory"`
	Disk           []DiskInfo     `json:"disk,omitempty"`
	Network        []NetworkInfo  `json:"network,omitempty"`
	Virtualization Virtualization `json:"virtualization,omitempty"`
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
	Device string `json:"device"`
	Mount  string `json:"mount"`
	SizeGB uint64 `json:"size_gb"`
	UsedGB uint64 `json:"used_gb"`
}

type NetworkInfo struct {
	Name string   `json:"name"`
	MAC  string   `json:"mac"`
	IPs  []string `json:"ips"`
}

type Virtualization struct {
	Type string `json:"type"`
}
