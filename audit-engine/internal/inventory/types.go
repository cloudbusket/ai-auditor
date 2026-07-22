package inventory

type Inventory struct {
	Hostname string `json:"hostname"`
	OS       string `json:"os"`
	Kernel   string `json:"kernel"`
	CPU      int    `json:"cpu"`
	MemoryGB uint64 `json:"memory_gb"`
}
