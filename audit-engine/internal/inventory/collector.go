package inventory

import (
	"github.com/cloudbusket/ai-auditor/audit-engine/internal/docker"
)

func Collect() (*Inventory, error) {

	inv := &Inventory{}

	collectors := []func(*Inventory) error{
		collectHostname,
		collectCloud,
		collectOS,
		collectKernel,
		collectCPU,
		collectMemory,
		collectDisk,
		collectNetwork,
		collectServices,
		collectVirtualization,
	}

	for _, c := range collectors {
		if err := c(inv); err != nil {
			// Optional collectors can return nil internally.
			return nil, err
		}
	}

	// Docker is optional.
	if d, err := docker.Collect(); err == nil {
		inv.Docker = d
	}

	return inv, nil
}
