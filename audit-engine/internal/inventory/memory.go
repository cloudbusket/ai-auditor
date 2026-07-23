package inventory

import "github.com/shirou/gopsutil/v3/mem"

func collectMemory(inv *Inventory) error {

	vm, err := mem.VirtualMemory()
	if err != nil {
		return err
	}

	inv.Memory = MemoryInfo{
		TotalGB: vm.Total / (1024 * 1024 * 1024),
	}

	return nil
}
