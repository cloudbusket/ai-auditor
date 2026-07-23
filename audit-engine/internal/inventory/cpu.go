package inventory

import (
	"runtime"

	"github.com/shirou/gopsutil/v3/cpu"
)

func collectCPU(inv *Inventory) error {

	info, err := cpu.Info()
	if err != nil {
		return err
	}

	inv.CPU = CPUInfo{
		Model:   info[0].ModelName,
		Vendor:  info[0].VendorID,
		Cores:   runtime.NumCPU(),
		Threads: runtime.NumCPU(),
	}

	return nil
}
