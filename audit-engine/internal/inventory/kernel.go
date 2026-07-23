package inventory

import (
	"runtime"

	"github.com/shirou/gopsutil/v3/host"
)

func collectKernel(inv *Inventory) error {

	info, err := host.Info()
	if err != nil {
		return err
	}

	inv.Kernel = KernelInfo{
		Version: info.KernelVersion,
		Arch:    runtime.GOARCH,
	}

	return nil
}
