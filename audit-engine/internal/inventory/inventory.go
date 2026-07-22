package inventory

import (
	"fmt"
	"os"
	"runtime"

	"github.com/shirou/gopsutil/v3/cpu"
	"github.com/shirou/gopsutil/v3/host"
	"github.com/shirou/gopsutil/v3/mem"
)

// Collect gathers basic host inventory information.
func Collect() (*Inventory, error) {

	info := &Inventory{}

	// Hostname
	hostname, err := os.Hostname()
	if err != nil {
		hostname = "unknown"
	}
	info.Hostname = hostname

	// Host Information
	hostInfo, err := host.Info()
	if err != nil {
		return nil, fmt.Errorf("failed to read host info: %w", err)
	}

	info.OS = fmt.Sprintf("%s %s", hostInfo.Platform, hostInfo.PlatformVersion)
	info.Kernel = hostInfo.KernelVersion

	// CPU
	cpuCount, err := cpu.Counts(true)
	if err != nil {
		cpuCount = runtime.NumCPU()
	}
	info.CPU = cpuCount

	// Memory
	vm, err := mem.VirtualMemory()
	if err != nil {
		return nil, fmt.Errorf("failed to read memory info: %w", err)
	}

	info.MemoryGB = vm.Total / (1024 * 1024 * 1024)

	return info, nil
}
