package docker

import (
	"fmt"
	"os/exec"
	"strings"
)

// Collect gathers Docker inventory. Docker is optional, so collection failures
// are reported in the inventory instead of aborting the host audit.
func Collect() (*Inventory, error) {
	inv := &Inventory{}

	if _, err := exec.LookPath("docker"); err != nil {
		inv.Error = "Docker CLI is not installed or not in PATH"
		return inv, nil
	}

	inv.Installed = true
	inv.CLIAvailable = true

	if err := collectVersion(inv); err != nil {
		inv.DaemonAvailable = false
		inv.Error = "Docker CLI is installed, but the daemon is unavailable: " + err.Error()
		return inv, nil
	}

	inv.DaemonAvailable = true

	collectors := []struct {
		name string
		run  func(*Inventory) error
	}{
		{"containers", collectContainers},
		{"images", collectImages},
		{"networks", collectNetworks},
		{"volumes", collectVolumes},
	}

	var collectionErrors []string
	for _, collector := range collectors {
		if err := collector.run(inv); err != nil {
			collectionErrors = append(collectionErrors, fmt.Sprintf("%s: %v", collector.name, err))
		}
	}

	if len(collectionErrors) > 0 {
		inv.Error = "Docker inventory is incomplete: " + strings.Join(collectionErrors, "; ")
	}

	return inv, nil
}
