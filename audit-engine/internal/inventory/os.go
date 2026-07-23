package inventory

import "github.com/shirou/gopsutil/v3/host"

func collectOS(inv *Inventory) error {

	info, err := host.Info()
	if err != nil {
		return err
	}

	inv.OS = OSInfo{
		Platform: info.Platform,
		Version:  info.PlatformVersion,
		Family:   info.PlatformFamily,
	}

	return nil
}
