package inventory

import (
	"bufio"
	"os"
	"strings"
	"syscall"
)

func collectDisk(inv *Inventory) error {

	file, err := os.Open("/proc/mounts")
	if err != nil {
		return err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)

	for scanner.Scan() {

		fields := strings.Fields(scanner.Text())

		if len(fields) < 3 {
			continue
		}

		device := fields[0]
		mount := fields[1]
		fsType := fields[2]

		// Ignore pseudo filesystems

		switch fsType {

		case "proc",
			"sysfs",
			"tmpfs",
			"devtmpfs",
			"devpts",
			"overlay",
			"cgroup",
			"cgroup2",
			"squashfs",
			"tracefs",
			"securityfs",
			"pstore",
			"configfs",
			"debugfs",
			"mqueue",
			"hugetlbfs",
			"fusectl",
			"ramfs":

			continue
		}

		var stat syscall.Statfs_t

		err := syscall.Statfs(mount, &stat)
		if err != nil {
			continue
		}

		total := stat.Blocks * uint64(stat.Bsize)
		free := stat.Bavail * uint64(stat.Bsize)
		used := total - free

		var usedPct uint64

		if total > 0 {
			usedPct = used * 100 / total
		}

		inv.Disk = append(inv.Disk, DiskInfo{

			Device: device,

			Mount: mount,

			FSType: fsType,

			SizeGB: total / 1024 / 1024 / 1024,

			UsedGB: used / 1024 / 1024 / 1024,

			FreeGB: free / 1024 / 1024 / 1024,

			UsedPercent: usedPct,
		})

	}

	return nil
}
