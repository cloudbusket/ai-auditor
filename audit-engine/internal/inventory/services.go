package inventory

import (
	"bufio"
	"bytes"
	"os/exec"
	"strconv"
	"strings"
)

func collectServices(inv *Inventory) error {

	cmd := exec.Command(
		"systemctl",
		"list-units",
		"--type=service",
		"--state=running",
		"--no-legend",
		"--no-pager",
	)

	out, err := cmd.Output()
	if err != nil {
		return nil
	}

	scanner := bufio.NewScanner(bytes.NewReader(out))

	for scanner.Scan() {

		line := strings.TrimSpace(scanner.Text())

		if line == "" {
			continue
		}

		fields := strings.Fields(line)

		if len(fields) == 0 {
			continue
		}

		unit := fields[0]

		service := ServiceInfo{
			Name: strings.TrimSuffix(unit, ".service"),
		}

		fillServiceDetails(unit, &service)

		inv.Services = append(inv.Services, service)
	}

	return nil
}

func fillServiceDetails(unit string, svc *ServiceInfo) {

	cmd := exec.Command(
		"systemctl",
		"show",
		unit,
		"--property=Description",
		"--property=ActiveState",
		"--property=SubState",
		"--property=UnitFileState",
		"--property=ActiveEnterTimestamp",
		"--property=MainPID",
	)

	out, err := cmd.Output()
	if err != nil {
		return
	}

	lines := strings.Split(string(out), "\n")

	for _, line := range lines {

		parts := strings.SplitN(line, "=", 2)

		if len(parts) != 2 {
			continue
		}

		key := parts[0]
		val := parts[1]

		switch key {

		case "Description":
			svc.Description = val

		case "ActiveState":
			svc.State = val

		case "SubState":
			svc.SubState = val

		case "UnitFileState":
			svc.Enabled = (val == "enabled")

		case "ActiveEnterTimestamp":
			svc.ActiveSince = val

		case "MainPID":
			pid, _ := strconv.Atoi(val)
			svc.MainPID = pid
		}
	}
}
