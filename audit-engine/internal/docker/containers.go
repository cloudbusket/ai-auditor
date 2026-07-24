package docker

import (
	"bytes"
	"encoding/json"
	"os/exec"
)

type dockerContainer struct {
	ID      string `json:"ID"`
	Image   string `json:"Image"`
	Names   string `json:"Names"`
	State   string `json:"State"`
	Status  string `json:"Status"`
	Running bool   `json:"RunningFor,omitempty"`
}

func collectContainers(inv *Inventory) error {

	cmd := exec.Command(
		"docker",
		"ps",
		"-a",
		"--format",
		`{{json .}}`,
	)

	out, err := cmd.Output()
	if err != nil {
		return err
	}

	lines := bytes.Split(bytes.TrimSpace(out), []byte("\n"))

	for _, line := range lines {

		if len(line) == 0 {
			continue
		}

		var c dockerContainer

		if err := json.Unmarshal(line, &c); err != nil {
			continue
		}

		inv.Containers = append(inv.Containers, Container{
			ID:      c.ID,
			Name:    c.Names,
			Image:   c.Image,
			State:   c.State,
			Status:  c.Status,
			Running: c.State == "running",
		})
	}

	return nil
}
