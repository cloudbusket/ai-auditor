package docker

import (
	"bytes"
	"encoding/json"
	"os/exec"
)

type dockerNetwork struct {
	ID     string `json:"ID"`
	Name   string `json:"Name"`
	Driver string `json:"Driver"`
	Scope  string `json:"Scope"`
}

func collectNetworks(inv *Inventory) error {

	cmd := exec.Command(
		"docker",
		"network",
		"ls",
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

		var n dockerNetwork

		if err := json.Unmarshal(line, &n); err != nil {
			continue
		}

		inv.Networks = append(inv.Networks, Network{
			ID:     n.ID,
			Name:   n.Name,
			Driver: n.Driver,
			Scope:  n.Scope,
		})
	}

	return nil
}
