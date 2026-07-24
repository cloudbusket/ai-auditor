package docker

import (
	"bytes"
	"encoding/json"
	"os/exec"
)

type dockerVolume struct {
	Driver     string `json:"Driver"`
	Name       string `json:"Name"`
	Mountpoint string `json:"Mountpoint"`
}

func collectVolumes(inv *Inventory) error {

	cmd := exec.Command(
		"docker",
		"volume",
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

		var v dockerVolume

		if err := json.Unmarshal(line, &v); err != nil {
			continue
		}

		inv.Volumes = append(inv.Volumes, Volume{
			Name:       v.Name,
			Driver:     v.Driver,
			Mountpoint: v.Mountpoint,
		})
	}

	return nil
}
