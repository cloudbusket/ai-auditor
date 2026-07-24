package docker

import (
	"bytes"
	"encoding/json"
	"os/exec"
)

type dockerVersion struct {
	Version      string `json:"Version"`
	APIVersion   string `json:"ApiVersion"`
	GoVersion    string `json:"GoVersion"`
	GitCommit    string `json:"GitCommit"`
	BuildTime    string `json:"BuildTime"`
	Experimental bool   `json:"Experimental"`
}

func collectVersion(inv *Inventory) error {

	cmd := exec.Command("docker", "version", "--format", "{{json .Server}}")

	out, err := cmd.Output()
	if err != nil {
		return err
	}

	var v dockerVersion

	if err := json.NewDecoder(bytes.NewReader(out)).Decode(&v); err != nil {
		return err
	}

	inv.Installed = true

	inv.Version = VersionInfo{
		Version:      v.Version,
		APIVersion:   v.APIVersion,
		GoVersion:    v.GoVersion,
		GitCommit:    v.GitCommit,
		BuildTime:    v.BuildTime,
		Experimental: v.Experimental,
	}

	return nil
}
