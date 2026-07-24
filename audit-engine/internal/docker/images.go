package docker

import (
	"bytes"
	"encoding/json"
	"os/exec"
	"strconv"
	"strings"
)

type dockerImage struct {
	ID         string `json:"ID"`
	Repository string `json:"Repository"`
	Tag        string `json:"Tag"`
	Size       string `json:"Size"`
	CreatedAt  string `json:"CreatedAt"`
}

func collectImages(inv *Inventory) error {

	cmd := exec.Command(
		"docker",
		"images",
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

		var img dockerImage

		if err := json.Unmarshal(line, &img); err != nil {
			continue
		}

		inv.Images = append(inv.Images, Image{
			ID:      img.ID,
			Repo:    img.Repository,
			Tag:     img.Tag,
			SizeMB:  parseDockerSize(img.Size),
			Created: img.CreatedAt,
		})
	}

	return nil
}

func parseDockerSize(s string) int64 {

	s = strings.TrimSpace(strings.ToUpper(s))

	if strings.HasSuffix(s, "MB") {
		v, _ := strconv.ParseFloat(strings.TrimSuffix(s, "MB"), 64)
		return int64(v)
	}

	if strings.HasSuffix(s, "GB") {
		v, _ := strconv.ParseFloat(strings.TrimSuffix(s, "GB"), 64)
		return int64(v * 1024)
	}

	if strings.HasSuffix(s, "KB") {
		v, _ := strconv.ParseFloat(strings.TrimSuffix(s, "KB"), 64)
		return int64(v / 1024)
	}

	return 0
}
