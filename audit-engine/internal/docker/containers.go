package docker

import (
	"bufio"
	"encoding/json"
	"os/exec"
	"strings"
)

type dockerContainer struct {
	ID     string `json:"ID"`
	Image  string `json:"Image"`
	Names  string `json:"Names"`
	State  string `json:"State"`
	Status string `json:"Status"`
	Health string `json:"Health"`
}

func collectContainers(inv *Inventory) error {
	cmd := exec.Command("docker", "ps", "-a", "--format", "{{json .}}")
	out, err := cmd.Output()
	if err != nil {
		return err
	}

	scanner := bufio.NewScanner(strings.NewReader(string(out)))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		var c dockerContainer
		if err := json.Unmarshal([]byte(line), &c); err != nil {
			continue
		}

		health := strings.ToLower(strings.TrimSpace(c.Health))
		statusLower := strings.ToLower(c.Status)

		// Docker's ps formatter may expose health in Status rather than Health.
		if health == "" {
			switch {
			case strings.Contains(statusLower, "(unhealthy)"):
				health = "unhealthy"
			case strings.Contains(statusLower, "(healthy)"):
				health = "healthy"
			case strings.Contains(statusLower, "(health: starting)"):
				health = "starting"
			}
		}

		inv.Containers = append(inv.Containers, Container{
			ID:      c.ID,
			Name:    c.Names,
			Image:   c.Image,
			State:   c.State,
			Status:  c.Status,
			Running: strings.EqualFold(c.State, "running"),
			Health:  health,
		})
	}

	return scanner.Err()
}
