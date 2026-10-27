package docker

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
	"syscall"
)

type StorageEntry struct {
	Type        string `json:"Type"`
	TotalCount  string `json:"TotalCount"`
	Active      string `json:"Active"`
	Size        string `json:"Size"`
	Reclaimable string `json:"Reclaimable"`
}

func collectStorage(inv *Inventory) error {
	cmd := exec.Command("docker", "system", "df", "--format", "{{json .}}")
	out, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("docker system df failed: %w", err)
	}

	scanner := bufio.NewScanner(strings.NewReader(string(out)))
	var entries []StorageEntry

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		var entry StorageEntry
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			return fmt.Errorf("parse Docker storage output: %w", err)
		}
		entries = append(entries, entry)
	}

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("read Docker storage output: %w", err)
	}

	inv.Storage = entries
	return nil
}

func collectDockerFilesystem(inv *Inventory) error {
	out, err := exec.Command(
		"docker", "info", "--format", "{{.DockerRootDir}}",
	).Output()
	if err != nil {
		return fmt.Errorf("discover Docker data directory: %w", err)
	}

	rootDir := strings.TrimSpace(string(out))
	if rootDir == "" {
		return fmt.Errorf("Docker returned an empty data directory")
	}

	var stat syscall.Statfs_t
	if err := syscall.Statfs(rootDir, &stat); err != nil {
		return fmt.Errorf("inspect filesystem for %s: %w", rootDir, err)
	}

	blockSize := uint64(stat.Bsize)
	total := stat.Blocks * blockSize
	free := stat.Bavail * blockSize
	if free > total {
		free = total
	}

	usedBlocks := stat.Blocks
	if stat.Bfree <= stat.Blocks {
		usedBlocks -= stat.Bfree
	} else {
		usedBlocks = 0
	}
	used := usedBlocks * blockSize

	var usedPercent uint64
	if total > 0 {
		usedPercent = used * 100 / total
	}

	inv.DockerRootDir = rootDir
	inv.FilesystemSizeGB = total / 1024 / 1024 / 1024
	inv.FilesystemUsedGB = used / 1024 / 1024 / 1024
	inv.FilesystemFreeGB = free / 1024 / 1024 / 1024
	inv.FilesystemUsedPercent = usedPercent

	return nil
}
