package docker

type Inventory struct {
	Installed  bool        `json:"installed"`
	Version    VersionInfo `json:"version,omitempty"`
	Containers []Container `json:"containers,omitempty"`
	Images     []Image     `json:"images,omitempty"`
	Networks   []Network   `json:"networks,omitempty"`
	Volumes    []Volume    `json:"volumes,omitempty"`
}

type VersionInfo struct {
	Version      string `json:"version,omitempty"`
	APIVersion   string `json:"api_version,omitempty"`
	GoVersion    string `json:"go_version,omitempty"`
	GitCommit    string `json:"git_commit,omitempty"`
	BuildTime    string `json:"build_time,omitempty"`
	Experimental bool   `json:"experimental,omitempty"`
}

type Container struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Image   string `json:"image"`
	State   string `json:"state"`
	Status  string `json:"status"`
	Running bool   `json:"running"`
}

type Image struct {
	ID      string `json:"id"`
	Repo    string `json:"repository"`
	Tag     string `json:"tag"`
	SizeMB  int64  `json:"size_mb"`
	Created string `json:"created,omitempty"`
}

type Network struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	Driver string `json:"driver"`
	Scope  string `json:"scope"`
}

type Volume struct {
	Name       string `json:"name"`
	Driver     string `json:"driver"`
	Mountpoint string `json:"mountpoint"`
}
