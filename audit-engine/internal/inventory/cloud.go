package inventory

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"time"
)

const metadataURL = "http://metadata.google.internal/computeMetadata/v1/"

var metadataClient = &http.Client{
	Timeout: 3 * time.Second,
}

func metadata(path string) string {

	req, err := http.NewRequest(
		"GET",
		metadataURL+path,
		nil,
	)

	if err != nil {
		return ""
	}

	req.Header.Set("Metadata-Flavor", "Google")

	resp, err := metadataClient.Do(req)

	if err != nil {
		return ""
	}

	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)

	return strings.TrimSpace(string(body))
}

func collectCloud(inv *Inventory) error {

	project := metadata("project/project-id")

	if project == "" {
		return nil
	}

	inv.Cloud.Provider = "gcp"

	inv.Cloud.ProjectID = project

	inv.Cloud.ProjectNumber = metadata("project/numeric-project-id")

	inv.Cloud.InstanceName = metadata("instance/name")

	inv.Cloud.InstanceID = metadata("instance/id")

	inv.Cloud.Hostname = metadata("instance/hostname")

	zone := metadata("instance/zone")

	zone = strings.TrimPrefix(
		zone,
		"projects/",
	)

	if idx := strings.LastIndex(zone, "/"); idx >= 0 {
		zone = zone[idx+1:]
	}

	inv.Cloud.Zone = zone

	if len(zone) > 2 {

		parts := strings.Split(zone, "-")

		if len(parts) >= 2 {

			inv.Cloud.Region = strings.Join(parts[:len(parts)-1], "-")
		}
	}

	mt := metadata("instance/machine-type")

	if idx := strings.LastIndex(mt, "/"); idx >= 0 {

		mt = mt[idx+1:]
	}

	inv.Cloud.MachineType = mt

	inv.Cloud.InternalIP =
		metadata("instance/network-interfaces/0/ip")

	inv.Cloud.ExternalIP =
		metadata("instance/network-interfaces/0/access-configs/0/external-ip")

	inv.Cloud.ServiceAccount =
		metadata("instance/service-accounts/default/email")

	//------------------------------------
	// Tags
	//------------------------------------

	tags := metadata("instance/tags")

	if tags != "" {

		inv.Cloud.Tags = strings.Split(tags, "\n")
	}

	//------------------------------------
	// Labels
	//------------------------------------

	lbl := metadata("instance/attributes/?recursive=true")

	if lbl != "" {

		var m map[string]string

		if json.Unmarshal([]byte(lbl), &m) == nil {

			inv.Cloud.Labels = m
		}
	}

	return nil
}
