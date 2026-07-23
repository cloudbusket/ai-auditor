package inventory

import (
	"os"
	"os/exec"
	"strings"
)

func collectVirtualization(inv *Inventory) error {

	v := Virtualization{
		Type: "bare-metal",
	}

	// Docker

	if _, err := os.Stat("/.dockerenv"); err == nil {
		v.Type = "docker"
		inv.Virtualization = v
		return nil
	}

	// systemd-detect-virt

	out, err := exec.Command("systemd-detect-virt").Output()
	if err == nil {

		virt := strings.TrimSpace(string(out))

		if virt != "" && virt != "none" {

			v.Type = virt

			switch virt {

			case "kvm":
				v.Vendor = "KVM"

			case "vmware":
				v.Vendor = "VMware"

			case "oracle":
				v.Vendor = "VirtualBox"

			case "microsoft":
				v.Vendor = "Hyper-V"

			case "amazon":
				v.Vendor = "AWS"

			case "google":
				v.Vendor = "Google Cloud"

			case "qemu":
				v.Vendor = "QEMU"

			case "lxc":
				v.Vendor = "LXC"

			case "docker":
				v.Vendor = "Docker"
			}
		}
	}

	// Detect Google Cloud

	if data, err := os.ReadFile("/sys/class/dmi/id/product_name"); err == nil {

		product := strings.ToLower(string(data))

		if strings.Contains(product, "google") {

			v.Type = "gcp"

			v.Vendor = "Google Cloud Platform"
		}
	}

	// Detect EC2

	if data, err := os.ReadFile("/sys/class/dmi/id/sys_vendor"); err == nil {

		vendor := strings.ToLower(string(data))

		if strings.Contains(vendor, "amazon") {

			v.Type = "ec2"

			v.Vendor = "Amazon EC2"
		}
	}

	inv.Virtualization = v

	return nil
}
