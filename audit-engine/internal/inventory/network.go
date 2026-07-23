package inventory

import (
	"net"
)

func collectNetwork(inv *Inventory) error {

	ifaces, err := net.Interfaces()
	if err != nil {
		return err
	}

	for _, iface := range ifaces {

		info := NetworkInfo{
			Name: iface.Name,
			MAC:  iface.HardwareAddr.String(),
			MTU:  iface.MTU,
		}

		if iface.Flags&net.FlagUp != 0 {
			info.State = "up"
		} else {
			info.State = "down"
		}

		addrs, err := iface.Addrs()
		if err == nil {

			for _, addr := range addrs {

				ipnet, ok := addr.(*net.IPNet)
				if !ok {
					continue
				}

				if ipnet.IP.IsLoopback() {
					continue
				}

				if ip4 := ipnet.IP.To4(); ip4 != nil {
					info.IPv4 = append(info.IPv4, ip4.String())
				} else {
					info.IPv6 = append(info.IPv6, ipnet.IP.String())
				}

			}
		}

		inv.Network = append(inv.Network, info)

	}

	return nil

}
