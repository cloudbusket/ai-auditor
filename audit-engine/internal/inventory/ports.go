package inventory

import (
	"fmt"
	"net"
	"strings"

	netstat "github.com/shirou/gopsutil/v3/net"
	"github.com/shirou/gopsutil/v3/process"
)

func collectListeningPorts(inv *Inventory) error {
	connections, err := netstat.Connections("inet")
	if err != nil {
		inv.PortCollectionError = err.Error()
		return nil
	}

	seen := make(map[string]bool)

	for _, conn := range connections {
		protocol := ""

		switch conn.Type {
		case 1: // SOCK_STREAM
			if !strings.EqualFold(conn.Status, "LISTEN") {
				continue
			}
			protocol = "tcp"

		case 2: // SOCK_DGRAM
			// UDP has no TCP-style LISTEN state.
			protocol = "udp"

		default:
			continue
		}

		if conn.Laddr.Port == 0 {
			continue
		}

		address := conn.Laddr.IP
		if address == "" {
			address = "0.0.0.0"
		}

		key := fmt.Sprintf("%s|%s|%d|%d",
			protocol, address, conn.Laddr.Port, conn.Pid)

		if seen[key] {
			continue
		}
		seen[key] = true

		port := ListeningPort{
			Protocol:  protocol,
			Address:   address,
			Port:      conn.Laddr.Port,
			PID:       conn.Pid,
			Service:   commonServiceName(conn.Laddr.Port),
			BindScope: classifyBindScope(address),
		}

		if conn.Pid > 0 {
			proc, err := process.NewProcess(conn.Pid)
			if err == nil {
				port.ProcessName, _ = proc.Name()
			}
		}

		inv.Ports = append(inv.Ports, port)
	}

	return nil
}

func classifyBindScope(address string) string {
	ip := net.ParseIP(address)

	if ip == nil {
		return "unknown"
	}

	if ip.IsUnspecified() {
		return "all_interfaces"
	}

	if ip.IsLoopback() {
		return "loopback"
	}

	if ip.IsPrivate() {
		return "private"
	}

	return "public_address"
}

func commonServiceName(port uint32) string {
	services := map[uint32]string{
		22:    "SSH",
		25:    "SMTP",
		53:    "DNS",
		80:    "HTTP",
		110:   "POP3",
		123:   "NTP",
		143:   "IMAP",
		443:   "HTTPS",
		465:   "SMTPS",
		587:   "SMTP Submission",
		993:   "IMAPS",
		995:   "POP3S",
		3000:  "Application",
		3306:  "MySQL",
		4000:  "Application",
		5432:  "PostgreSQL",
		5672:  "RabbitMQ",
		6379:  "Redis",
		8080:  "HTTP Alternate",
		8443:  "HTTPS Alternate",
		9090:  "Prometheus",
		9200:  "Elasticsearch",
		11211: "Memcached",
		11434: "Ollama",
	}

	if name, ok := services[port]; ok {
		return name
	}

	return "Unknown"
}
