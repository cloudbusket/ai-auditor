package version

import "fmt"

const (
	AppName = "CloudBusket AI Auditor"
	Version = "0.1.0"
	Build   = "dev"
)

func Print() {
	fmt.Printf("%s %s (%s)\n", AppName, Version, Build)
}
