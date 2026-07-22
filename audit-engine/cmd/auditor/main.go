package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/cloudbusket/ai-auditor/audit-engine/internal/health"
	"github.com/cloudbusket/ai-auditor/audit-engine/internal/inventory"
	"github.com/cloudbusket/ai-auditor/audit-engine/internal/version"
)

func main() {

	showVersion := flag.Bool("version", false, "Print version")
	showHealth := flag.Bool("health", false, "Health check")
	showInventory := flag.Bool("inventory", false, "Collect inventory")

	flag.Parse()

	switch {

	case *showVersion:

		version.Print()
		return

	case *showHealth:

		result := health.Check()

		output(result)

		return

	case *showInventory:

		info, err := inventory.Collect()
		if err != nil {

			fmt.Println(err)
			os.Exit(1)

		}

		output(info)

		return

	default:

		flag.Usage()

	}
}

func output(v interface{}) {

	b, _ := json.MarshalIndent(v, "", "  ")

	fmt.Println(string(b))

}
