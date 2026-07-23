package inventory

import "os"

func collectHostname(inv *Inventory) error {

	h, err := os.Hostname()
	if err != nil {
		return err
	}

	inv.Hostname = h

	return nil
}
