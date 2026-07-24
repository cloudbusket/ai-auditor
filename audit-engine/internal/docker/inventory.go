package docker

// Collect gathers Docker inventory.
func Collect() (*Inventory, error) {

	inv := &Inventory{}

	if err := collectVersion(inv); err != nil {
		// Docker may not be installed.
		return inv, nil
	}

	// These will be implemented later.
	_ = collectImages(inv)
	_ = collectContainers(inv)
	_ = collectNetworks(inv)
	_ = collectVolumes(inv)

	return inv, nil
}
