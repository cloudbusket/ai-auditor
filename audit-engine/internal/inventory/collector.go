package inventory

func Collect() (*Inventory, error) {

	inv := &Inventory{}

	collectors := []func(*Inventory) error{
		collectHostname,
		collectOS,
		collectKernel,
		collectCPU,
		collectMemory,
		collectDisk,
		collectNetwork,
		collectVirtualization,
	}

	for _, c := range collectors {
		if err := c(inv); err != nil {
			// Optional collectors can return nil internally.
			return nil, err
		}
	}

	return inv, nil
}
