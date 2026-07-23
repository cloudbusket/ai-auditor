package inventory

func Collect() (*Inventory, error) {

	inv := &Inventory{}

	if err := collectHostname(inv); err != nil {
		return nil, err
	}

	if err := collectOS(inv); err != nil {
		return nil, err
	}

	if err := collectKernel(inv); err != nil {
		return nil, err
	}

	if err := collectCPU(inv); err != nil {
		return nil, err
	}

	if err := collectMemory(inv); err != nil {
		return nil, err
	}

	return inv, nil
}
