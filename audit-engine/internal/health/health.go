package health

type Result struct {
	Status string `json:"status"`
}

func Check() Result {
	return Result{
		Status: "ok",
	}
}
