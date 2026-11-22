package cmd

type exitCodeError struct {
	code    int
	message string
}

func (e *exitCodeError) Error() string {
	return e.message
}
