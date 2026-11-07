package cmd

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"

	"github.com/cloudbusket/ai-auditor/audit-engine/internal/appsec"
)

func prepareSnyk(
	ctx context.Context,
	input io.Reader,
	output io.Writer,
	errorOutput io.Writer,
	interactive bool,
) (*appsec.SnykScanner, error) {
	scanner := &appsec.SnykScanner{}

	if scanner.Available(ctx) {
		return scanner, nil
	}

	if !interactive {
		return scanner, nil
	}

	fmt.Fprintln(errorOutput, "\nSnyk CLI is not installed.")
	fmt.Fprintln(errorOutput, "Install command: npm install --global snyk")
	fmt.Fprint(errorOutput, "Install Snyk CLI now? [y/N]: ")

	reader := bufio.NewReader(input)
	answer, readErr := reader.ReadString('\n')

	if readErr != nil && readErr != io.EOF {
		return nil, fmt.Errorf("unable to read installation choice: %w", readErr)
	}

	if !strings.EqualFold(strings.TrimSpace(answer), "y") &&
		!strings.EqualFold(strings.TrimSpace(answer), "yes") {
		fmt.Fprintln(output, "Snyk installation declined; application security scan skipped.")
		return scanner, nil
	}

	npmPath, err := exec.LookPath("npm")
	if err != nil {
		return nil, fmt.Errorf(
			"npm is not installed; install Node.js/npm first, then run: npm install --global snyk",
		)
	}

	fmt.Fprintln(output, "\nInstalling Snyk CLI...")

	install := exec.CommandContext(
		ctx,
		npmPath,
		"install",
		"--global",
		"snyk",
	)
	install.Stdout = output
	install.Stderr = errorOutput

	if err := install.Run(); err != nil {
		return nil, fmt.Errorf("Snyk installation failed: %w", err)
	}

	if !scanner.Available(ctx) {
		return nil, fmt.Errorf(
			"Snyk installation completed, but the CLI was not found in PATH; reopen the shell and try again",
		)
	}

	fmt.Fprintln(output, "\nSnyk CLI installed successfully.")
	fmt.Fprintln(output, "Authenticate before scanning: snyk auth")

	return scanner, nil
}

func isInteractiveInput(input io.Reader) bool {
	file, ok := input.(*os.File)
	if !ok {
		return false
	}

	info, err := file.Stat()
	if err != nil {
		return false
	}

	return info.Mode()&os.ModeCharDevice != 0
}
