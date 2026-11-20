package e2e

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

func TestRunner(t *testing.T) {
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"pass", "fail", "timeout"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if mode == "timeout" {
				ctx, cancel = context.WithTimeout(context.Background(), 100*time.Millisecond)
				defer cancel()
			}
			output, err := Run(ctx, binary, []string{"-test.run=^TestRunnerHelper$"}, []string{"SOAP_RUNNER_HELPER=" + mode})
			switch mode {
			case "pass":
				if err != nil || !strings.Contains(output, "synthetic output") {
					t.Fatalf("%q %v", output, err)
				}
			case "fail":
				var exit *exec.ExitError
				if !errors.As(err, &exit) || exit.ExitCode() != 99 {
					t.Fatalf("expected 99: %v", err)
				}
			case "timeout":
				if !errors.Is(err, context.DeadlineExceeded) {
					t.Fatalf("expected deadline: %v", err)
				}
			}
		})
	}
}

func TestRunnerHelper(t *testing.T) {
	switch os.Getenv("SOAP_RUNNER_HELPER") {
	case "pass":
		_, _ = os.Stdout.WriteString("synthetic output\n")
		os.Exit(0)
	case "fail":
		os.Exit(99)
	case "timeout":
		time.Sleep(10 * time.Second)
		os.Exit(0)
	}
}

func TestRunnerMissingBinary(t *testing.T) {
	if _, err := Run(context.Background(), "/nonexistent/soap-k6", nil, nil); err == nil {
		t.Fatal("missing executable succeeded")
	}
}

func TestRunnerOutputBound(t *testing.T) {
	output := &cappedOutput{}
	payload := []byte(strings.Repeat("x", 64<<10))
	for range 2 {
		n, err := output.Write(payload)
		if err != nil || n != len(payload) {
			t.Fatalf("pipe drain: %d %v", n, err)
		}
	}
	if output.Len() != 32<<10 {
		t.Fatalf("retained %d bytes", output.Len())
	}
}
