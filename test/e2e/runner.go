// Package e2e contains test process orchestration, never extension runtime code.
package e2e

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"time"
)

// cappedOutput retains bounded diagnostics while continuing to drain child pipes.
type cappedOutput struct{ bytes.Buffer }

func (b *cappedOutput) Write(p []byte) (int, error) {
	n := len(p)
	remaining := (32 << 10) - b.Len()
	if remaining > 0 {
		if len(p) > remaining {
			p = p[:remaining]
		}
		_, _ = b.Buffer.Write(p)
	}
	return n, nil
}

func runCommand(ctx context.Context, binary string, args, env []string) (string, error) {
	// Every child has a deadline even if a caller forgets to supply one.
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, binary, args...)
	cmd.Env = append(os.Environ(), env...)
	cmd.WaitDelay = time.Second
	output := &cappedOutput{}
	cmd.Stdout = output
	cmd.Stderr = output
	err := cmd.Run()
	if ctx.Err() != nil {
		err = ctx.Err()
	}
	if err != nil {
		return output.String(), fmt.Errorf("run %s: %w", binary, err)
	}
	return output.String(), nil
}
