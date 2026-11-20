package archtest

import (
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func TestInteropRequiresColdDockerBuild(t *testing.T) {
	root, e := filepath.Abs("../..")
	if e != nil {
		t.Fatal(e)
	}
	dir := t.TempDir()
	fake := `#!/bin/sh
printf '%s\n' "$*" > "$SOAP_DOCKER_TRACE"
exit 73
`
	if e = os.WriteFile(filepath.Join(dir, "docker"), []byte(fake), 0755); e != nil {
		t.Fatal(e)
	}
	trace := filepath.Join(dir, "trace")
	cmd := exec.Command("sh", "scripts/interop.sh")
	cmd.Dir = root
	cmd.Env = append(os.Environ(), "PATH="+dir+string(os.PathListSeparator)+os.Getenv("PATH"), "SOAP_DOCKER_TRACE="+trace)
	output, e := cmd.CombinedOutput()
	status, ok := e.(*exec.ExitError)
	if !ok || status.ExitCode() != 73 {
		t.Fatalf("Docker failure not propagated: %v %s", e, output)
	}
	b, e := os.ReadFile(trace)
	if e != nil {
		t.Fatal(e)
	}
	args := strings.Fields(string(b))
	if len(args) == 0 || args[0] != "build" || !slices.Contains(args, "--no-cache") {
		t.Fatal("interop did not request a cold build", args)
	}
}
