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

func TestInteropBuildRetryBoundary(t *testing.T) {
	for _, tc := range []struct {
		scenario   string
		attempts   int
		assertions int
		wantOK     bool
	}{
		{"recovered", 2, 1, true},
		{"exhausted", 2, 0, false},
		{"unclassified", 1, 0, false},
		{"outer-timeout", 1, 0, false},
		{"assertion-fails", 1, 1, false},
	} {
		t.Run(tc.scenario, func(t *testing.T) {
			dir := t.TempDir()
			docker := `#!/bin/sh
set -eu
value_after() {
    flag=$1
    shift
    while [ "$#" -gt 1 ]; do
        if [ "$1" = "$flag" ]; then printf '%s' "$2"; return; fi
        shift
    done
    return 1
}
printf '%s\n' "$1" >> "$SOAP_INTEROP_TEST_DIR/trace"
case "$1" in
    build)
        test "$2" = --no-cache
        n=$(awk '/^build$/ { n++ } END { print n }' "$SOAP_INTEROP_TEST_DIR/trace")
        printf 'cold build diagnostic %s\n' "$n"
        case "$SOAP_INTEROP_TEST_SCENARIO:$n" in
            recovered:1|exhausted:*)
                printf '#9 0.300 WSS4J_TERMINAL_MAVEN_TRANSFER_RETRYABLE\n'
                printf '%s\n' 'ERROR: failed to build: failed to solve: process "/bin/sh -c sh maven-build.sh" did not complete successfully: exit code: 75'
                exit 1 ;;
            unclassified:*)
                printf '%s\n' 'Earlier Maven transfer: status code: 429' 'ERROR: failed to build: artifact not found'
                exit 1 ;;
            outer-timeout:*)
                printf '#9 0.300 WSS4J_TERMINAL_MAVEN_TRANSFER_RETRYABLE\n'
                exit 124 ;;
        esac
        printf 'fixture-image\n' > "$(value_after --iidfile "$@")" ;;
    run) printf 'fixture-container\n' > "$(value_after --cidfile "$@")" ;;
    port) printf '127.0.0.1:10000\n' ;;
    cp|logs|rm) ;;
    *) exit 98 ;;
esac
`
			goCommand := `#!/bin/sh
set -eu
printf 'assertions\n' >> "$SOAP_INTEROP_TEST_DIR/trace"
case "$*" in *"-timeout=90s"*) ;; *) exit 98 ;; esac
test "$SOAP_INTEROP_TEST_SCENARIO" != assertion-fails
`
			for name, stub := range map[string]string{"docker": docker, "go": goCommand} {
				if err := os.WriteFile(filepath.Join(dir, name), []byte(stub), 0755); err != nil {
					t.Fatal(err)
				}
			}
			cmd := exec.Command("sh", "scripts/interop.sh")
			cmd.Dir = "../.."
			cmd.Env = append(os.Environ(), "PATH="+dir+string(os.PathListSeparator)+os.Getenv("PATH"),
				"SOAP_INTEROP_TEST_DIR="+dir, "SOAP_INTEROP_TEST_SCENARIO="+tc.scenario)
			output, err := cmd.CombinedOutput()
			if (err == nil) != tc.wantOK {
				t.Errorf("interop returned %v, want success %t:\n%s", err, tc.wantOK, output)
			}
			trace, err := os.ReadFile(filepath.Join(dir, "trace"))
			if err != nil {
				t.Fatal(err)
			}
			calls := strings.Fields(string(trace))
			if strings.Count(string(trace), "build\n") != tc.attempts || strings.Count(string(trace), "assertions\n") != tc.assertions ||
				strings.Count(string(trace), "run\n") != tc.assertions || strings.Count(string(trace), "rm\n") != tc.assertions {
				t.Errorf("wrong build, start, assertion or cleanup counts: %v\n%s", calls, output)
			}
			if !strings.Contains(string(output), "cold build diagnostic 1") ||
				tc.attempts == 2 && !strings.Contains(string(output), "cold build diagnostic 2") {
				t.Errorf("missing build diagnostics: %s", output)
			}
			if tc.scenario == "assertion-fails" && !strings.Contains(string(output), "interoperability assertions failed") {
				t.Errorf("missing assertion failure stage: %s", output)
			}
		})
	}
}
