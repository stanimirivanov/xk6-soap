package archtest

import (
	"encoding/xml"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestMavenBuildRecovery(t *testing.T) {
	for _, tc := range []struct {
		scenario string
		exit     int
		calls    int
		fallback bool
	}{
		{"success", 0, 2, false},
		{"missing-once", 0, 3, true},
		{"missing-always", 17, 2, true},
		{"central-429-once", 0, 3, true},
		{"central-429-always", 18, 2, true},
		{"other-429", 18, 1, false},
		{"validation-error", 9, 1, false},
		{"transfer-error", 18, 1, false},
		{"model-error", 19, 1, false},
		{"build-with-bom-text", 23, 2, false},
		{"build-error", 23, 2, false},
	} {
		t.Run(tc.scenario, func(t *testing.T) {
			dir := t.TempDir()
			fake := `#!/bin/sh
set -eu
n=0
if [ -f "$SOAP_MAVEN_TEST_DIR/count" ]; then n=$(cat "$SOAP_MAVEN_TEST_DIR/count"); fi
n=$((n+1))
printf '%s' "$n" > "$SOAP_MAVEN_TEST_DIR/count"
printf '%s\n' "$*" >> "$SOAP_MAVEN_TEST_DIR/calls"
case "$*" in
 *validate*)
  case "$SOAP_MAVEN_TEST_SCENARIO" in
   missing-always) missing=true ;;
   missing-once) if [ "$n" -eq 1 ]; then missing=true; else missing=false; fi ;;
   central-429-*)
    if [ "$n" -eq 1 ] || [ "$SOAP_MAVEN_TEST_SCENARIO" = central-429-always ]; then
     repository='central (https://repo.maven.apache.org/maven2)'
     if [ "$n" -gt 1 ]; then repository='central-fallback (https://maven-central.storage-download.googleapis.com/maven2/)'; fi
     printf '[ERROR] Non-resolvable import POM: The following artifacts could not be resolved: org.apache.cxf:cxf-bom:pom:4.2.4 (absent): Could not transfer artifact org.apache.cxf:cxf-bom:pom:4.2.4 from/to %s: status code: 429, reason phrase: Too Many Requests (429) @ line 6, column 17\n' "$repository"
     exit 18
    fi
    missing=false ;;
   other-429)
    printf '[ERROR] Non-resolvable import POM: Could not transfer artifact test:bom:pom:1 from/to other (https://repo.example.test): status code: 429, reason phrase: Too Many Requests (429)\n'
    exit 18 ;;
   validation-error) printf '[ERROR] BannedDependencies: WSS4J versions differ\n'; exit 9 ;;
   transfer-error) printf '[ERROR] Non-resolvable import POM: Could not transfer artifact: HTTP 403\n'; exit 18 ;;
   model-error) printf '[ERROR] Non-resolvable import POM: invalid version\n'; exit 19 ;;
   *) missing=false ;;
  esac
  if "$missing"; then
   printf '[ERROR] Non-resolvable import POM: Could not find artifact org.apache.cxf:cxf-bom:pom:4.2.4 in central (https://repo.maven.apache.org/maven2)\n'
   exit 17
  fi ;;
 *package*) if [ "$SOAP_MAVEN_TEST_SCENARIO" = build-with-bom-text ]; then printf '[ERROR] Non-resolvable import POM: Could not find artifact\n'; exit 23; fi; if [ "$SOAP_MAVEN_TEST_SCENARIO" = build-error ]; then printf '[ERROR] Tests failed\n'; exit 23; fi ;;
 *) exit 98 ;;
esac
`
			if e := os.WriteFile(filepath.Join(dir, "mvn"), []byte(fake), 0755); e != nil {
				t.Fatal(e)
			}
			script, e := filepath.Abs("../../test/interop/wss4j/maven-build.sh")
			if e != nil {
				t.Fatal(e)
			}
			cmd := exec.Command("sh", script)
			cmd.Env = append(os.Environ(), "PATH="+dir+string(os.PathListSeparator)+os.Getenv("PATH"), "SOAP_MAVEN_TEST_DIR="+dir, "SOAP_MAVEN_TEST_SCENARIO="+tc.scenario)
			output, e := cmd.CombinedOutput()
			exit := 0
			if e != nil {
				if status, ok := e.(*exec.ExitError); ok {
					exit = status.ExitCode()
				} else {
					t.Fatal(e)
				}
			}
			if exit != tc.exit {
				t.Fatalf("exit=%d want %d: %s", exit, tc.exit, output)
			}
			b, e := os.ReadFile(filepath.Join(dir, "calls"))
			if e != nil {
				t.Fatal(e)
			}
			calls := strings.Split(strings.TrimSpace(string(b)), "\n")
			if len(calls) != tc.calls {
				t.Fatalf("wrong invocation count: %q", calls)
			}
			for i, line := range calls {
				if strings.Contains(line, "validate") && !strings.Contains(line, "-U") {
					t.Fatal("resolution must bypass Maven's negative cache", line)
				}
				fallback := strings.Contains(line, "central-fallback.xml")
				if fallback != (tc.fallback && i > 0) {
					t.Fatal("wrong endpoint selection", calls)
				}
			}
			if tc.exit == 0 && !strings.Contains(calls[len(calls)-1], "package dependency:copy-dependencies") {
				t.Fatal("successful recovery skipped the build", calls)
			}
		})
	}
}

func TestMavenFallbackSettings(t *testing.T) {
	b, e := os.ReadFile("../../test/interop/wss4j/central-fallback.xml")
	if e != nil {
		t.Fatal(e)
	}
	var settings struct {
		Mirrors []struct {
			ID       string `xml:"id"`
			MirrorOf string `xml:"mirrorOf"`
			URL      string `xml:"url"`
		} `xml:"mirrors>mirror"`
	}
	if e = xml.Unmarshal(b, &settings); e != nil {
		t.Fatal(e)
	}
	if len(settings.Mirrors) != 1 || settings.Mirrors[0].MirrorOf != "central" || settings.Mirrors[0].URL != "https://maven-central.storage-download.googleapis.com/maven2/" {
		t.Fatal("fallback must use only the independently hosted HTTPS Central mirror", settings)
	}
}
