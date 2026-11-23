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
		scenario  string
		exit      int
		endpoints string
	}{
		{"success", 0, "central central"},
		{"missing-once", 0, "central americas americas"},
		{"missing-always", 17, "central americas"},
		{"central-429-once", 0, "central americas americas"},
		{"central-429-always", 75, "central americas eu"},
		{"earlier-429-terminal-missing", 17, "central americas"},
		{"packaging-transfer", 75, "central central"},
		{"packaging-multiline", 75, "central central"},
		{"packaging-descriptor", 75, "central central"},
		{"packaging-mixed", 23, "central central"},
		{"packaging-aggregate", 23, "central central"},
		{"packaging-other-repo", 23, "central central"},
		{"regional-after-timeout", 0, "central americas eu eu"},
		{"regional-timeout", 124, "central americas eu"},
		{"mirror-model-error", 19, "central americas"},
		{"primary-timeout", 0, "central americas americas"},
		{"other-429", 18, "central"},
		{"validation-error", 9, "central"},
		{"transfer-error", 18, "central"},
		{"model-error", 19, "central"},
		{"build-with-bom-text", 23, "central central"},
		{"build-error", 23, "central central"},
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
   primary-timeout) if [ "$n" -eq 1 ]; then exit 124; fi; missing=false ;;
   regional-*|mirror-model-error)
    if [ "$n" -eq 2 ]; then
     if [ "$SOAP_MAVEN_TEST_SCENARIO" = mirror-model-error ]; then
      printf '[ERROR] BannedDependencies: WSS4J versions differ\n'; exit 19
     fi
     printf '[INFO] Building wss4j-fixture 0.0.1\n'; exit 124
    fi
    if [ "$n" -eq 3 ] && [ "$SOAP_MAVEN_TEST_SCENARIO" = regional-timeout ]; then exit 124; fi
    if [ "$n" -eq 1 ]; then missing=true; else missing=false; fi ;;
   earlier-429-terminal-missing)
    if [ "$n" -eq 2 ]; then
     printf '[ERROR] Non-resolvable import POM: Could not find artifact test:bom:pom:1 in google-maven-central\n'
     exit 17
    fi
    printf '[ERROR] Non-resolvable import POM: Could not transfer artifact test:bom:pom:1 from/to central (https://repo.maven.apache.org/maven2): status code: 429\n'
    exit 18 ;;
   central-429-*)
    if [ "$n" -eq 1 ] || [ "$SOAP_MAVEN_TEST_SCENARIO" = central-429-always ]; then
     repository='central (https://repo.maven.apache.org/maven2)'
     if [ "$n" -gt 1 ]; then repository='google-maven-central (https://maven-central.storage-download.googleapis.com/maven2/)'; fi
     if [ "$n" -eq 3 ]; then repository='google-maven-central-eu (https://maven-central-eu.storage-download.googleapis.com/maven2/)'; fi
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
 *package*)
  case "$SOAP_MAVEN_TEST_SCENARIO" in
   packaging-multiline)
    printf '%s\n' \
     '[ERROR] Failed to execute goal on project wss4j-fixture: Could not resolve dependencies for project test:wss4j-fixture:jar:1' \
     '[ERROR] dependency: test:dep:jar:1 (compile)' \
     '[ERROR]     Could not transfer artifact test:dep:jar:1 from/to central (https://repo.maven.apache.org/maven2): status code: 504, reason phrase: Gateway Timeout (504)' \
     '[ERROR] -> [Help 1]'
    exit 23 ;;
   packaging-descriptor)
    printf '%s\n' \
     '[ERROR] Failed to execute goal on project wss4j-fixture: Could not collect dependencies for project test:wss4j-fixture:jar:1' \
     '[ERROR] Failed to read artifact descriptor for test:dep:jar:1' \
     '[ERROR]     Could not transfer artifact test:dep:pom:1 from/to central (https://repo.maven.apache.org/maven2): status code: 502' \
     '[ERROR] -> [Help 1]'
    exit 23 ;;
   packaging-aggregate)
    printf '%s\n' '[ERROR] The following artifacts could not be resolved: test:dep:jar:1 (absent), test:missing:jar:1 (absent): Could not transfer artifact test:dep:jar:1 from/to central (https://repo.maven.apache.org/maven2): status code: 503'
    exit 23 ;;
   packaging-*)
    repository='central (https://repo.maven.apache.org/maven2)'
    if [ "$SOAP_MAVEN_TEST_SCENARIO" = packaging-other-repo ]; then repository='other (https://repo.example.test)'; fi
    printf '[ERROR] Failed to execute goal on project wss4j-fixture: Could not resolve dependencies: Could not transfer artifact test:dep:jar:1 from/to %s: status code: 503, reason phrase: Service Unavailable (503) -> [Help 1]\n' "$repository"
    if [ "$SOAP_MAVEN_TEST_SCENARIO" = packaging-mixed ]; then
     printf '[ERROR] Could not find artifact test:missing:jar:1 in central\n'
    fi
    exit 23 ;;
  esac
  if [ "$SOAP_MAVEN_TEST_SCENARIO" = build-with-bom-text ]; then printf '[ERROR] Non-resolvable import POM: Could not find artifact\n'; exit 23; fi; if [ "$SOAP_MAVEN_TEST_SCENARIO" = build-error ]; then printf '[ERROR] Tests failed\n'; exit 23; fi ;;
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
			if strings.Contains(string(output), "WSS4J_TERMINAL_MAVEN_TRANSFER_RETRYABLE") != (tc.exit == 75) {
				t.Errorf("wrong retry classification: %s", output)
			}
			if exit != tc.exit {
				t.Fatalf("exit=%d want %d: %s", exit, tc.exit, output)
			}
			b, e := os.ReadFile(filepath.Join(dir, "calls"))
			if e != nil {
				t.Fatal(e)
			}
			calls := strings.Split(strings.TrimSpace(string(b)), "\n")
			endpoints := strings.Fields(tc.endpoints)
			if len(calls) != len(endpoints) {
				t.Fatalf("wrong invocation count: %q", calls)
			}
			for i, line := range calls {
				if strings.Contains(line, "validate") && !strings.Contains(line, "-U") {
					t.Fatal("resolution must bypass Maven's negative cache", line)
				}
				endpoint := "central"
				switch {
				case strings.Contains(line, "central-fallback-eu.xml"):
					endpoint = "eu"
				case strings.Contains(line, "central-fallback.xml"):
					endpoint = "americas"
				}
				if endpoint != endpoints[i] {
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
	for filename, url := range map[string]string{
		"central-fallback.xml":    "https://maven-central.storage-download.googleapis.com/maven2/",
		"central-fallback-eu.xml": "https://maven-central-eu.storage-download.googleapis.com/maven2/",
	} {
		b, e := os.ReadFile(filepath.Join("../../test/interop/wss4j", filename))
		if e != nil {
			t.Fatal(e)
		}
		var settings struct {
			Mirrors []struct {
				MirrorOf string `xml:"mirrorOf"`
				URL      string `xml:"url"`
			} `xml:"mirrors>mirror"`
		}
		if e = xml.Unmarshal(b, &settings); e != nil {
			t.Fatal(e)
		}
		if len(settings.Mirrors) != 1 || settings.Mirrors[0].MirrorOf != "central" || settings.Mirrors[0].URL != url {
			t.Fatal("unexpected Central mirror", filename, settings)
		}
	}
}
