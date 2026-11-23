package archtest

import (
	"os"
	"os/exec"
	"slices"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

func TestRequiredCICheck(t *testing.T) {
	var workflow struct {
		On   map[string]map[string]any `yaml:"on"`
		Jobs map[string]struct {
			Name            string
			If              string
			Needs           []string
			ContinueOnError any `yaml:"continue-on-error"`
			Steps           []struct {
				If              string
				Shell           string
				Run             string
				Env             map[string]string
				ContinueOnError any `yaml:"continue-on-error"`
			}
		}
	}
	source, err := os.ReadFile("../../.github/workflows/ci.yml")
	if err != nil {
		t.Fatal(err)
	}
	if err = yaml.Unmarshal(source, &workflow); err != nil {
		t.Fatal(err)
	}
	pr, exists := workflow.On["pull_request"]
	if !exists || len(pr) != 0 {
		t.Fatal("CI must run on every pull request without event filters")
	}
	expected := []string{"interop", "k6-race", "quality", "runtime", "vulnerabilities"}
	gate, exists := workflow.Jobs["required-ci"]
	slices.Sort(gate.Needs)
	if !exists || gate.Name != "required-ci" || !slices.Equal(gate.Needs, expected) ||
		gate.If != "${{ always() && !cancelled() }}" || gate.ContinueOnError != nil || len(gate.Steps) != 1 {
		t.Fatal("required-ci must evaluate all five direct dependencies and permit workflow cancellation")
	}
	evaluation := gate.Steps[0]
	if evaluation.If != "" || evaluation.Shell != "bash" || evaluation.Run == "" ||
		evaluation.ContinueOnError != nil {
		t.Fatal("the required-ci result evaluator must run without a separate condition")
	}

	results := make([]string, 0, len(expected))
	for _, job := range expected {
		dependency, exists := workflow.Jobs[job]
		if !exists || dependency.ContinueOnError != nil {
			t.Fatalf("required dependency %s is missing or permits failure", job)
		}
		for _, step := range dependency.Steps {
			if step.ContinueOnError != nil {
				t.Fatalf("required dependency %s has a step that permits failure", job)
			}
		}
		name := strings.ToUpper(strings.ReplaceAll(job, "-", "_")) + "_RESULT"
		if evaluation.Env[name] != "${{ needs."+job+".result }}" {
			t.Fatalf("required-ci must read the result of %s directly", job)
		}
		results = append(results, name)
	}

	evaluate := func(t *testing.T, override, value string, wantOK bool, diagnostic string) {
		t.Helper()
		cmd := exec.Command("bash", "-eo", "pipefail", "-c", evaluation.Run)
		cmd.Env = []string{}
		for _, name := range results {
			cmd.Env = append(cmd.Env, name+"=success")
		}
		if override != "" {
			cmd.Env = append(cmd.Env, override+"="+value)
		}
		output, err := cmd.CombinedOutput()
		if (err == nil) != wantOK || !strings.Contains(string(output), diagnostic) {
			t.Fatalf("gate returned %v, want success %t and diagnostic %q:\n%s", err, wantOK, diagnostic, output)
		}
	}
	t.Run("all succeeded", func(t *testing.T) {
		evaluate(t, "", "", true, "All required jobs succeeded")
	})
	for _, result := range results {
		for _, value := range []string{"failure", "skipped", "cancelled", "", "neutral", "unexpected=success"} {
			t.Run(result+"="+value, func(t *testing.T) {
				evaluate(t, result, value, false, "Required jobs did not succeed")
			})
		}
	}
}
