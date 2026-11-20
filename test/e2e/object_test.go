//go:build e2e

package e2e

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stanimirivanov/xk6-soap/test/fixture"
)

func TestK6ObjectPayloadEcho(t *testing.T) {
	server := fixture.Start(t)
	binary, e := filepath.Abs("../../bin/k6")
	if e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	output, e := Run(ctx, binary, []string{"run", "--quiet", "--no-usage-report", "object.js"}, []string{"SOAP_FIXTURE_URL=" + server.URL})
	if e != nil {
		t.Fatalf("object echo: %v %s", e, output)
	}
	if strings.Contains(output, "OBJECT_PRIVATE_SENTINEL") {
		t.Fatal("object payload leaked into diagnostics")
	}
	captures := server.Captures()
	if len(captures) != 2 {
		t.Fatal("wrong HTTP request count", len(captures))
	}
	for _, capture := range captures {
		if capture.Path != "/echo" || !strings.Contains(capture.Body, `<a>one</a><a>two</a>`) {
			t.Fatal("object request did not reach echo fixture")
		}
	}
}
