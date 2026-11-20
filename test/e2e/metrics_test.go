//go:build e2e

package e2e

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestK6SOAPMetricSummary(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/xml")
		_, _ = w.Write([]byte(`<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"><s:Body><s:Fault><faultcode>s:Server</faultcode><faultstring>Synthetic fault</faultstring></s:Fault></s:Body></s:Envelope>`))
	}))
	defer server.Close()
	binary, e := filepath.Abs("../../bin/k6")
	if e != nil {
		t.Fatal(e)
	}
	for _, negative := range []bool{false, true} {
		flag := "0"
		if negative {
			flag = "1"
		}
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		output, e := Run(ctx, binary, []string{"run", "--quiet", "--no-usage-report", "metrics.js"}, []string{"SOAP_METRICS_URL=" + server.URL, "SOAP_METRICS_FAIL=" + flag})
		cancel()
		if negative {
			var exit *exec.ExitError
			if !errors.As(e, &exit) || exit.ExitCode() != 99 {
				t.Fatalf("SOAP threshold should exit 99: %v %s", e, output)
			}
		} else if e != nil {
			t.Fatalf("metric summary run: %v %s", e, output)
		}
		if strings.Contains(output, "METRIC_PRIVATE_SENTINEL") {
			t.Fatal("metric output leaked payload")
		}
		marker := "SOAP_METRICS_SUMMARY="
		pos := strings.Index(output, marker)
		if pos < 0 {
			t.Fatal("missing actual k6 summary", output)
		}
		line := strings.SplitN(output[pos+len(marker):], "\n", 2)[0]
		var summary map[string]struct {
			Type     string             `json:"type"`
			Contains string             `json:"contains"`
			Values   map[string]float64 `json:"values"`
		}
		if e = json.Unmarshal([]byte(line), &summary); e != nil {
			t.Fatal(e, output)
		}
		for name, count := range map[string]float64{"soap_build_duration": 3, "soap_parse_duration": 6, "soap_reqs": 6} {
			if summary[name].Values["count"] != count {
				t.Fatal("wrong metric count", name, summary)
			}
		}
		if summary["soap_req_failed"].Values["rate"] != 4.0/6.0 || summary["http_req_failed"].Values["rate"] != 0 {
			t.Fatal("SOAP/HTTP outcomes conflated", summary)
		}
		for _, name := range []string{"soap_build_duration", "soap_parse_duration"} {
			m := summary[name]
			if m.Type != "trend" || m.Contains != "time" || m.Values["min"] < 0 {
				t.Fatal("wrong trend units/type", m)
			}
		}
	}
}
