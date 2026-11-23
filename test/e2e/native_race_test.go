//go:build k6race

package e2e

import (
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stanimirivanov/xk6-soap/test/fixture"
)

func TestNativeK6RaceWorkload(t *testing.T) {
	binary, err := filepath.Abs("../../bin/k6-race")
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name         string
		vus          int
		iterations   int
		wrongReply   bool
		wantExit     int
		wantMatching int
	}{
		{name: "all exchanges stay isolated", vus: 16, iterations: 20, wantMatching: 320},
		{name: "valid previous reply fails the marker threshold", vus: 1, iterations: 2, wrongReply: true, wantExit: 99, wantMatching: 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			markers := fixture.NewExchangeMarkers(tc.vus, tc.iterations)
			firstReply := make(chan []byte, 1)
			server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				var envelope struct {
					XMLName xml.Name `xml:"http://www.w3.org/2003/05/soap-envelope Envelope"`
					Body    struct {
						Markers []string `xml:"urn:fixture:race Echo"`
					} `xml:"http://www.w3.org/2003/05/soap-envelope Body"`
				}
				body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, fixture.MaxBodyBytes))
				if r.Method != http.MethodPost || err != nil || xml.Unmarshal(body, &envelope) != nil || len(envelope.Body.Markers) != 1 {
					markers.Record("")
					w.WriteHeader(http.StatusBadRequest)
					return
				}
				marker := envelope.Body.Markers[0]
				if !markers.Record(marker) {
					w.WriteHeader(http.StatusBadRequest)
					return
				}
				if tc.wrongReply {
					switch marker {
					case "1-0":
						firstReply <- body
					case "1-1":
						select {
						case body = <-firstReply:
						default:
							w.WriteHeader(http.StatusConflict)
							return
						}
					}
				}
				w.Header().Set("Content-Type", "application/soap+xml; charset=utf-8")
				_, _ = w.Write(body)
			}))
			server.Config.ReadTimeout = 2 * time.Second
			server.Config.WriteTimeout = 2 * time.Second
			server.Config.IdleTimeout = 2 * time.Second
			server.Start()
			t.Cleanup(server.Close)

			env := []string{
				"SOAP_RACE_URL=" + server.URL,
				"SOAP_RACE_VUS=" + strconv.Itoa(tc.vus),
				"SOAP_RACE_ITERATIONS=" + strconv.Itoa(tc.iterations),
				"GORACE=halt_on_error=1 exitcode=66 log_path=stderr",
			}
			args := []string{
				"run", "--quiet", "--no-usage-report", "--http-debug=", "--http-debug-redact=false",
				"--no-thresholds=false", "--summary-mode=compact", "--new-machine-readable-summary=false", "native_race.js",
			}
			output, err := Run(context.Background(), binary, args, env)
			if tc.wantExit != 0 {
				var exit *exec.ExitError
				if !errors.As(err, &exit) || exit.ExitCode() != tc.wantExit {
					t.Fatalf("expected k6 exit %d, got %v\n%s", tc.wantExit, err, output)
				}
			} else if err != nil {
				t.Fatalf("race-enabled k6 failed: %v\n%s", err, output)
			}
			if err := markers.Check(); err != nil {
				t.Fatal(err)
			}
			wantSummary := fmt.Sprintf("RACE_REPLIES verified=%d matching=%d\n", tc.vus*tc.iterations, tc.wantMatching)
			if !strings.Contains(output, wantSummary) {
				t.Fatalf("expected %q from k6\n%s", wantSummary, output)
			}
		})
	}
}
