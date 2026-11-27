//go:build k6race

package e2e

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stanimirivanov/xk6-soap/test/fixture"
)

func TestNativeK6RaceWorkload(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("../fixture", fixture.RaceCorpusFile))
	if err != nil {
		t.Fatal(err)
	}
	corpus, err := fixture.ParseRaceCorpus(data)
	if err != nil {
		t.Fatal(err)
	}
	binary, err := filepath.Abs("../../bin/k6-race")
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name                  string
		vus                   int
		iterations            int
		control               string
		wrongReply            bool
		wantExit              int
		wantVerified          int
		wantMatching          int
		wantPayloadMismatches int32
	}{
		{
			name: "all exchanges stay isolated", vus: fixture.RaceVUs, iterations: fixture.RaceIterations,
			wantVerified: 320, wantMatching: 320,
		},
		{
			name: "valid previous reply fails the marker threshold", vus: 1, iterations: 2, wrongReply: true,
			wantExit: 99, wantVerified: 2, wantMatching: 1,
		},
		{
			name: "swapped valid exchanges fail the marker threshold", vus: 1, iterations: 2, control: "swap",
			wantExit: 99, wantVerified: 2, wantMatching: 0,
		},
		{
			name: "same marker with different operation bytes fails receiver validation", vus: 1, iterations: 2, control: "different-bytes",
			wantExit: 99, wantVerified: 1, wantMatching: 1, wantPayloadMismatches: 1,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			markers := fixture.NewExchangeMarkers(tc.vus, tc.iterations)
			var payloadMismatches atomic.Int32
			firstReply := make(chan []byte, 1)
			server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, fixture.MaxBodyBytes))
				if r.Method != http.MethodPost || err != nil {
					markers.Record("")
					w.WriteHeader(http.StatusBadRequest)
					return
				}
				marker, err := corpus.MatchRequest(body)
				recorded := markers.Record(marker)
				if errors.Is(err, fixture.ErrRaceOperationMismatch) {
					payloadMismatches.Add(1)
				}
				if err != nil || !recorded {
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
				"SOAP_RACE_CONTROL=" + tc.control,
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
			if got := payloadMismatches.Load(); got != tc.wantPayloadMismatches {
				t.Errorf("receiver operation byte mismatches = %d, want %d", got, tc.wantPayloadMismatches)
			}
			wantSummary := fmt.Sprintf("RACE_REPLIES verified=%d matching=%d\n", tc.wantVerified, tc.wantMatching)
			if !strings.Contains(output, wantSummary) {
				t.Fatalf("expected %q from k6\n%s", wantSummary, output)
			}
			t.Logf("k6 exit %d, %s", tc.wantExit, strings.TrimSuffix(wantSummary, "\n"))
		})
	}
}
