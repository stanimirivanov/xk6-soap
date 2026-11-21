// Package perf runs synthetic, transport-free benchmarks for the SOAP boundary.
package perf

import (
	"crypto/rand"
	_ "embed"
	"encoding/json"
	"fmt"
	"os"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/stanimirivanov/xk6-soap/internal/keys"
	"github.com/stanimirivanov/xk6-soap/internal/message"
	"github.com/stanimirivanov/xk6-soap/internal/wssec"
)

//go:embed workload.json
var workloadJSON []byte

type workloadSettings struct {
	PayloadBytes int      `json:"payload_bytes"`
	Modes        []string `json:"modes"`
	Retention    struct {
		Warmup  int `json:"warmup_iterations"`
		Window  int `json:"iterations_per_window"`
		Windows int `json:"windows"`
		GC      int `json:"gc_cycles_per_sample"`
	}
}

func settings(t testing.TB) workloadSettings {
	t.Helper()
	var settings workloadSettings
	if err := json.Unmarshal(workloadJSON, &settings); err != nil {
		t.Fatal(err)
	}
	if settings.PayloadBytes != 2048 || len(settings.Modes) != 4 || settings.Retention.Warmup <= 0 || settings.Retention.Window <= 0 || settings.Retention.Windows <= 0 || settings.Retention.GC <= 0 {
		t.Fatal("invalid performance workload settings")
	}
	return settings
}

type workload struct {
	policy   wssec.Policy
	material wssec.KeyMaterial
	now      time.Time
	payload  string
}

func fixture(t testing.TB) keys.Input {
	t.Helper()
	cert, err := os.ReadFile("../../internal/wssec/testdata/signing-cert.pem")
	if err != nil {
		t.Fatal(err)
	}
	key, err := os.ReadFile("../../internal/wssec/testdata/signing-key.pem")
	if err != nil {
		t.Fatal(err)
	}
	return keys.Input{Cert: cert, Key: key}
}

func newWorkload(t testing.TB, mode string) workload {
	t.Helper()
	size := settings(t).PayloadBytes
	w := workload{now: time.Now().UTC(), payload: "<Echo>" + strings.Repeat("x", size-len("<Echo></Echo>")) + "</Echo>"}
	options := wssec.SecurityOptions{}
	if mode != "plain" {
		m, err := keys.NewCache().Load(fixture(t), keys.Signing, w.now)
		if err != nil {
			t.Fatal(err)
		}
		w.material = wssec.KeyMaterial{Signing: m, Trust: []*keys.Material{m}}
		options.Sign = &wssec.SigningPolicy{}
		if mode == "ste" || mode == "ets" {
			order := wssec.SignThenEncrypt
			if mode == "ets" {
				order = wssec.EncryptThenSign
			}
			w.material.Recipient = m
			w.material.Decryption = m
			required := true
			options.Encrypt = &wssec.EncryptionPolicy{}
			options.Order = string(order)
			options.Verify = &wssec.ReceiveOptions{Order: string(order), RequireEncryption: &required}
		}
	}
	var err error
	w.policy, err = wssec.CompilePolicy(options, w.material, w.now)
	if err != nil {
		t.Fatal(err)
	}
	return w
}

func (w workload) build(t testing.TB) string {
	t.Helper()
	request, err := message.Build("Echo", w.payload, message.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if w.policy.Sign == nil {
		return request.Body
	}
	wire, err := wssec.BuildSecurity([]byte(request.Body), w.policy, w.material, w.now, rand.Reader, nil, message.Limits{})
	if err != nil {
		t.Fatal(err)
	}
	return string(wire)
}

func (w workload) parse(t testing.TB, wire string) {
	t.Helper()
	result := wssec.ReceiveWithKeys(200, wire, "1.1", message.Limits{}, w.policy.Receive, w.material, w.now)
	if !result.OK {
		t.Fatal(result.Error)
	}
}

func BenchmarkSOAP(b *testing.B) {
	for _, mode := range settings(b).Modes {
		w := newWorkload(b, mode)
		wire := w.build(b)
		w.parse(b, wire)
		b.Run(mode+"/build", func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				w.build(b)
			}
		})
		b.Run(mode+"/parse", func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				w.parse(b, wire)
			}
		})
	}
}

func BenchmarkColdPEMKeyInit(b *testing.B) {
	input := fixture(b)
	now := time.Now()
	b.ReportAllocs()
	for b.Loop() {
		if _, err := keys.NewCache().Load(input, keys.Signing, now); err != nil {
			b.Fatal(err)
		}
	}
}

type retentionSample struct {
	HeapBytes  uint64 `json:"heap_bytes"`
	Goroutines int    `json:"goroutines"`
}

func snapshot(cycles int) retentionSample {
	for range cycles {
		runtime.GC()
	}
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	return retentionSample{HeapBytes: m.HeapAlloc, Goroutines: runtime.NumGoroutine()}
}

func TestRetention(t *testing.T) {
	if os.Getenv("XK6_PERF_RETENTION") != "1" {
		t.Skip("run make bench for the isolated retention profile")
	}
	config := settings(t)
	for _, mode := range config.Modes {
		t.Run(mode, func(t *testing.T) {
			w := newWorkload(t, mode)
			work := func(count int) {
				for range count {
					w.parse(t, w.build(t))
				}
			}
			work(config.Retention.Warmup)
			samples := []retentionSample{snapshot(config.Retention.GC)}
			for range config.Retention.Windows {
				work(config.Retention.Window)
				samples = append(samples, snapshot(config.Retention.GC))
			}
			runtime.KeepAlive(w)
			record, err := json.Marshal(samples)
			if err != nil {
				t.Fatal(err)
			}
			fmt.Printf("RETENTION %s %s\n", mode, record)
		})
	}
}
