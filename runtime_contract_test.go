package soap

import (
	"context"
	"go.k6.io/k6/v2/js/modules"
	"testing"
	"time"

	"go.k6.io/k6/v2/js/modulestest"
	"go.k6.io/k6/v2/lib"
	"go.k6.io/k6/v2/metrics"
)

func TestMetricRuntimeContract(t *testing.T) {
	rt := modulestest.NewRuntime(t)
	registry := rt.VU.InitEnv().Registry
	metric, err := registry.NewMetric("soap_probe_duration", metrics.Trend, metrics.Time)
	if err != nil {
		t.Fatal(err)
	}
	same, err := registry.NewMetric("soap_probe_duration", metrics.Trend, metrics.Time)
	if err != nil || same != metric {
		t.Fatalf("registration is not shared: %v", err)
	}
	if _, err := registry.NewMetric("soap_probe_duration", metrics.Counter); err == nil {
		t.Fatal("conflicting metric accepted")
	}
	emit := metricProbe(rt.VU, metric)
	if emit(3) {
		t.Fatal("emitted in init context")
	}
	output := make(chan metrics.SampleContainer, 1)
	rt.MoveToVUContext(&lib.State{Samples: output})
	if !emit(3.5) {
		t.Fatal("sample not emitted")
	}
	sample := (<-output).GetSamples()[0]
	if sample.Metric != metric || sample.Value != 3.5 || sample.Tags != registry.RootTagSet() {
		t.Fatalf("sample contract: %+v", sample)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	rt.VU.CtxField = ctx
	if emit(9) || len(output) != 0 {
		t.Fatal("emitted after cancellation")
	}
}

// metricProbe validates the integration seam without registering production metrics
// before the metrics feature task. Each closure retains only its owning VU.
func metricProbe(vu modules.VU, metric *metrics.Metric) func(float64) bool {
	tags := vu.InitEnv().Registry.RootTagSet()
	return func(value float64) bool {
		state := vu.State()
		if state == nil {
			return false
		}
		return metrics.PushIfNotDone(vu.Context(), state.Samples, metrics.Sample{
			TimeSeries: metrics.TimeSeries{Metric: metric, Tags: tags}, Time: time.Now(), Value: value,
		})
	}
}
