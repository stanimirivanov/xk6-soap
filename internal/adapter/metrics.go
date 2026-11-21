package adapter

import (
	"time"

	"github.com/stanimirivanov/xk6-soap/internal/wssec"
	"go.k6.io/k6/v2/metrics"
)

type soapMetrics struct {
	registry *metrics.Registry
	build    *metrics.Metric
	parse    *metrics.Metric
	requests *metrics.Metric
	failed   *metrics.Metric
}

// Registration is serialized per module and cached per k6-owned registry. A
// name found before registration is rejected, even if its type matches.
func (r *RootModule) registerMetrics(registry *metrics.Registry) *soapMetrics {
	if registry == nil {
		return nil
	}
	r.metricsMu.Lock()
	defer r.metricsMu.Unlock()
	if m := r.metrics[registry]; m != nil {
		return m
	}
	specs := []struct {
		name string
		kind metrics.MetricType
		unit metrics.ValueType
	}{
		{"soap_build_duration", metrics.Trend, metrics.Time},
		{"soap_parse_duration", metrics.Trend, metrics.Time},
		{"soap_reqs", metrics.Counter, metrics.Default},
		{"soap_req_failed", metrics.Rate, metrics.Default},
	}
	for _, existing := range registry.All() {
		for _, spec := range specs {
			if existing.Name == spec.name {
				return nil
			}
		}
	}
	created := make([]*metrics.Metric, 0, len(specs))
	for _, spec := range specs {
		m, e := registry.NewMetric(spec.name, spec.kind, spec.unit)
		if e != nil {
			return nil
		}
		created = append(created, m)
	}
	m := &soapMetrics{registry: registry, build: created[0], parse: created[1], requests: created[2], failed: created[3]}
	if r.metrics == nil {
		r.metrics = make(map[*metrics.Registry]*soapMetrics)
	}
	r.metrics[registry] = m
	return m
}

// These describe configured policy, not successful authentication. Values never
// originate from operation names, addresses, credentials or received XML.
func metricSecurityMode(p wssec.Policy) string {
	if p.Sign != nil || p.Receive.Signature {
		if p.UsernameToken != nil {
			return "signed_username_token"
		}
		return "signed"
	}
	if p.UsernameToken != nil {
		return "username_token"
	}
	if p.Timestamp != nil {
		return "timestamp"
	}
	return "plain"
}
func metricVersion(version string) string {
	if version == "1.2" {
		return "1.2"
	}
	return "1.1"
}

func (i *instance) recordMetrics(cfg clientConfig, start time.Time, parse bool, ok bool) {
	state := i.vu.State()
	if i.metrics == nil || state == nil || state.Samples == nil || i.vu.Context().Err() != nil {
		return
	}
	snapshot := metrics.TagsAndMeta{Tags: i.metrics.registry.RootTagSet()}
	if state.Tags != nil {
		snapshot = state.Tags.GetCurrentValues()
	}
	tags := snapshot.Tags.With("soap_version", metricVersion(cfg.version)).With("security_mode", metricSecurityMode(cfg.policy))
	now := time.Now()
	sample := func(metric *metrics.Metric, value float64) metrics.Sample {
		return metrics.Sample{TimeSeries: metrics.TimeSeries{Metric: metric, Tags: tags}, Time: now, Value: value, Metadata: snapshot.Metadata}
	}
	var batch metrics.Samples
	if parse {
		failure := 0.0
		if !ok {
			failure = 1
		}
		batch = metrics.Samples{sample(i.metrics.parse, metrics.D(now.Sub(start))), sample(i.metrics.requests, 1), sample(i.metrics.failed, failure)}
	} else {
		batch = metrics.Samples{sample(i.metrics.build, metrics.D(now.Sub(start)))}
	}
	// The pinned PushIfNotDone performs a blocking send after checking ctx.Err.
	// A select also handles cancellation that arrives while the output is blocked.
	select {
	case state.Samples <- batch:
	case <-i.vu.Context().Done():
	}
}
