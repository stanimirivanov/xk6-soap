package adapter

import (
	"context"
	"github.com/stanimirivanov/xk6-soap/internal/wssec"
	"sync"
	"testing"
	"time"

	"go.k6.io/k6/v2/js/modulestest"
	"go.k6.io/k6/v2/lib"
	"go.k6.io/k6/v2/metrics"
)

func TestMetricRegistrationAndCounts(t *testing.T) {
	rt := modulestest.NewRuntime(t)
	registry := rt.VU.InitEnvField.Registry
	root := New()
	inst := root.NewModuleInstance(rt.VU)
	rt.VU.Runtime().Set("Client", inst.Exports().Named["Client"])
	for _, tc := range []struct {
		name string
		kind metrics.MetricType
		unit metrics.ValueType
	}{
		{"soap_build_duration", metrics.Trend, metrics.Time},
		{"soap_parse_duration", metrics.Trend, metrics.Time},
		{"soap_reqs", metrics.Counter, metrics.Default},
		{"soap_req_failed", metrics.Rate, metrics.Default},
	} {
		m := registry.Get(tc.name)
		if m == nil || m.Type != tc.kind || m.Contains != tc.unit {
			t.Fatalf("missing/wrong metric %s", tc.name)
		}
	}
	before := registry.Get("soap_reqs")
	root.NewModuleInstance(rt.VU)
	if registry.Get("soap_reqs") != before {
		t.Fatal("metric redefined across VUs")
	}
	js(t, rt.VU.Runtime(), `var client=new Client({url:'https://PRIVATE.invalid'});try{client.build('Echo','<Echo/>')}catch(e){if(e.code!=='SOAP_EXECUTION_ONLY')throw e;}`)
	samples := make(chan metrics.SampleContainer, 20)
	state := &lib.State{Samples: samples, Tags: lib.NewVUStateTags(registry.RootTagSet().With("scenario", "user-scenario"))}
	rt.MoveToVUContext(state)
	js(t, rt.VU.Runtime(), `var request=client.build('Echo','<Echo>PRIVATE_BODY</Echo>');try{client.build('Echo','bad')}catch(e){}
 client.parse({status:200,body:request.body});client.parse({status:200,body:request.body});client.parse({status:0});client.parse({status:500,body:request.body});try{client.parse()}catch(e){}
 var p=client.parse({status:200,body:request.body});p.xpath('string(.)');`)
	counts := map[string]int{}
	failed := 0
	for len(samples) > 0 {
		for _, s := range (<-samples).GetSamples() {
			counts[s.Metric.Name]++
			if s.Metric.Name == "soap_req_failed" && s.Value == 1 {
				failed++
			}
			tags := s.Tags.Map()
			if tags["scenario"] != "user-scenario" || tags["soap_version"] != "1.1" || tags["security_mode"] != "plain" || len(tags) != 3 {
				t.Fatal("unexpected metric tags", tags)
			}
			if s.Value < 0 {
				t.Fatal("negative sample")
			}
		}
	}
	for name, want := range map[string]int{"soap_build_duration": 2, "soap_parse_duration": 6, "soap_reqs": 6, "soap_req_failed": 6} {
		if counts[name] != want {
			t.Fatalf("%s count=%d want %d", name, counts[name], want)
		}
	}
	if failed != 3 {
		t.Fatal("wrong failed parse count", failed)
	}
}

func TestMetricCollisionIsSanitized(t *testing.T) {
	for _, kind := range []metrics.MetricType{metrics.Counter, metrics.Trend} {
		rt := modulestest.NewRuntime(t)
		_, e := rt.VU.InitEnvField.Registry.NewMetric("soap_build_duration", kind, metrics.Time)
		if e != nil {
			t.Fatal(e)
		}
		inst := New().NewModuleInstance(rt.VU)
		rt.VU.Runtime().Set("Client", inst.Exports().Named["Client"])
		js(t, rt.VU.Runtime(), `try{new Client({url:'https://PRIVATE.invalid'});throw new Error('metric collision accepted')}catch(e){if(e.code!=='SOAP_METRIC_REGISTRATION'||String(e).includes('PRIVATE'))throw e;}`)
	}
}

func TestMetricSamplingCancellation(t *testing.T) {
	rt := modulestest.NewRuntime(t)
	rt.VU.Runtime().Set("Client", New().NewModuleInstance(rt.VU).Exports().Named["Client"])
	js(t, rt.VU.Runtime(), `var client=new Client({url:'https://example.test'});`)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	rt.VU.CtxField = ctx
	rt.MoveToVUContext(&lib.State{Samples: make(chan metrics.SampleContainer)})
	done := make(chan error, 1)
	go func() { _, e := rt.VU.Runtime().RunString(`client.build('Echo','<Echo/>')`); done <- e }()
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("sampling blocked cancellation")
	}
}

func TestMetricTagEnumsAndDurationUnits(t *testing.T) {
	rt := modulestest.NewRuntime(t)
	inst := New().NewModuleInstance(rt.VU).(*instance)
	registry := rt.VU.InitEnvField.Registry
	samples := make(chan metrics.SampleContainer, 20)
	state := &lib.State{Samples: samples, Tags: lib.NewVUStateTags(registry.RootTagSet().With("custom", "user").With("soap_version", "PRIVATE_VERSION").With("security_mode", "PRIVATE_MODE"))}
	state.Tags.Modify(func(tags *metrics.TagsAndMeta) { tags.SetMetadata("custom", "user metadata") })
	rt.MoveToVUContext(state)
	for _, tc := range []struct {
		policy wssec.Policy
		mode   string
	}{
		{wssec.Policy{}, "plain"},
		{wssec.Policy{Timestamp: &wssec.TimestampPolicy{}}, "timestamp"},
		{wssec.Policy{UsernameToken: &wssec.UsernameTokenPolicy{User: "PRIVATE", Password: "PRIVATE"}}, "username_token"},
		{wssec.Policy{Sign: &wssec.SigningPolicy{Algorithm: "PRIVATE"}}, "signed"},
		{wssec.Policy{Receive: wssec.ReceivePolicy{Signature: true}}, "signed"},
		{wssec.Policy{Sign: &wssec.SigningPolicy{}, UsernameToken: &wssec.UsernameTokenPolicy{}}, "signed_username_token"},
	} {
		inst.recordMetrics(clientConfig{url: "https://PRIVATE.invalid", version: "1.2", policy: tc.policy}, time.Now().Add(-time.Second), false, false)
		sample := (<-samples).GetSamples()[0]
		tags := sample.Tags.Map()
		if tags["soap_version"] != "1.2" || tags["security_mode"] != tc.mode || tags["custom"] != "user" || len(tags) != 3 {
			t.Fatal("unsafe metric tags", tags)
		}
		if sample.Metadata["custom"] != "user metadata" {
			t.Fatal("VU metadata lost")
		}
		if sample.Value < 1000 || sample.Value > 60000 {
			t.Fatal("duration is not milliseconds", sample.Value)
		}
	}
	if version, _ := state.Tags.GetCurrentValues().Tags.Get("soap_version"); version != "PRIVATE_VERSION" {
		t.Fatal("extension mutated VU tags")
	}
	state.Tags.Modify(func(tags *metrics.TagsAndMeta) { tags.SetTag("custom", "changed") })
	inst.recordMetrics(clientConfig{}, time.Now(), true, true)
	for _, sample := range (<-samples).GetSamples() {
		if custom, _ := sample.Tags.Get("custom"); custom != "changed" {
			t.Fatal("stale tags reused")
		}
	}
}

func TestMetricRegistrationAcrossConcurrentVUs(t *testing.T) {
	rt := modulestest.NewRuntime(t)
	root := New()
	values := make(chan *soapMetrics, 20)
	var wg sync.WaitGroup
	// VUs share the registry, never their Sobek runtime.
	runtimes := make([]*modulestest.Runtime, 20)
	for index := range runtimes {
		runtimes[index] = modulestest.NewRuntime(t)
		runtimes[index].VU.InitEnvField.Registry = rt.VU.InitEnvField.Registry
	}
	for _, runtime := range runtimes {
		wg.Add(1)
		go func() { defer wg.Done(); values <- root.NewModuleInstance(runtime.VU).(*instance).metrics }()
	}
	wg.Wait()
	close(values)
	var first *soapMetrics
	for m := range values {
		if m == nil {
			t.Fatal("concurrent registration failed")
		}
		if first == nil {
			first = m
		}
		if m != first {
			t.Fatal("metrics registered repeatedly")
		}
	}
}

type samplingContext struct {
	context.Context
	checked chan struct{}
	resume  chan struct{}
	once    sync.Once
}

func (c *samplingContext) Err() error {
	result := c.Context.Err()
	c.once.Do(func() { close(c.checked); <-c.resume })
	return result
}
func TestMetricCancellationAfterContextCheck(t *testing.T) {
	rt := modulestest.NewRuntime(t)
	inst := New().NewModuleInstance(rt.VU).(*instance)
	base, cancel := context.WithCancel(context.Background())
	defer cancel()
	ctx := &samplingContext{Context: base, checked: make(chan struct{}), resume: make(chan struct{})}
	rt.VU.CtxField = ctx
	rt.MoveToVUContext(&lib.State{Samples: make(chan metrics.SampleContainer)})
	done := make(chan struct{})
	go func() { inst.recordMetrics(clientConfig{}, time.Now(), true, false); close(done) }()
	<-ctx.checked
	cancel()
	close(ctx.resume)
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("cancellation after the context check blocked sampling")
	}
}

func TestMissingMetricRegistryErrorsAtConstruction(t *testing.T) {
	rt := modulestest.NewRuntime(t)
	rt.VU.InitEnvField.Registry = nil
	rt.VU.Runtime().Set("Client", New().NewModuleInstance(rt.VU).Exports().Named["Client"])
	js(t, rt.VU.Runtime(), `try{new Client({url:'https://example.test'});throw new Error('missing registry accepted')}catch(e){if(e.code!=='SOAP_METRIC_REGISTRATION')throw e;}`)
}

func TestMetricSecurityOutcomes(t *testing.T) {
	rt := keyRuntime(t, New())
	registry := rt.VU.InitEnvField.Registry
	js(t, rt.VU.Runtime(), `var receiver=new Client({url:'https://PRIVATE.invalid',keys:{trust:[cert]},security:{verify:{signature:true}}});`)
	rt.VU.Runtime().Set("wire", signedResponse(t, "<Echo>PRIVATE_RESPONSE</Echo>"))
	samples := make(chan metrics.SampleContainer, 10)
	rt.MoveToVUContext(&lib.State{Samples: samples})
	js(t, rt.VU.Runtime(), `receiver.parse({status:200,body:wire});receiver.parse({status:200,body:wire.replace('PRIVATE_RESPONSE','TAMPERED')});`)
	counts := map[string]int{}
	failed := 0
	for len(samples) > 0 {
		for _, sample := range (<-samples).GetSamples() {
			counts[sample.Metric.Name]++
			if sample.Metric == registry.Get("soap_req_failed") && sample.Value == 1 {
				failed++
			}
			mode, _ := sample.Tags.Get("security_mode")
			if mode != "signed" {
				t.Fatal("wrong security policy tag", mode)
			}
		}
	}
	if counts["soap_parse_duration"] != 2 || counts["soap_reqs"] != 2 || counts["soap_req_failed"] != 2 || failed != 1 {
		t.Fatal("security outcomes not instrumented", counts, failed)
	}
}
