package adapter

import (
	"strings"
	"testing"

	"go.k6.io/k6/v2/js/modulestest"
	"go.k6.io/k6/v2/lib"
)

func TestClientScaffold(t *testing.T) {
	rt := modulestest.NewRuntime(t)
	instance := New().NewModuleInstance(rt.VU)
	if err := rt.VU.Runtime().Set("Client", instance.Exports().Named["Client"]); err != nil {
		t.Fatal(err)
	}
	if _, err := rt.VU.Runtime().RunString(`var client = new Client({url:'http://example.test'});`); err != nil {
		t.Fatal(err)
	}
	for _, expression := range []string{`client.build()`, `client.parse()`} {
		if _, err := rt.VU.Runtime().RunString(expression); err == nil || !strings.Contains(err.Error(), "SOAP_EXECUTION_ONLY") {
			t.Fatalf("%s: got %v", expression, err)
		}
	}
	rt.MoveToVUContext(&lib.State{})
	if _, err := rt.VU.Runtime().RunString(`new Client({url:'http://example.test'})`); err == nil || !strings.Contains(err.Error(), "SOAP_INIT_ONLY") {
		t.Fatalf("execution construction: %v", err)
	}
}

func TestClientsBelongToTheirVU(t *testing.T) {
	root := New()
	for range 2 {
		rt := modulestest.NewRuntime(t)
		if err := rt.VU.Runtime().Set("Client", root.NewModuleInstance(rt.VU).Exports().Named["Client"]); err != nil {
			t.Fatal(err)
		}
		value, err := rt.VU.Runtime().RunString(`const a = new Client({url:'http://example.test'}); const b = new Client({url:'http://example.test'}); a.marker = 1; b.marker === undefined && a instanceof Client;`)
		if err != nil || !value.ToBoolean() {
			t.Fatalf("client isolation/prototype contract failed: %v", err)
		}
	}
}
