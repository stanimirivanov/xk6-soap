// Package soap registers the k6 SOAP extension. SOAP behavior is not implemented yet.
package soap

import (
	"github.com/grafana/sobek"
	"go.k6.io/k6/v2/js/modules"
)

func init() { modules.Register("k6/x/soap", New()) }

// RootModule is shared across VUs. It currently has no mutable state.
type RootModule struct{}

// New constructs the extension root.
func New() *RootModule { return &RootModule{} }

// NewModuleInstance creates bindings owned exclusively by one VU.
func (*RootModule) NewModuleInstance(vu modules.VU) modules.Instance {
	return &instance{vu: vu}
}

type instance struct{ vu modules.VU }

func (i *instance) Exports() modules.Exports {
	return modules.Exports{Named: map[string]any{"Client": i.newClient}}
}

func (i *instance) newClient(call sobek.ConstructorCall) *sobek.Object {
	rt := i.vu.Runtime()
	if i.vu.State() != nil {
		panic(rt.NewTypeError("SOAP_INIT_ONLY: construct Client in init context"))
	}
	if len(call.Arguments) != 0 {
		panic(rt.NewTypeError("SOAP_NOT_IMPLEMENTED: configuration is not available in this scaffold"))
	}
	obj := call.This
	unavailable := func(sobek.FunctionCall) sobek.Value {
		panic(rt.NewTypeError("SOAP_NOT_IMPLEMENTED: SOAP operations are not available in this scaffold"))
	}
	for _, name := range []string{"build", "parse"} {
		if err := obj.Set(name, unavailable); err != nil {
			panic(rt.NewGoError(err))
		}
	}
	return obj
}

var (
	_ modules.Module   = (*RootModule)(nil)
	_ modules.Instance = (*instance)(nil)
)
