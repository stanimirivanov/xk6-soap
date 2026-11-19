// Package soap registers the k6 SOAP extension.
package soap

import (
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

var (
	_ modules.Module   = (*RootModule)(nil)
	_ modules.Instance = (*instance)(nil)
)
