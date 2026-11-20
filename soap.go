// Package soap registers the k6 SOAP extension.
package soap

import (
	"crypto/rand"
	"io"
	"time"

	"github.com/stanimirivanov/xk6-soap/internal/keys"
	"go.k6.io/k6/v2/js/modules"
)

func init() { modules.Register("k6/x/soap", New()) }

// RootModule shares only its bounded concurrency-safe key cache across VUs.
type RootModule struct{ keyCache *keys.Cache }

// New constructs the extension root.
func New() *RootModule { return &RootModule{keyCache: keys.NewCache()} }

// NewModuleInstance creates bindings owned exclusively by one VU.
func (r *RootModule) NewModuleInstance(vu modules.VU) modules.Instance {
	return &instance{vu: vu, keyCache: r.keyCache, random: rand.Reader, now: time.Now}
}

type instance struct {
	vu       modules.VU
	keyCache *keys.Cache
	random   io.Reader
	now      func() time.Time
}

func (i *instance) Exports() modules.Exports {
	return modules.Exports{Named: map[string]any{"Client": i.newClient}}
}

var (
	_ modules.Module   = (*RootModule)(nil)
	_ modules.Instance = (*instance)(nil)
)
