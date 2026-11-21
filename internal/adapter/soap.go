// Package adapter registers the k6 SOAP extension.
package adapter

import (
	"crypto/rand"
	"io"
	"sync"
	"time"

	"github.com/grafana/sobek"
	"github.com/stanimirivanov/xk6-soap/internal/keys"
	"go.k6.io/k6/v2/js/modules"
	"go.k6.io/k6/v2/metrics"
)

func init() { modules.Register("k6/x/soap", New()) }

// RootModule shares immutable key material and k6-owned metric references across VUs.
type RootModule struct {
	keyCache  *keys.Cache
	metricsMu sync.Mutex
	metrics   map[*metrics.Registry]*soapMetrics
}

// New constructs the extension root.
func New() *RootModule { return &RootModule{keyCache: keys.NewCache()} }

// NewModuleInstance creates bindings owned exclusively by one VU.
func (r *RootModule) NewModuleInstance(vu modules.VU) modules.Instance {
	var registered *soapMetrics
	if env := vu.InitEnv(); env != nil {
		registered = r.registerMetrics(env.Registry)
	}
	object := vu.Runtime().Get("Object").ToObject(vu.Runtime())
	ownKeys, _ := sobek.AssertFunction(object.Get("keys"))
	ownDescriptor, _ := sobek.AssertFunction(object.Get("getOwnPropertyDescriptor"))
	return &instance{vu: vu, keyCache: r.keyCache, random: rand.Reader, now: time.Now, metrics: registered, ownKeys: ownKeys, ownDescriptor: ownDescriptor}
}

type instance struct {
	vu            modules.VU
	metrics       *soapMetrics
	ownKeys       sobek.Callable
	ownDescriptor sobek.Callable
	keyCache      *keys.Cache
	random        io.Reader
	now           func() time.Time
}

func (i *instance) Exports() modules.Exports {
	return modules.Exports{Named: map[string]any{"Client": i.newClient}}
}

var (
	_ modules.Module   = (*RootModule)(nil)
	_ modules.Instance = (*instance)(nil)
)
