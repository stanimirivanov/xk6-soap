package soap

import (
	"bytes"
	"testing"

	"github.com/grafana/sobek"
	"go.k6.io/k6/v2/js/modulestest"
)

func TestCopyArrayBuffer(t *testing.T) {
	rt := modulestest.NewRuntime(t).VU.Runtime()
	value, err := rt.RunString(`var input = new Uint8Array([0, 128, 255]); input.buffer`)
	if err != nil {
		t.Fatal(err)
	}
	got, err := copyArrayBuffer(value)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, []byte{0, 128, 255}) {
		t.Fatalf("bytes: %v", got)
	}
	if _, err := rt.RunString(`input[0] = 42`); err != nil {
		t.Fatal(err)
	}
	if got[0] != 0 {
		t.Fatal("Go bytes alias mutable JS storage")
	}
	got[1] = 7
	v, err := rt.RunString(`input[1]`)
	if err != nil || v.ToInteger() != 128 {
		t.Fatalf("JS bytes alias Go storage: %v", err)
	}
}

func TestCopyArrayBufferRejectsOtherTypes(t *testing.T) {
	rt := modulestest.NewRuntime(t).VU.Runtime()
	for _, expr := range []string{`null`, `undefined`, `"key"`, `[1,2]`, `new Uint8Array([1])`, `({})`} {
		value, err := rt.RunString(expr)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := copyArrayBuffer(value); err == nil {
			t.Errorf("accepted %s", expr)
		}
	}
	if _, err := copyArrayBuffer(nil); err == nil {
		t.Error("accepted nil")
	}
}

func TestCopyArrayBufferEmptyAndDetached(t *testing.T) {
	rt := sobek.New()
	buffer := rt.NewArrayBuffer([]byte{})
	if got, err := copyArrayBuffer(rt.ToValue(buffer)); err != nil || len(got) != 0 {
		t.Fatalf("empty: %v %v", got, err)
	}
	buffer.Detach()
	if _, err := copyArrayBuffer(rt.ToValue(buffer)); err == nil {
		t.Error("accepted detached buffer")
	}
}
