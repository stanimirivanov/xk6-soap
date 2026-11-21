package adapter

import (
	"bytes"
	"errors"

	"github.com/grafana/sobek"
)

// copyArrayBuffer takes ownership of key bytes without retaining mutable JS storage.
// Typed-array views are deliberately excluded: callers pass open(path, 'b') directly.
func copyArrayBuffer(value sobek.Value) ([]byte, error) {
	if value != nil {
		if buffer, ok := value.Export().(sobek.ArrayBuffer); ok && !buffer.Detached() {
			return bytes.Clone(buffer.Bytes()), nil
		}
	}
	return nil, errors.New("SOAP_INVALID_ARGUMENT: expected an attached ArrayBuffer")
}
