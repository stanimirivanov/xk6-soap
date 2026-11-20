package soap

import (
	"reflect"
	"strconv"

	"github.com/grafana/sobek"
	"github.com/stanimirivanov/xk6-soap/internal/message"
)

// Capture once at the JS boundary. Exceptions and coercion cannot leak input.
func (i *instance) headerOptions(options *sobek.Object, limits message.Limits) (headers []message.Header, addressing *message.Addressing, err error) {
	invalid := func() error { return &message.Error{Code: "INVALID_ARGUMENT", Stage: "headers"} }
	defer func() {
		if recover() != nil {
			headers = nil
			addressing = nil
			err = invalid()
		}
	}()
	capture := objectCapture{instance: i, limits: limits}
	recordObject := func(value sobek.Value, fields ...string) *sobek.Object {
		if obj, ok := value.(*sobek.Object); ok && obj.ExportType() == reflect.TypeOf(sobek.Proxy{}) {
			panic(invalid())
		}
		return i.object(value, fields...)
	}
	text := func(obj *sobek.Object, name string) (string, error) {
		value, e := capture.own(obj, name)
		if e != nil {
			return "", invalid()
		}
		if _, ok := value.(sobek.String); !ok {
			return "", invalid()
		}
		return capture.scalar(value)
	}
	if value := policyField(options, "headers"); value != nil {
		array, ok := value.(*sobek.Object)
		if !ok || array.ExportType() == reflect.TypeOf(sobek.Proxy{}) || array.ClassName() != "Array" || array.Prototype() != i.vu.Runtime().NewArray().Prototype() || len(array.Symbols()) != 0 {
			return nil, nil, invalid()
		}
		length := array.Get("length").ToInteger()
		if length < 0 || length > 16 {
			return nil, nil, invalid()
		}
		for _, key := range array.GetOwnPropertyNames() {
			if key == "length" {
				continue
			}
			idx, e := strconv.Atoi(key)
			if e != nil || idx < 0 || int64(idx) >= length || strconv.Itoa(idx) != key {
				return nil, nil, invalid()
			}
		}
		for n := int64(0); n < length; n++ {
			value, e := capture.own(array, strconv.FormatInt(n, 10))
			if e != nil {
				return nil, nil, invalid()
			}
			record := recordObject(value, "name", "xml")
			name, e := text(record, "name")
			if e != nil {
				return nil, nil, e
			}
			raw, e := text(record, "xml")
			if e != nil {
				return nil, nil, e
			}
			headers = append(headers, message.Header{Name: name, XML: raw})
		}
	}
	if value := policyField(options, "addressing"); value != nil {
		record := recordObject(value, "action", "to", "messageId", "replyTo")
		addressing = &message.Addressing{}
		for j, name := range []string{"action", "to", "messageId", "replyTo"} {
			out := []*string{&addressing.Action, &addressing.To, &addressing.MessageID, &addressing.ReplyTo}[j]
			*out, err = text(record, name)
			if err != nil {
				return nil, nil, err
			}
		}
	}
	return headers, addressing, nil
}
