package soap

import (
	"math"
	"reflect"
	"strconv"
	"strings"

	"github.com/grafana/sobek"
	"github.com/stanimirivanov/xk6-soap/internal/message"
)

type objectCapture struct {
	instance *instance
	limits   message.Limits
	active   map[*sobek.Object]bool
	nodes    int
	bytes    int
}

func objectFailure() error { return &message.Error{Code: "INVALID_ARGUMENT", Stage: "payload"} }
func objectLimit() error   { return &message.Error{Code: "LIMIT_EXCEEDED", Stage: "payload"} }
func (c *objectCapture) budget(n int) error {
	if n > c.limits.Bytes-c.bytes {
		return objectLimit()
	}
	c.bytes += n
	return nil
}
func (c *objectCapture) own(obj *sobek.Object, key string) (sobek.Value, error) {
	descriptor, e := c.instance.ownDescriptor(sobek.Undefined(), obj, c.instance.vu.Runtime().ToValue(key))
	if e != nil || sobek.IsUndefined(descriptor) {
		return nil, objectFailure()
	}
	d, ok := descriptor.(*sobek.Object)
	if !ok {
		return nil, objectFailure()
	}
	for _, name := range d.GetOwnPropertyNames() {
		if name == "value" {
			return d.Get("value"), nil
		}
	}
	getter, ok := sobek.AssertFunction(d.Get("get"))
	if !ok {
		return nil, objectFailure()
	}
	value, e := getter(obj)
	if e != nil {
		return nil, objectFailure()
	}
	return value, nil
}
func (c *objectCapture) keys(obj *sobek.Object) ([]string, error) {
	value, e := c.instance.ownKeys(sobek.Undefined(), obj)
	if e != nil {
		return nil, objectFailure()
	}
	array := value.(*sobek.Object)
	length := array.Get("length").ToInteger()
	if length > int64(c.limits.Nodes-c.nodes) {
		return nil, objectLimit()
	}
	names := make([]string, 0, int(length))
	for index := int64(0); index < length; index++ {
		key, e := c.scalar(array.GetIdx(index))
		if e != nil {
			return nil, e
		}
		names = append(names, key)
	}
	return names, nil
}
func (c *objectCapture) scalar(value sobek.Value) (string, error) {
	if value == nil || sobek.IsNull(value) || sobek.IsUndefined(value) {
		return "", objectFailure()
	}
	if _, ok := value.(*sobek.Object); ok {
		return "", objectFailure()
	}
	if text, ok := value.(sobek.String); ok {
		if text.Length() > c.limits.Bytes-c.bytes {
			return "", objectLimit()
		}
		for index := 0; index < text.Length(); index++ {
			ch := text.CharAt(index)
			if ch >= 0xD800 && ch <= 0xDBFF {
				index++
				if index >= text.Length() || text.CharAt(index) < 0xDC00 || text.CharAt(index) > 0xDFFF {
					return "", objectFailure()
				}
			} else if ch >= 0xDC00 && ch <= 0xDFFF {
				return "", objectFailure()
			}
		}
	} else {
		switch v := value.Export().(type) {
		case bool, int64, int32, int:
		case float64:
			if math.IsInf(v, 0) || math.IsNaN(v) {
				return "", objectFailure()
			}
		default:
			return "", objectFailure()
		}
	}
	text := value.String()
	if e := c.budget(len(text)); e != nil {
		return "", e
	}
	return text, nil
}
func (c *objectCapture) element(name string, value sobek.Value, depth int) (message.ObjectElement, error) {
	node := message.ObjectElement{Name: name}
	if c.instance.vu.Context().Err() != nil {
		return node, &message.Error{Code: "CANCELLED", Stage: "payload"}
	}
	c.nodes++
	if depth+2 > c.limits.Depth || c.nodes > c.limits.Nodes {
		return node, objectLimit()
	}
	obj, ok := value.(*sobek.Object)
	if !ok {
		text, e := c.scalar(value)
		node.Text = &text
		return node, e
	}
	if obj.ExportType() == reflect.TypeOf(sobek.Proxy{}) || obj.ClassName() != "Object" || len(obj.Symbols()) != 0 {
		return node, objectFailure()
	}
	if proto := obj.Prototype(); proto != nil && proto != c.instance.vu.Runtime().NewObject().Prototype() {
		return node, objectFailure()
	}
	if c.active[obj] {
		return node, objectFailure()
	}
	c.active[obj] = true
	defer delete(c.active, obj)
	names, e := c.keys(obj)
	if e != nil {
		return node, e
	}
	children := false
	for _, key := range names {
		if key != "#text" && !strings.HasPrefix(key, "@") {
			children = true
		}
		child, e := c.own(obj, key)
		if e != nil {
			return node, e
		}
		if key == "#text" {
			text, e := c.scalar(child)
			if e != nil {
				return node, e
			}
			node.Text = &text
			continue
		}
		if strings.HasPrefix(key, "@") {
			attr := strings.TrimPrefix(key, "@")
			if !message.ValidObjectName(attr) {
				return node, objectFailure()
			}
			text, e := c.scalar(child)
			if e != nil {
				return node, e
			}
			node.Attributes = append(node.Attributes, message.ObjectAttribute{Name: attr, Value: text})
			if len(node.Attributes) > c.limits.Attributes {
				return node, objectLimit()
			}
			continue
		}
		if !message.ValidObjectName(key) {
			return node, objectFailure()
		}
		if array, ok := child.(*sobek.Object); ok && array.ExportType() != reflect.TypeOf(sobek.Proxy{}) && array.ClassName() == "Array" {
			normalArray := c.instance.vu.Runtime().NewArray().Prototype()
			if array.Prototype() != normalArray {
				return node, objectFailure()
			}
			if c.active[array] || len(array.Symbols()) != 0 {
				return node, objectFailure()
			}
			length := array.Get("length").ToInteger()
			if length > int64(c.limits.Nodes-c.nodes) {
				return node, objectLimit()
			}
			fields := array.GetOwnPropertyNames()
			if int64(len(fields)) != length+1 {
				return node, objectFailure()
			}
			for _, field := range fields {
				if field == "length" {
					continue
				}
				index, e := strconv.ParseInt(field, 10, 64)
				if e != nil || index < 0 || index >= length || strconv.FormatInt(index, 10) != field {
					return node, objectFailure()
				}
			}
			c.active[array] = true
			for index := int64(0); index < length; index++ {
				item, e := c.own(array, strconv.FormatInt(index, 10))
				if e != nil {
					return node, e
				}
				mapped, e := c.element(key, item, depth+1)
				if e != nil {
					return node, e
				}
				node.Children = append(node.Children, mapped)
			}
			delete(c.active, array)
		} else {
			mapped, e := c.element(key, child, depth+1)
			if e != nil {
				return node, e
			}
			node.Children = append(node.Children, mapped)
		}
	}
	if node.Text != nil && children {
		return node, objectFailure()
	}
	return node, nil
}
func (i *instance) objectPayload(operation string, value sobek.Value, cfg clientConfig) (payload string, err error) {
	defer func() {
		if recover() != nil {
			payload = ""
			err = objectFailure()
			if i.vu.Context().Err() != nil {
				err = &message.Error{Code: "CANCELLED", Stage: "payload"}
			}
		}
	}()
	if !message.ValidObjectName(operation) || cfg.namespace == "" || i.ownKeys == nil || i.ownDescriptor == nil {
		return "", objectFailure()
	}
	obj, ok := value.(*sobek.Object)
	if !ok || obj.ClassName() != "Object" {
		return "", objectFailure()
	}
	capture := objectCapture{instance: i, limits: cfg.limits, active: make(map[*sobek.Object]bool)}
	root, e := capture.element(operation, obj, 1)
	if e != nil {
		return "", e
	}
	if i.vu.Context().Err() != nil {
		return "", &message.Error{Code: "CANCELLED", Stage: "payload"}
	}
	payload, err = message.MarshalObject(operation, cfg.namespace, root, cfg.limits)
	if err == nil && i.vu.Context().Err() != nil {
		return "", &message.Error{Code: "CANCELLED", Stage: "payload"}
	}
	return payload, err
}

func (i *instance) objectNamespace(options *sobek.Object) (namespace string, err error) {
	defer func() {
		if recover() != nil {
			namespace = ""
			err = objectFailure()
		}
	}()
	value := policyField(options, "namespace")
	if value == nil {
		return "", nil
	}
	if _, ok := value.(sobek.String); !ok {
		return "", objectFailure()
	}
	capture := objectCapture{limits: message.Limits{Bytes: 4 << 20}}
	namespace, err = capture.scalar(value)
	if err != nil || !message.ValidObjectNamespace(namespace) {
		return "", objectFailure()
	}
	return namespace, nil
}
