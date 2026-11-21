package soap

import (
	"math"
	"net/url"
	"reflect"
	"time"

	"github.com/grafana/sobek"
	"github.com/stanimirivanov/xk6-soap/internal/message"
	"github.com/stanimirivanov/xk6-soap/internal/wssec"
)

type clientConfig struct {
	url       string
	version   string
	namespace string
	limits    message.Limits
	keys      *clientKeys
	policy    wssec.Policy
	debug     bool
}

func (i *instance) throw(code, stage string) {
	err := i.vu.Runtime().NewTypeError(code + ": " + stage)
	_ = err.Set("code", code)
	_ = err.Set("stage", stage)
	panic(err)
}
func (i *instance) object(value sobek.Value, allowed ...string) *sobek.Object {
	obj, ok := value.(*sobek.Object)
	if !ok || obj.ClassName() != "Object" || len(obj.Symbols()) != 0 {
		i.throw("INVALID_ARGUMENT", "options")
	}
	if proto := obj.Prototype(); proto != nil && proto != i.vu.Runtime().NewObject().Prototype() {
		i.throw("INVALID_ARGUMENT", "options")
	}
	for _, key := range obj.GetOwnPropertyNames() {
		found := false
		for _, name := range allowed {
			if key == name {
				found = true
			}
		}
		if !found {
			i.throw("INVALID_ARGUMENT", "options")
		}
	}
	return obj
}
func absent(v sobek.Value) bool { return v == nil || sobek.IsUndefined(v) }
func (i *instance) text(value sobek.Value) string {
	if value == nil {
		i.throw("INVALID_ARGUMENT", "string")
	}
	text, ok := value.Export().(string)
	if !ok {
		i.throw("INVALID_ARGUMENT", "string")
	}
	return text
}
func (i *instance) number(value sobek.Value) int {
	var number float64
	if value == nil {
		i.throw("INVALID_ARGUMENT", "number")
	}
	switch v := value.Export().(type) {
	case int64:
		number = float64(v)
	case int32:
		number = float64(v)
	case int:
		number = float64(v)
	case float64:
		number = v
	default:
		i.throw("INVALID_ARGUMENT", "number")
	}
	if math.IsNaN(number) || math.IsInf(number, 0) || number != math.Trunc(number) || number < 0 || number > math.MaxInt32 {
		i.throw("INVALID_ARGUMENT", "number")
	}
	return int(number)
}
func (i *instance) newClient(call sobek.ConstructorCall) *sobek.Object {
	if i.vu.State() != nil {
		i.throw("SOAP_INIT_ONLY", "constructor")
	}
	if i.metrics == nil {
		i.throw("SOAP_METRIC_REGISTRATION", "constructor")
	}
	if len(call.Arguments) != 1 {
		i.throw("INVALID_ARGUMENT", "constructor")
	}
	start := time.Now()
	cfg := clientConfig{version: "1.1"}
	options := i.object(call.Argument(0), "url", "soapVersion", "namespace", "limits", "debug", "keys", "security")
	cfg.url = i.text(options.Get("url"))
	parsed, err := url.Parse(cfg.url)
	if err != nil || parsed.Hostname() == "" || parsed.Scheme != "http" && parsed.Scheme != "https" || parsed.User != nil || parsed.Fragment != "" {
		i.throw("INVALID_ARGUMENT", "url")
	}
	if value := options.Get("soapVersion"); !absent(value) {
		cfg.version = i.text(value)
		if cfg.version != "1.1" && cfg.version != "1.2" {
			i.throw("INVALID_ARGUMENT", "soapVersion")
		}
	}
	cfg.namespace, err = i.objectNamespace(options)
	if err != nil {
		i.throw("INVALID_ARGUMENT", "namespace")
	}

	if value := options.Get("debug"); !absent(value) {
		enabled, ok := value.Export().(bool)
		if !ok {
			i.throw("INVALID_ARGUMENT", "debug")
		}
		cfg.debug = enabled
	}
	if value := options.Get("limits"); !absent(value) {
		limits := i.object(value, "bytes", "depth", "nodes", "attributes")
		fields := map[string]*int{"bytes": &cfg.limits.Bytes, "depth": &cfg.limits.Depth, "nodes": &cfg.limits.Nodes, "attributes": &cfg.limits.Attributes}
		for name, target := range fields {
			if value := limits.Get(name); !absent(value) {
				*target = i.number(value)
				if *target == 0 {
					i.throw("INVALID_ARGUMENT", "limits")
				}
			}
		}
	}
	cfg.limits, err = cfg.limits.Normalized()
	if err != nil {
		i.throw("INVALID_ARGUMENT", "limits")
	}
	if value := options.Get("keys"); !absent(value) {
		cfg.keys = i.decodeKeys(value)
	}
	cfg.policy, err = wssec.CompilePolicy(i.decodeSecurity(options), cfg.keys.policyMaterial(), time.Now())
	if err != nil {
		i.diagnostic(cfg.debug, "constructor", start, wssec.Policy{}, err.Error())
		i.throw(err.Error(), "security")
	}
	err = cfg.policy.RequireAvailable()
	code := "OK"
	if err != nil {
		code = err.Error()
	}
	i.diagnostic(cfg.debug, "constructor", start, cfg.policy, code)
	if err != nil {
		i.throw(err.Error(), "security")
	}
	obj := call.This
	_ = obj.Set("build", func(call sobek.FunctionCall) sobek.Value { return i.build(cfg, call) })
	_ = obj.Set("parse", func(call sobek.FunctionCall) sobek.Value { return i.parse(cfg, call) })
	return obj
}
func (i *instance) execution() {
	if i.vu.State() == nil {
		i.throw("SOAP_EXECUTION_ONLY", "execution")
	}
	if i.vu.Context().Err() != nil {
		i.throw("CANCELLED", "execution")
	}
}
func (i *instance) build(cfg clientConfig, call sobek.FunctionCall) sobek.Value {
	i.execution()
	start := time.Now()
	defer i.recordMetrics(cfg, start, false, false)
	i.validateKeys(cfg)
	if len(call.Arguments) < 2 || len(call.Arguments) > 3 {
		i.throw("INVALID_ARGUMENT", "build")
	}
	var operation string
	var payload string
	if _, ok := call.Argument(1).(sobek.String); ok {
		operation = i.text(call.Argument(0))
		payload = i.text(call.Argument(1))
	} else {
		operationValue, ok := call.Argument(0).(sobek.String)
		if !ok {
			i.throw("INVALID_ARGUMENT", "operation")
		}
		reader := objectCapture{limits: cfg.limits}
		var err error
		operation, err = reader.scalar(operationValue)
		if err != nil {
			i.throw("INVALID_ARGUMENT", "operation")
		}
		payload, err = i.objectPayload(operation, call.Argument(1), cfg)
		if err != nil {
			failure := err.(*message.Error)
			i.throw(failure.Code, failure.Stage)
		}
	}
	action := ""
	actionSet := false
	var credentials *wssec.Credentials
	var headers []message.Header
	var addressing *message.Addressing
	if len(call.Arguments) == 3 && !sobek.IsUndefined(call.Argument(2)) {
		options := i.object(call.Argument(2), "soapAction", "credentials", "headers", "addressing")
		var e error
		headers, addressing, e = i.headerOptions(options, cfg.limits)
		if e != nil {
			failure := e.(*message.Error)
			i.throw(failure.Code, failure.Stage)
		}
		if value := policyField(options, "soapAction"); !absent(value) {
			action = i.text(value)
			actionSet = true
		}
	}
	if len(call.Arguments) == 3 && !sobek.IsUndefined(call.Argument(2)) {
		credentials = i.decodeCredentials(call.Argument(2).ToObject(i.vu.Runtime()), cfg.policy)
	}
	i.execution()
	request, err := message.Build(operation, payload, message.Options{Version: cfg.version, Action: action, ActionSet: actionSet, Limits: cfg.limits, URL: cfg.url, Headers: headers, Addressing: addressing})
	if err != nil {
		failure := err.(*message.Error)
		i.diagnostic(cfg.debug, "build", start, cfg.policy, failure.Code)
		i.throw(failure.Code, failure.Stage)
	}
	if cfg.policy.Timestamp != nil {
		i.execution()
		wire, buildErr := wssec.BuildSecurity([]byte(request.Body), cfg.policy, cfg.keys.policyMaterial(), i.now(), i.random, credentials, cfg.limits, request.HeaderSelectors...)
		if buildErr != nil {
			i.diagnostic(cfg.debug, "build", start, cfg.policy, buildErr.Error())
			i.throw(buildErr.Error(), "build")
		}
		i.execution()
		request.Body = string(wire)
	}
	i.execution()
	i.diagnostic(cfg.debug, "build", start, cfg.policy, "OK")
	return i.vu.Runtime().ToValue(map[string]any{"url": cfg.url, "body": request.Body, "headers": request.Headers, "buildDuration": float64(time.Since(start)) / float64(time.Millisecond)})
}
func (i *instance) parse(cfg clientConfig, call sobek.FunctionCall) sobek.Value {
	i.execution()
	start := time.Now()
	var outcome *message.Parsed
	defer func() { i.recordMetrics(cfg, start, true, outcome != nil && outcome.OK) }()
	i.validateKeys(cfg)
	if len(call.Arguments) != 1 {
		i.throw("INVALID_ARGUMENT", "parse")
	}
	obj, ok := call.Argument(0).(*sobek.Object)
	if !ok || obj.ClassName() != "Object" {
		i.throw("INVALID_ARGUMENT", "response")
	}
	statusValue := i.responseProperty(obj, "status")
	if _, isObject := statusValue.(*sobek.Object); isObject {
		i.throw("INVALID_ARGUMENT", "status")
	}
	status := i.number(statusValue)
	if status > 599 {
		i.throw("INVALID_ARGUMENT", "status")
	}
	body := ""
	if status != 0 {
		value := i.responseProperty(obj, "body")
		if !absent(value) && !sobek.IsNull(value) {
			if data, ok := value.(sobek.String); ok {
				if data.Length() > cfg.limits.Bytes {
					outcome = &message.Parsed{Status: status, Error: &message.Error{Code: "LIMIT_EXCEEDED", Stage: "parse"}}
					return i.parsedValue(outcome)
				}
				body = data.String()
			} else {
				object, ok := value.(*sobek.Object)
				if !ok || object.ExportType() != reflect.TypeFor[sobek.ArrayBuffer]() {
					i.throw("INVALID_ARGUMENT", "body")
				}
				data := object.Export().(sobek.ArrayBuffer)
				if data.Detached() {
					i.throw("INVALID_ARGUMENT", "body")
				}
				if len(data.Bytes()) > cfg.limits.Bytes {
					outcome = &message.Parsed{Status: status, Error: &message.Error{Code: "LIMIT_EXCEEDED", Stage: "parse"}}
					return i.parsedValue(outcome)
				}
				body = string(data.Bytes())
			}
		}
	}
	i.execution()
	parsed := wssec.ReceiveWithKeys(status, body, cfg.version, cfg.limits, cfg.policy.Receive, cfg.keys.policyMaterial(), i.now())
	i.execution()
	code := "OK"
	if parsed.Error != nil {
		code = parsed.Error.Code
	}
	i.diagnostic(cfg.debug, "parse", start, cfg.policy, code)
	outcome = parsed
	return i.parsedValue(parsed)
}

// Read native response properties without reflecting accessor exceptions.
func (i *instance) responseProperty(obj *sobek.Object, name string) sobek.Value {
	var value sobek.Value
	exception := i.vu.Runtime().Try(func() { value = obj.Get(name) })
	i.execution()
	if exception != nil {
		i.throw("INVALID_ARGUMENT", name)
	}
	return value
}

func resultError(err *message.Error) any {
	if err == nil {
		return nil
	}
	return map[string]any{"code": err.Code, "stage": err.Stage, "message": err.Code + ": " + err.Stage}
}
func (i *instance) parsedValue(parsed *message.Parsed) sobek.Value {
	var body any
	if parsed.Body != nil {
		body = *parsed.Body
	}
	var fault any
	if parsed.Fault != nil {
		fault = parsed.Fault
	}
	obj := i.vu.Runtime().ToValue(map[string]any{"ok": parsed.OK, "status": parsed.Status, "body": body, "fault": fault, "error": resultError(parsed.Error), "sigVerified": optionalBool(parsed.SigVerified), "timestampValid": optionalBool(parsed.TimestampValid)}).ToObject(i.vu.Runtime())
	_ = obj.Set("xpath", func(call sobek.FunctionCall) sobek.Value {
		i.execution()
		errorResult := func(code string) sobek.Value {
			return i.vu.Runtime().ToValue(map[string]any{"value": nil, "error": resultError(&message.Error{Code: code, Stage: "xpath"})})
		}
		if len(call.Arguments) < 1 || len(call.Arguments) > 2 {
			return errorResult("XPATH_INVALID")
		}
		expression, ok := call.Argument(0).(sobek.String)
		if !ok {
			return errorResult("XPATH_INVALID")
		}
		ns := map[string]string{}
		if expression.Length() > 4096 {
			if parsed.Body == nil {
				return errorResult("CONTENT_UNAVAILABLE")
			}
			return errorResult("LIMIT_EXCEEDED")
		}
		if len(call.Arguments) == 2 && !sobek.IsUndefined(call.Argument(1)) {
			bindings, code := i.xpathBindings(call.Argument(1))
			if code != "" {
				return errorResult(code)
			}
			ns = bindings
		}
		value, err := parsed.XPath(expression.String(), ns)
		i.execution()

		var failure any
		if err != nil {
			failure = resultError(err.(*message.Error))
		}
		return i.vu.Runtime().ToValue(map[string]any{"value": value, "error": failure})
	})
	return obj
}

// Inspect the namespace map without exporting arbitrary JavaScript objects.
func (i *instance) xpathBindings(value sobek.Value) (map[string]string, string) {
	obj, ok := value.(*sobek.Object)
	if !ok {
		return nil, "XPATH_INVALID"
	}
	ns := map[string]string{}
	code := ""
	exception := i.vu.Runtime().Try(func() {
		if obj.ClassName() != "Object" {
			code = "XPATH_INVALID"
			return
		}
		keys := obj.Keys()
		if len(keys) > 64 {
			code = "LIMIT_EXCEEDED"
			return
		}
		for _, prefix := range keys {
			uri, ok := obj.Get(prefix).(sobek.String)
			if !ok || uri.Length() > 4096 {
				code = "XPATH_INVALID"
				return
			}
			ns[prefix] = uri.String()
		}
	})
	i.execution()
	if exception != nil {
		return nil, "XPATH_INVALID"
	}
	return ns, code
}

func optionalBool(v *bool) any {
	if v == nil {
		return nil
	}
	return *v
}
