package soap

import (
	"github.com/stanimirivanov/xk6-soap/internal/wssec"
	"time"
)

// Closed stage/code allow-lists and the typed policy projection prevent raw
// metadata strings from leaking. Never serialize the policy or message content.
func (i *instance) diagnostic(enabled bool, stage string, start time.Time, policy wssec.Policy, code string) {
	if !enabled {
		return
	}
	switch stage {
	case "constructor", "build", "parse":
	default:
		stage = "unknown"
	}
	switch code {
	case "OK", "INVALID_ARGUMENT", "CANCELLED", "LIMIT_EXCEEDED", "XML_INVALID", "POLICY_VIOLATION", "SOAP_FAULT", "HTTP_STATUS", "TRANSPORT_ERROR", "BODY_UNAVAILABLE", "SOAP_POLICY_INVALID", "SOAP_POLICY_KEY", "SOAP_FEATURE_UNAVAILABLE", "SOAP_RANDOM_FAILED", "SOAP_CREDENTIAL_BUILD_FAILED", "SOAP_SIGNATURE_BUILD_FAILED":
	default:
		code = "SOAP_REJECTED"
	}
	algorithm := policy.DiagnosticAlgorithm()

	if state := i.vu.State(); state != nil {
		if state.Logger != nil {
			state.Logger.Infof("soap stage=%s duration_ms=%.3f algorithm=%s code=%s", stage, float64(time.Since(start))/float64(time.Millisecond), algorithm, code)
		}
	} else if env := i.vu.InitEnv(); env != nil && env.Logger != nil {
		env.Logger.Infof("soap stage=%s duration_ms=%.3f algorithm=%s code=%s", stage, float64(time.Since(start))/float64(time.Millisecond), algorithm, code)
	}
}
