package wssec

import (
	"encoding/base64"
	"strings"
	"testing"
	"time"

	"github.com/knroy/go-xml/v2/c14n"
	"github.com/knroy/go-xmlsec/v2"
	"github.com/knroy/go-xmlsec/v2/dsig"
	"github.com/knroy/go-xmlsec/v2/wss"
	"github.com/stanimirivanov/xk6-soap/internal/message"
)

func timestampXML(created, expires string) string {
	return `<wsu:Timestamp wsu:Id="ts-1"><wsu:Created>` + created + `</wsu:Created><wsu:Expires>` + expires + `</wsu:Expires></wsu:Timestamp>`
}
func signedTimestamp(t *testing.T, version, stamp string, covered bool) string {
	t.Helper()
	id := identity(t)
	ns := xmlsec.NSSOAP11
	if version == "1.2" {
		ns = xmlsec.NSSOAP12
	}
	raw := `<s:Envelope xmlns:s="` + ns + `" xmlns:wsu="` + xmlsec.NSWSU + `" xmlns:wsse="` + xmlsec.NSWSSE + `"><s:Header><wsse:Security s:mustUnderstand="1">` + stamp + `<wsse:BinarySecurityToken wsu:Id="bst-1" ValueType="` + xmlsec.BSTValueTypeX509v3 + `" EncodingType="` + base64Encoding + `">` + base64.StdEncoding.EncodeToString(id.Certificate.Raw) + `</wsse:BinarySecurityToken></wsse:Security></s:Header><s:Body wsu:Id="body-1"><Echo>PRIVATE_TIMESTAMP_PAYLOAD</Echo></s:Body></s:Envelope>`
	doc, _, e := parsed([]byte(raw))
	if e != nil {
		t.Fatal(e)
	}
	security, e := wss.FindHeader(doc.Root(), ns, "")
	if e != nil {
		t.Fatal(e)
	}
	refs := []dsig.Reference{{URI: "#body-1", DigestAlgorithm: xmlsec.DigestSHA256, Transforms: []dsig.TransformSpec{{Algorithm: string(c14n.Exclusive10)}}}}
	if covered && stamp != "" {
		refs = append(refs, dsig.Reference{URI: "#ts-1", DigestAlgorithm: xmlsec.DigestSHA256, Transforms: []dsig.TransformSpec{{Algorithm: string(c14n.Exclusive10)}}})
	}
	_, e = dsig.Sign(doc, xmlsec.KeyProvider{Signer: id.Key, Certificate: id.Certificate}, dsig.SignOptions{SignatureAlgorithm: xmlsec.SigRSASHA256, CanonicalizationAlgorithm: string(c14n.Exclusive10), References: refs, KeyInfo: dsig.KeyInfoSecurityTokenReference, SecurityTokenID: "bst-1", Parent: security})
	if e != nil {
		t.Fatal(e)
	}
	wire, e := c14n.Bytes(doc.Root(), c14n.Options{Algorithm: c14n.Inclusive10WithComments})
	if e != nil {
		t.Fatal(e)
	}
	return string(wire)
}

func TestSignedTimestampBoundaries(t *testing.T) {
	p, trust := receivePolicy(t)
	wire := signedTimestamp(t, "1.1", timestampXML("2030-01-02T03:04:05.000Z", "2030-01-02T03:09:05.000Z"), true)
	for _, tc := range []struct {
		name   string
		offset time.Duration
		skew   int
		age    int
		valid  bool
	}{
		{"created at future skew equality", -60 * time.Second, 60, 300, true},
		{"created beyond future skew", -60*time.Second - time.Nanosecond, 60, 300, false},
		{"expires just inside skew", 360*time.Second - time.Nanosecond, 60, 300, true},
		// Age is also maxAge+skew here; the strict expiry condition still wins.
		{"expires at skew equality", 360 * time.Second, 60, 300, false},
		{"beyond age plus skew", 360*time.Second + time.Nanosecond, 60, 300, false},
		{"zero skew created equality", 0, 0, 300, true},
		{"zero skew future nanosecond", -time.Nanosecond, 0, 300, false},
		{"zero skew before expiry", 300*time.Second - time.Nanosecond, 0, 300, true},
		{"zero skew expiry equality", 300 * time.Second, 0, 300, false},
		{"lifetime exceeds configured max age", 0, 60, 299, false},
		{"maximum configured skew", -300 * time.Second, 300, 300, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			policy := p
			policy.ClockSkewSeconds = tc.skew
			policy.MaxAgeSeconds = tc.age
			result := Receive(200, wire, "1.1", message.Limits{}, policy, trust, fixedTime.Add(tc.offset))
			if result.OK != tc.valid {
				t.Fatalf("valid=%v want %v; error=%v", result.OK, tc.valid, result.Error)
			}
			if !tc.valid {
				assertHidden(t, result)
				if result.SigVerified == nil || !*result.SigVerified || result.TimestampValid == nil || *result.TimestampValid || result.Error.Code != "TIMESTAMP_INVALID" {
					t.Fatal("freshness failure lost signed-but-stale evidence", result)
				}
			}
		})
	}
}

func TestFreshnessPolicyActivation(t *testing.T) {
	_, trust := receivePolicy(t)
	p, e := CompilePolicy(SecurityOptions{Verify: &ReceiveOptions{Signature: boolp(true), ClockSkewSeconds: intp(0), MaxAgeSeconds: intp(3600)}}, KeyMaterial{Trust: trust}, fixedTime)
	if e != nil || p.RequireAvailable() != nil {
		t.Fatal("valid freshness policy unavailable", e, p.RequireAvailable())
	}
}

func TestRequiredSignedTimestampStructure(t *testing.T) {
	policy, trust := receivePolicy(t)
	created := `<wsu:Created>2030-01-02T03:04:05.000Z</wsu:Created>`
	expires := `<wsu:Expires>2030-01-02T03:09:05.000Z</wsu:Expires>`
	for _, tc := range []struct {
		name   string
		fields string
	}{
		{"mixed Timestamp text", "PRIVATE_MIXED_TEXT" + created + expires},
		{"missing Created", expires},
		{"missing Expires", created},
		{"duplicate Created", created + created + expires},
		{"duplicate Expires", created + expires + expires},
		{"nested Created", `<wsu:Created><n xmlns="urn:nested">2030-01-02T03:04:05.000Z</n></wsu:Created>` + expires},
		{"nested Expires", created + `<wsu:Expires><n xmlns="urn:nested">2030-01-02T03:09:05.000Z</n></wsu:Expires>`},
		{"reversed lifetime", timestampFields("2030-01-02T03:04:05.000Z", "2030-01-02T03:04:04.999Z")},
		{"zero lifetime", timestampFields("2030-01-02T03:04:05.000Z", "2030-01-02T03:04:05.000Z")},
		{"excess lifetime", timestampFields("2030-01-02T03:04:05.000Z", "2030-01-02T03:09:05.001Z")},
		{"non UTC", timestampFields("2030-01-02T04:04:05.000+01:00", "2030-01-02T04:09:05.000+01:00")},
		{"invalid date", timestampFields("2030-02-30T03:04:05.000Z", "2030-02-30T03:09:05.000Z")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			wire := signedTimestamp(t, "1.1", `<wsu:Timestamp wsu:Id="ts-1">`+tc.fields+`</wsu:Timestamp>`, true)
			result := Receive(500, wire, "1.1", message.Limits{}, policy, trust, fixedTime)
			assertHidden(t, result)
			if result.Error.Code != "TIMESTAMP_INVALID" || result.SigVerified == nil || !*result.SigVerified || result.TimestampValid == nil || *result.TimestampValid {
				t.Fatal("malformed signed Timestamp not rejected as freshness failure", result)
			}
		})
	}
}
func timestampFields(created, expires string) string {
	return `<wsu:Created>` + created + `</wsu:Created><wsu:Expires>` + expires + `</wsu:Expires>`
}

func TestTimestampPresenceCoverageAndSkips(t *testing.T) {
	policy, trust := receivePolicy(t)
	valid := timestampXML("2030-01-02T03:04:05.000Z", "2030-01-02T03:09:05.000Z")
	for _, version := range []string{"1.1", "1.2"} {
		for _, tc := range []struct {
			name    string
			stamp   string
			covered bool
		}{
			{"missing", "", false},
			{"unsigned", valid, false},
			{"duplicate", valid + strings.Replace(valid, `Id="ts-1"`, `Id="ts-2"`, 1), true},
		} {
			t.Run(version+"/"+tc.name, func(t *testing.T) {
				wire := signedTimestamp(t, version, tc.stamp, tc.covered)
				result := Receive(200, wire, version, message.Limits{}, policy, trust, fixedTime)
				assertHidden(t, result)
				if tc.name == "missing" && (result.Error.Code != "TIMESTAMP_INVALID" || result.SigVerified == nil || !*result.SigVerified || result.TimestampValid == nil || *result.TimestampValid) {
					t.Fatal("missing required timestamp was skipped", result)
				}
			})
		}
		stale := signedTimestamp(t, version, timestampXML("2030-01-02T01:04:05.000Z", "2030-01-02T01:09:05.000Z"), true)
		p := policy
		p.Timestamp = false
		result := Receive(200, stale, version, message.Limits{}, p, trust, fixedTime)
		if !result.OK || result.SigVerified == nil || !*result.SigVerified || result.TimestampValid != nil {
			t.Fatal("freshness skip changed", result.Error)
		}
		p.Signature = false
		result = Receive(200, stale, version, message.Limits{}, p, nil, fixedTime)
		if !result.OK || result.SigVerified != nil || result.TimestampValid != nil {
			t.Fatal("signature skip changed", result.Error)
		}
	}
}

func TestConfiguredTimestampLifetimeBounds(t *testing.T) {
	policy, trust := receivePolicy(t)
	for _, ttl := range []int{1, 600, 3600} {
		policy.MaxAgeSeconds = ttl
		wire := signedTimestamp(t, "1.1", timestampXML(fixedTime.Format(time.RFC3339Nano), fixedTime.Add(time.Duration(ttl)*time.Second).Format(time.RFC3339Nano)), true)
		result := Receive(200, wire, "1.1", message.Limits{}, policy, trust, fixedTime)
		if !result.OK {
			t.Fatal("configured lifetime equality rejected", ttl, result.Error)
		}
		if ttl > 1 {
			policy.MaxAgeSeconds = ttl - 1
			assertHidden(t, Receive(200, wire, "1.1", message.Limits{}, policy, trust, fixedTime))
		}
	}
}

func TestSignedTimestampWhitespace(t *testing.T) {
	policy, trust := receivePolicy(t)
	stamp := `<wsu:Timestamp wsu:Id="ts-1">
 <wsu:Created> 2030-01-02T03:04:05.000Z </wsu:Created>
 <wsu:Expires>2030-01-02T03:09:05.000Z</wsu:Expires>
 </wsu:Timestamp>`
	result := Receive(200, signedTimestamp(t, "1.1", stamp, true), "1.1", message.Limits{}, policy, trust, fixedTime)
	if !result.OK {
		t.Fatal("XML whitespace rejected", result.Error)
	}
}
