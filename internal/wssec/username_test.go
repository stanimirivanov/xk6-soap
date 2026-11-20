package wssec

import (
	"bytes"
	"encoding/xml"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/stanimirivanov/xk6-soap/internal/message"
)

func TestUsernameTokenVectorAndTimestamp(t *testing.T) {
	now := time.Date(2030, 1, 2, 3, 4, 5, 123456789, time.UTC)
	p, err := CompilePolicy(SecurityOptions{UsernameToken: &UsernameTokenPolicy{User: "synthetic<&", Password: "synthetic-π"}}, KeyMaterial{}, now)
	if err != nil {
		t.Fatal(err)
	}
	for _, version := range []string{"1.1", "1.2"} {
		wire, err := BuildCredentials(envelope(version), p, now, bytes.NewReader([]byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}), nil, message.Limits{})
		if err != nil {
			t.Fatal(err)
		}
		for _, want := range []string{"2030-01-02T03:04:05.123Z", "2030-01-02T03:09:05.123Z", "AAECAwQFBgcICQoLDA0ODw==", "Z62LgQEVFLIVUJP/Y7NH9H1eWJM=", "synthetic&lt;&amp;"} {
			if !strings.Contains(string(wire), want) {
				t.Fatal("missing exact token/timestamp serialization", want)
			}
		}
		expectedMU := "1"
		if version == "1.2" {
			expectedMU = "true"
		}
		decoder := xml.NewDecoder(bytes.NewReader(wire))
		found := false
		for {
			token, e := decoder.Token()
			if e == io.EOF {
				break
			}
			if e != nil {
				t.Fatal(e)
			}
			if start, ok := token.(xml.StartElement); ok && start.Name.Local == "Security" {
				for _, attr := range start.Attr {
					if attr.Name.Local == "mustUnderstand" {
						found = attr.Value == expectedMU && attr.Name.Space == decoderNamespace(version)
					}
				}
			}
		}
		if !found {
			t.Fatal("incorrect namespace-qualified mustUnderstand")
		}
		if bytes.Contains(wire, []byte("synthetic-π")) {
			t.Fatal("digest sent plaintext password")
		}
	}
}

type failedRandom struct{}

func (failedRandom) Read([]byte) (int, error) { return 0, errors.New("PRIVATE_RNG_ERROR") }
func TestCredentialsOverridesAndFailure(t *testing.T) {
	p, err := CompilePolicy(SecurityOptions{UsernameToken: &UsernameTokenPolicy{User: "default", Password: "PRIVATE_DEFAULT", PasswordType: "PasswordText"}, Timestamp: &TimestampOptions{TTLSeconds: intp(1), ClockOffsetSeconds: intp(-300)}}, KeyMaterial{}, fixedTime)
	if err != nil {
		t.Fatal(err)
	}
	override := &Credentials{User: "override", Password: "PRIVATE_OVERRIDE"}
	wire, err := BuildCredentials(envelope("1.1"), p, fixedTime, bytes.NewReader(make([]byte, 16)), override, message.Limits{})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(wire, []byte("PRIVATE_OVERRIDE")) || bytes.Contains(wire, []byte("PRIVATE_DEFAULT")) || p.UsernameToken.Password != "PRIVATE_DEFAULT" {
		t.Fatal("override mutated defaults")
	}
	if !bytes.Contains(wire, []byte("2030-01-02T02:59:05.000Z")) || !bytes.Contains(wire, []byte("2030-01-02T02:59:06.000Z")) {
		t.Fatal("timestamp policy ignored")
	}
	if wire, err := BuildCredentials(envelope("1.1"), p, fixedTime, failedRandom{}, nil, message.Limits{}); err != ErrRandom || wire != nil {
		t.Fatal("random failure did not fail closed", err)
	}
}

func TestCredentialOutputLimitsAndIDs(t *testing.T) {
	p, err := CompilePolicy(SecurityOptions{UsernameToken: &UsernameTokenPolicy{User: "synthetic", Password: strings.Repeat("&", 1000), PasswordType: "PasswordText"}}, KeyMaterial{}, fixedTime)
	if err != nil {
		t.Fatal(err)
	}
	if wire, err := BuildCredentials(envelope("1.1"), p, fixedTime, bytes.NewReader(make([]byte, 16)), nil, message.Limits{Bytes: 2048}); err != ErrOutputLimit || wire != nil {
		t.Fatal("security output escaped its byte budget", err)
	}
	raw := bytes.Replace(envelope("1.1"), []byte("<m:echo>"), []byte(`<m:echo xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd" wsu:Id="ut-1">`), 1)
	if wire, err := BuildCredentials(raw, p, fixedTime, bytes.NewReader(make([]byte, 16)), nil, message.Limits{}); err == nil || wire != nil {
		t.Fatal("duplicate security IDs emitted")
	}
}

func decoderNamespace(version string) string {
	if version == "1.2" {
		return message.SOAP12
	}
	return message.SOAP11
}

type fullErrorRandom struct{}

func (fullErrorRandom) Read(p []byte) (int, error) { return len(p), errors.New("PRIVATE_RNG") }
func TestRandomErrorsAreNeverDiscarded(t *testing.T) {
	p, err := CompilePolicy(SecurityOptions{UsernameToken: &UsernameTokenPolicy{User: "u", Password: "PRIVATE"}}, KeyMaterial{}, fixedTime)
	if err != nil {
		t.Fatal(err)
	}
	if wire, err := BuildCredentials(envelope("1.1"), p, fixedTime, fullErrorRandom{}, nil, message.Limits{}); err != ErrRandom || wire != nil {
		t.Fatal("complete-read RNG error was discarded", err)
	}
}

type noProgressRandom struct{}

func (noProgressRandom) Read([]byte) (int, error) { return 0, nil }
func TestRandomNonProgressFailsClosed(t *testing.T) {
	p, _ := CompilePolicy(SecurityOptions{UsernameToken: &UsernameTokenPolicy{User: "u", Password: "PRIVATE"}}, KeyMaterial{}, fixedTime)
	if wire, err := BuildCredentials(envelope("1.1"), p, fixedTime, noProgressRandom{}, nil, message.Limits{}); err != ErrRandom || wire != nil {
		t.Fatal("non-progress RNG accepted", err)
	}
}
