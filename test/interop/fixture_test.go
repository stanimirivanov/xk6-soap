//go:build interop

package interop

import (
	"context"
	"crypto/rand"
	"crypto/sha1" // UsernameToken PasswordDigest is specified to use SHA-1.
	"encoding/base64"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"
)

// Apache is the verifier. These requests are hand-assembled from the OASIS
// UsernameToken wire formula, without importing the Go extension/provider.
func request(version, kind, password string, created time.Time, nonce []byte) string {
	ns := "http://schemas.xmlsoap.org/soap/envelope/"
	if version == "12" {
		ns = "http://www.w3.org/2003/05/soap-envelope"
	}
	timestamp := created.UTC().Format("2006-01-02T15:04:05.000Z")
	value := password
	if kind == "PasswordDigest" {
		hash := sha1.New()
		_, _ = hash.Write(nonce)
		_, _ = hash.Write([]byte(timestamp))
		_, _ = hash.Write([]byte(password))
		value = base64.StdEncoding.EncodeToString(hash.Sum(nil))
	}
	return fmt.Sprintf(`<s:Envelope xmlns:s="%s" xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd" xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd"><s:Header><wsse:Security s:mustUnderstand="1"><wsu:Timestamp wsu:Id="TS"><wsu:Created>%s</wsu:Created><wsu:Expires>%s</wsu:Expires></wsu:Timestamp><wsse:UsernameToken wsu:Id="UT"><wsse:Username>fixture-user</wsse:Username><wsse:Password Type="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#%s">%s</wsse:Password><wsse:Nonce EncodingType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary">%s</wsse:Nonce><wsu:Created>%s</wsu:Created></wsse:UsernameToken></wsse:Security></s:Header><s:Body><m:echo xmlns:m="urn:xk6-soap:fixture"><value>synthetic</value></m:echo></s:Body></s:Envelope>`, ns, timestamp, created.Add(300*time.Second).UTC().Format("2006-01-02T15:04:05.000Z"), kind, value, base64.StdEncoding.EncodeToString(nonce), timestamp)
}
func freshNonce(t *testing.T) []byte {
	t.Helper()
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		t.Fatal(err)
	}
	return nonce
}
func TestApacheFixture(t *testing.T) {
	base := os.Getenv("SOAP_INTEROP_URL")
	if base == "" {
		t.Fatal("SOAP_INTEROP_URL missing; use make interop")
	}
	client := &http.Client{Timeout: 5 * time.Second}
	// Probe both bound endpoints; the 30-second context bounds total readiness.
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	for _, version := range []string{"11", "12"} {
		for {
			req, _ := http.NewRequestWithContext(ctx, http.MethodGet, base+"/ut"+version+"?wsdl", nil)
			res, err := client.Do(req)
			if err == nil {
				res.Body.Close()
				if res.StatusCode == 200 {
					break
				}
			}
			select {
			case <-ctx.Done():
				t.Fatal("Apache fixture readiness deadline exceeded")
			case <-time.After(100 * time.Millisecond):
			}
		}
	}

	post := func(t *testing.T, version, body string, wantFault bool) string {
		t.Helper()
		contentType := "text/xml; charset=utf-8"
		if version == "12" {
			contentType = "application/soap+xml; charset=utf-8"
		}
		req, err := http.NewRequest(http.MethodPost, base+"/ut"+version, strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", contentType)
		req.Header.Set("SOAPAction", `"urn:echo"`)
		res, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer res.Body.Close()
		data, err := io.ReadAll(io.LimitReader(res.Body, 65537))
		if err != nil || len(data) > 65536 {
			t.Fatalf("bounded response: %v", err)
		}
		var envelope struct {
			XMLName xml.Name
			Body    struct {
				XMLName  xml.Name
				Fault    *struct{ XMLName xml.Name } `xml:"Fault"`
				Response *struct {
					Value string `xml:"return"`
				} `xml:"echoResponse"`
			} `xml:"Body"`
		}
		if err := xml.Unmarshal(data, &envelope); err != nil {
			t.Fatalf("non-XML response: %v", err)
		}
		expectedNS := "http://schemas.xmlsoap.org/soap/envelope/"
		if version == "12" {
			expectedNS = "http://www.w3.org/2003/05/soap-envelope"
		}
		if envelope.XMLName != (xml.Name{Space: expectedNS, Local: "Envelope"}) || envelope.Body.XMLName != (xml.Name{Space: expectedNS, Local: "Body"}) {
			t.Fatal("response SOAP version/structure mismatch")
		}
		if wantFault {
			if res.StatusCode != 500 || envelope.Body.Fault == nil {
				t.Fatalf("expected rejection, status %d: %s", res.StatusCode, data)
			}
		} else if res.StatusCode != 200 || envelope.Body.Fault != nil || envelope.Body.Response == nil || envelope.Body.Response.Value != "synthetic" {
			t.Fatalf("expected accepted echo, status %d: %s", res.StatusCode, data)
		}
		return string(data)
	}
	for _, version := range []string{"11", "12"} {
		for _, kind := range []string{"PasswordDigest", "PasswordText"} {
			t.Run(version+"/"+kind, func(t *testing.T) {
				now := time.Now()
				nonce := freshNonce(t)
				good := request(version, kind, "fixture-password", now, nonce)
				post(t, version, good, false)
				post(t, version, good, true) // identical nonce replay rejected
				post(t, version, strings.Replace(request(version, kind, "fixture-password", now, freshNonce(t)), "fixture-user", "unknown-user", 1), true)
				complete := request(version, kind, "fixture-password", now, freshNonce(t))
				start := strings.Index(complete, "<wsu:Timestamp")
				end := strings.Index(complete, "</wsu:Timestamp>") + len("</wsu:Timestamp>")
				post(t, version, complete[:start]+complete[end:], true)
				start = strings.Index(complete, "<wsse:UsernameToken")
				end = strings.Index(complete, "</wsse:UsernameToken>") + len("</wsse:UsernameToken>")
				post(t, version, complete[:start]+complete[end:], true)
				start = strings.Index(complete, "<wsu:Expires>")
				end = strings.Index(complete, "</wsu:Expires>") + len("</wsu:Expires>")
				post(t, version, complete[:start]+complete[end:], true)
				// Expired Timestamp with a fresh, correctly hashed UsernameToken.
				staleTime := time.Now().Add(-10 * time.Minute)
				stamp := now.UTC().Format("2006-01-02T15:04:05.000Z")
				stale := request(version, kind, "fixture-password", now, freshNonce(t))
				stale = strings.Replace(stale, stamp, staleTime.UTC().Format("2006-01-02T15:04:05.000Z"), 1)
				stale = strings.Replace(stale, now.Add(300*time.Second).UTC().Format("2006-01-02T15:04:05.000Z"), staleTime.Add(300*time.Second).UTC().Format("2006-01-02T15:04:05.000Z"), 1)
				post(t, version, stale, true)
				// A failed authentication must not poison the nonce replay cache.
				reused := freshNonce(t)
				post(t, version, request(version, kind, "wrong-password", now, reused), true)
				post(t, version, request(version, kind, "fixture-password", now, reused), false)
				fault := strings.Replace(request(version, kind, "fixture-password", now, freshNonce(t)), "<value>synthetic</value>", "<value>fault</value>", 1)
				if response := post(t, version, fault, true); !strings.Contains(response, "Synthetic service fault") {
					t.Fatal("service fault was not reached")
				}

				post(t, version, request(version, kind, "wrong-password", now, freshNonce(t)), true)
				post(t, version, request(version, kind, "fixture-password", now.Add(-10*time.Minute), freshNonce(t)), true)
				post(t, version, request(version, kind, "fixture-password", now.Add(10*time.Minute), freshNonce(t)), true)
			})
		}
		ns := "http://schemas.xmlsoap.org/soap/envelope/"
		if version == "12" {
			ns = "http://www.w3.org/2003/05/soap-envelope"
		}
		post(t, version, `<s:Envelope xmlns:s="`+ns+`"><s:Body><m:echo xmlns:m="urn:xk6-soap:fixture"><value>synthetic</value></m:echo></s:Body></s:Envelope>`, true)
	}
}
