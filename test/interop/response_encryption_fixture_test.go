package interop

import "testing"

func TestInteropEncryptedResponseEchoFixtures(t *testing.T) {
	// These literals record the former inline response-encryption.js inputs.
	fixtures := map[string]string{
		"response-encryption/echo-success.xml": `<m:echo xmlns:m="urn:xk6-soap:fixture"><value>RESPONSE_PRIVATE_SENTINEL</value></m:echo>`,
		"matrix/echo-fault.xml":                `<m:echo xmlns:m="urn:xk6-soap:fixture"><value>fault</value></m:echo>`,
	}
	checkInteropFixtureBytes(t, "testdata", fixtures)
}
