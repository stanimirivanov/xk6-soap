package interop

import "testing"

func TestInteropSignedReceiveEchoFixtures(t *testing.T) {
	// These literals record the former inline receive.js inputs.
	fixtures := map[string]string{
		"receive/echo-success.xml": `<m:echo xmlns:m="urn:xk6-soap:fixture"><value>synthetic</value></m:echo>`,
		"matrix/echo-fault.xml":    `<m:echo xmlns:m="urn:xk6-soap:fixture"><value>fault</value></m:echo>`,
	}
	checkInteropFixtureBytes(t, "testdata", fixtures)
}
