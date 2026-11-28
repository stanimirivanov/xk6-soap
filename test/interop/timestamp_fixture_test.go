package interop

import "testing"

func TestInteropTimestampFreshnessEchoFixtures(t *testing.T) {
	// These literals record the former inline timestamp.js inputs.
	fixtures := map[string]string{
		"timestamp/echo-success.xml": `<m:echo xmlns:m="urn:xk6-soap:fixture"><value>TIMESTAMP_PRIVATE_SENTINEL</value></m:echo>`,
		"matrix/echo-fault.xml":      `<m:echo xmlns:m="urn:xk6-soap:fixture"><value>fault</value></m:echo>`,
	}
	checkInteropFixtureBytes(t, "testdata", fixtures)
}
