package interop

import "testing"

func TestInteropUsernameTokenEchoFixture(t *testing.T) {
	// This literal records the former inline username.js input.
	fixtures := map[string]string{
		"receive/echo-success.xml": `<m:echo xmlns:m="urn:xk6-soap:fixture"><value>synthetic</value></m:echo>`,
	}
	checkInteropFixtureBytes(t, "testdata", fixtures)
}
