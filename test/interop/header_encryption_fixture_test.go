package interop

import "testing"

func TestInteropHeaderEncryptionFixtures(t *testing.T) {
	// These literals record the former inline header-encryption.js inputs.
	fixtures := map[string]string{
		"header-encryption/echo.xml":         `<m:echo xmlns:m="urn:xk6-soap:fixture"><value>visible-body</value></m:echo>`,
		"header-encryption/header-trace.xml": `<h:Trace xmlns:h="urn:trace">HEADER_ENCRYPTION_PRIVATE_SENTINEL</h:Trace>`,
		"matrix/header-other.xml":            `<h:Other xmlns:h="urn:trace">clear-header</h:Other>`,
	}
	checkInteropFixtureBytes(t, "testdata", fixtures)
}
