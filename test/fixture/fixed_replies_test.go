package fixture

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestFixedSOAPReplies(t *testing.T) {
	const soap11 = "text/xml; charset=utf-8"
	const soap12 = "application/soap+xml; charset=utf-8"

	server := Start(t)
	client := server.Client()
	client.Timeout = 2 * time.Second
	for _, tc := range []struct {
		path        string
		file        string
		status      int
		contentType string
	}{
		{"/fault11", "fault-soap11-reply.xml", 500, soap11},
		{"/fault12", "xmlp8-receiver-fault-reply.xml", 500, soap12},
		{"/soap12-bad-arguments-fault", "xmlp11-bad-arguments-fault-reply.xml", 400, soap12},
		{"/soap12-data-encoding-unknown-fault", "t80-data-encoding-unknown-fault-reply.xml", 500, soap12},
		{"/soap12-must-understand-fault", "th4-must-understand-fault-reply.xml", 500, soap12},
		{"/soap12-procedure-not-present-fault", "t33-procedure-not-present-fault-reply.xml", 400, soap12},
		{"/soap12-qualified-wrapper-attributes", "t28-t71-t72-qualified-wrapper-control-reply.xml", 200, soap12},
		{"/soap12-sender-fault", "th2-sender-fault-reply.xml", 400, soap12},
		{"/soap12-valid-envelope", "t69-t70-valid-envelope-control-reply.xml", 200, soap12},
		{"/w3c-default-role/0", "t38-default-role-0-reply.xml", 200, soap12},
		{"/w3c-default-role/1", "t38-default-role-1-reply.xml", 200, soap12},
		{"/w3c-default-role/false", "t11-default-role-false-reply.xml", 200, soap12},
		{"/w3c-default-role/true", "t13-default-role-true-reply.xml", 200, soap12},
		{"/w3c-sbr2-optional-next", "sbr2-echo-me-unknown-optional-next-reply.xml", 200, soap12},
		{"/w3c-standard-role/next", "t17-mandatory-next-reply.xml", 200, soap12},
		{"/w3c-standard-role/none", "t19-mandatory-none-reply.xml", 200, soap12},
		{"/w3c-t12", "t12-reply.xml", 200, soap12},
		{"/w3c-t15", "t15-reply.xml", 200, soap12},
		{"/w3c-t24", "t24-reply.xml", 200, soap12},
		{"/w3c-t25", "t25-reply.xml", 200, soap12},
		{"/w3c-t28", "t28-reply.xml", 200, soap12},
		{"/w3c-t29", "t29-reply.xml", 200, soap12},
		{"/w3c-t30", "t30-reply.xml", 500, soap11},
		{"/w3c-t34/foreign-actor", "t34-foreign-actor-reply.xml", 200, soap12},
		{"/w3c-t34/foreign-only", "t34-foreign-only-reply.xml", 200, soap12},
		{"/w3c-t34/mandatory-foreign-first", "t34-mandatory-foreign-first-reply.xml", 200, soap12},
		{"/w3c-t34/mandatory-native-first", "t34-mandatory-native-first-reply.xml", 200, soap12},
		{"/w3c-t34/optional-foreign-first", "t34-optional-foreign-first-reply.xml", 200, soap12},
		{"/w3c-t34/optional-native-first", "t34-optional-native-first-reply.xml", 200, soap12},
		{"/w3c-t37", "t37-reply.xml", 200, soap12},
		{"/w3c-t39", "t39-reply.xml", 200, soap12},
		{"/w3c-t40", "t40-reply.xml", 200, soap12},
		{"/w3c-t5", "t5-reply.xml", 200, soap12},
		{"/w3c-t64", "t64-reply.xml", 200, soap12},
		{"/w3c-t65", "t65-reply.xml", 200, soap12},
		{"/w3c-t67", "t67-reply.xml", 200, soap12},
		{"/w3c-t68/compact", "t68-compact-reply.xml", 200, soap12},
		{"/w3c-t68/formatted", "t68-formatted-reply.xml", 200, soap12},
		{"/w3c-t69", "t69-reply.xml", 200, soap12},
		{"/w3c-t70", "t70-reply.xml", 200, soap12},
		{"/w3c-t71", "t71-reply.xml", 200, soap12},
		{"/w3c-t72", "t72-reply.xml", 200, soap12},
		{"/w3c-t74", "t74-reply.xml", 200, soap12},
		{"/w3c-th3", "th3-reply.xml", 500, soap12},
		{"/w3c-th5", "", 415, ""},
	} {
		t.Run(tc.path, func(t *testing.T) {
			var want []byte
			if tc.file != "" {
				var err error
				want, err = os.ReadFile(filepath.Join("testdata", "soap12", tc.file))
				if err != nil {
					t.Fatal(err)
				}
			}
			response, err := client.Post(server.URL+tc.path, "", nil)
			if err != nil {
				t.Fatal(err)
			}
			defer response.Body.Close()
			body, err := io.ReadAll(response.Body)
			if err != nil {
				t.Fatal(err)
			}
			if response.StatusCode != tc.status {
				t.Errorf("status = %d, want %d", response.StatusCode, tc.status)
			}
			contentTypes := response.Header.Values("Content-Type")
			if tc.contentType == "" {
				if len(contentTypes) != 0 {
					t.Errorf("Content-Type = %q, want absent", contentTypes)
				}
			} else if len(contentTypes) != 1 || contentTypes[0] != tc.contentType {
				t.Errorf("Content-Type = %q, want %q", contentTypes, tc.contentType)
			}
			if !bytes.Equal(body, want) {
				t.Errorf("response bytes = %q, want %q", body, want)
			}
		})
	}
}
