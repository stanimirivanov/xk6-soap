package fixture

import (
	"embed"
	"log"
	"net/http"
)

const soap11ContentType = "text/xml; charset=utf-8"
const soap12ContentType = "application/soap+xml; charset=utf-8"

//go:embed testdata/soap12/*-reply.xml
var fixedSOAPReplyFiles embed.FS

type fixedSOAPReply struct {
	file        string
	status      int
	contentType string
}

var fixedSOAPReplies = map[string]fixedSOAPReply{
	"/fault11":                             {"fault-soap11-reply.xml", http.StatusInternalServerError, soap11ContentType},
	"/fault12":                             {"xmlp8-receiver-fault-reply.xml", http.StatusInternalServerError, soap12ContentType},
	"/soap12-bad-arguments-fault":          {"xmlp11-bad-arguments-fault-reply.xml", http.StatusBadRequest, soap12ContentType},
	"/soap12-data-encoding-unknown-fault":  {"t80-data-encoding-unknown-fault-reply.xml", http.StatusInternalServerError, soap12ContentType},
	"/soap12-must-understand-fault":        {"th4-must-understand-fault-reply.xml", http.StatusInternalServerError, soap12ContentType},
	"/soap12-procedure-not-present-fault":  {"t33-procedure-not-present-fault-reply.xml", http.StatusBadRequest, soap12ContentType},
	"/soap12-qualified-wrapper-attributes": {"t28-t71-t72-qualified-wrapper-control-reply.xml", http.StatusOK, soap12ContentType},
	"/soap12-sender-fault":                 {"th2-sender-fault-reply.xml", http.StatusBadRequest, soap12ContentType},
	"/soap12-valid-envelope":               {"t69-t70-valid-envelope-control-reply.xml", http.StatusOK, soap12ContentType},
	"/w3c-default-role/0":                  {"t38-default-role-0-reply.xml", http.StatusOK, soap12ContentType},
	"/w3c-default-role/1":                  {"t38-default-role-1-reply.xml", http.StatusOK, soap12ContentType},
	"/w3c-default-role/false":              {"t11-default-role-false-reply.xml", http.StatusOK, soap12ContentType},
	"/w3c-default-role/true":               {"t13-default-role-true-reply.xml", http.StatusOK, soap12ContentType},
	"/w3c-sbr2-optional-next":              {"sbr2-echo-me-unknown-optional-next-reply.xml", http.StatusOK, soap12ContentType},
	"/w3c-standard-role/next":              {"t17-mandatory-next-reply.xml", http.StatusOK, soap12ContentType},
	"/w3c-standard-role/none":              {"t19-mandatory-none-reply.xml", http.StatusOK, soap12ContentType},
	"/w3c-t12":                             {"t12-reply.xml", http.StatusOK, soap12ContentType},
	"/w3c-t15":                             {"t15-reply.xml", http.StatusOK, soap12ContentType},
	"/w3c-t24":                             {"t24-reply.xml", http.StatusOK, soap12ContentType},
	"/w3c-t25":                             {"t25-reply.xml", http.StatusOK, soap12ContentType},
	"/w3c-t28":                             {"t28-reply.xml", http.StatusOK, soap12ContentType},
	"/w3c-t29":                             {"t29-reply.xml", http.StatusOK, soap12ContentType},
	"/w3c-t30":                             {"t30-reply.xml", http.StatusInternalServerError, soap11ContentType},
	"/w3c-t34/foreign-actor":               {"t34-foreign-actor-reply.xml", http.StatusOK, soap12ContentType},
	"/w3c-t34/foreign-only":                {"t34-foreign-only-reply.xml", http.StatusOK, soap12ContentType},
	"/w3c-t34/mandatory-foreign-first":     {"t34-mandatory-foreign-first-reply.xml", http.StatusOK, soap12ContentType},
	"/w3c-t34/mandatory-native-first":      {"t34-mandatory-native-first-reply.xml", http.StatusOK, soap12ContentType},
	"/w3c-t34/optional-foreign-first":      {"t34-optional-foreign-first-reply.xml", http.StatusOK, soap12ContentType},
	"/w3c-t34/optional-native-first":       {"t34-optional-native-first-reply.xml", http.StatusOK, soap12ContentType},
	"/w3c-t37":                             {"t37-reply.xml", http.StatusOK, soap12ContentType},
	"/w3c-t39":                             {"t39-reply.xml", http.StatusOK, soap12ContentType},
	"/w3c-t40":                             {"t40-reply.xml", http.StatusOK, soap12ContentType},
	"/w3c-t5":                              {"t5-reply.xml", http.StatusOK, soap12ContentType},
	"/w3c-t64":                             {"t64-reply.xml", http.StatusOK, soap12ContentType},
	"/w3c-t65":                             {"t65-reply.xml", http.StatusOK, soap12ContentType},
	"/w3c-t67":                             {"t67-reply.xml", http.StatusOK, soap12ContentType},
	"/w3c-t68/compact":                     {"t68-compact-reply.xml", http.StatusOK, soap12ContentType},
	"/w3c-t68/formatted":                   {"t68-formatted-reply.xml", http.StatusOK, soap12ContentType},
	"/w3c-t69":                             {"t69-reply.xml", http.StatusOK, soap12ContentType},
	"/w3c-t70":                             {"t70-reply.xml", http.StatusOK, soap12ContentType},
	"/w3c-t71":                             {"t71-reply.xml", http.StatusOK, soap12ContentType},
	"/w3c-t72":                             {"t72-reply.xml", http.StatusOK, soap12ContentType},
	"/w3c-t74":                             {"t74-reply.xml", http.StatusOK, soap12ContentType},
	"/w3c-th3":                             {"th3-reply.xml", http.StatusInternalServerError, soap12ContentType},
}

func (s *Server) serveFixedSOAPReply(w http.ResponseWriter, path string, reply fixedSOAPReply) {
	body, err := fixedSOAPReplyFiles.ReadFile("testdata/soap12/" + reply.file)
	if err != nil {
		http.Error(w, "missing SOAP fixture reply", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", reply.contentType)
	w.WriteHeader(reply.status)
	if _, err := w.Write(body); err != nil {
		logger := s.Config.ErrorLog
		if logger == nil {
			logger = log.Default()
		}
		// The matched fixture route is safe to log. Write errors may contain sensitive text.
		logger.Printf("SOAP 1.2 fixture %s: response write failed", path)
	}
}
