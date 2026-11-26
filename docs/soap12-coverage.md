# SOAP 1.2 test collection coverage

This inventory maps all 125 cases in the [W3C SOAP 1.2 Test Collection, Second
Edition, §3.5][collection] to the [supported client contracts][contracts].
The collection exercises clients, receiving endpoints, and intermediaries.
xk6-soap builds messages and decides response acceptance. k6 provides HTTP
transport. Any assertion about a receiving peer's application behavior,
generated Fault, or forwarded message needs evidence from that peer.

The status refers to the client behavior identified in each row.

- **Direct** means an existing test asserts the applicable client behavior
  at the public seam using a synthetic equivalent.
- **Adapted** means a synthetic reply exercises an analogous client rule
  from a case originally defined for another node.
- **Partial** means an existing assertion covers a related version, input,
  or outcome. The row names the missing part.
- **Gap** means the applicable client behavior lacks a targeted assertion.
- **Outside** means the case's distinguishing behavior is outside the
  client contract. Any linked evidence is adjacent.
- **Decision** means the intended client behavior needs a maintainer decision
  before a corresponding assertion can be specified.

The case names are summarized here. The loopback fixtures use original
synthetic messages. Check provenance and applicable reuse terms before
incorporating upstream payloads.

The [byte checks][fixed-replies-http] compare each fixed synthetic reply
against its linked XML file over loopback HTTP. The [request checks][fixed-requests-k6]
verify empty POST bodies for the response-only cases. The bare TH5 exchange
has no body in either direction and no response Content-Type. The generic
Fault checks share one [trigger XML][fault-request] for the
[SOAP 1.1 Fault reply][fault-soap11-reply] and the
[SOAP 1.2 Receiver Fault reply][xmlp8-receiver-fault-reply].
The DTD fixtures use inert URNs and are served as bytes.

## Numbered cases

| W3C case | Behavior | Status | Evidence and next action |
| --- | --- | --- | --- |
| [T1][w3c-T1] | Known header targeted at next | Outside | Peer processes the application header and produces a reply header. Client header policy does not implement echoOk. |
| [T2][w3c-T2] | Known header targeted at an application role | Outside | Peer assumes a custom role and produces a reply header. |
| [T3][w3c-T3] | Known header with no role | Outside | Peer processes the application header and produces a reply header. Default-role rejection of unknown mandatory headers is tracked below. |
| [T4][w3c-T4] | Known header targeted at ultimateReceiver | Outside | Peer processes the application header and produces a reply header. |
| [T5][w3c-T5] | Optional header for another application role | Adapted | [Optional unrelated-role check][optional-other-role] omits mustUnderstand and exposes the reply's Body marker. The upstream receiver ignores an application Header block in a request and returns an empty Body. [Reply XML][t5-reply]. |
| [T6][w3c-T6] | Forward a header for another role | Outside | Requires an intermediary to preserve the block on forwarding. |
| [T7][w3c-T7] | Remove an optional targeted header | Outside | Requires an intermediary to remove its own block before forwarding. |
| [T8][w3c-T8] | Remove only the block for the intermediary | Outside | Requires intermediary role-based removal and preservation of the other blocks. |
| [T9][w3c-T9] | Forward an ultimateReceiver header | Outside | Requires an intermediary to preserve a block for the ultimate receiver. |
| [T10][w3c-T10] | Unknown header without mustUnderstand | Adapted | [Omitted attribute check][omitted-must-understand] exposes the Body marker for the explicit ultimateReceiver role. The upstream receiver returns an empty Body. [Reply XML shared with T37][t37-reply]. |
| [T11][w3c-T11] | Unknown header with mustUnderstand=false | Adapted | [Header role check][roles] accepts an unknown block with mustUnderstand=false and makes the Body marker queryable. The reply omits the role. The upstream request names ultimateReceiver and the peer sends an empty Body. [Reply XML][t11-default-role-false-reply]. |
| [T12][w3c-T12] | Unknown mandatory header for ultimateReceiver | Adapted | [Header role check][roles] asserts HTTP 200, a failed SOAP outcome, POLICY_VIOLATION at parse, null Body and Fault, and CONTENT_UNAVAILABLE with a null XPath value. The upstream receiver instead generates a MustUnderstand Fault with NotUnderstood. [Reply XML shared with T36][t12-reply]. |
| [T13][w3c-T13] | Unknown mandatory header with mustUnderstand=true | Adapted | [Header role check][roles] withholds content for an unknown block with mustUnderstand=true and omitted role. The upstream request names ultimateReceiver and the peer generates a MustUnderstand Fault. [Reply XML][t13-default-role-true-reply]. |
| [T14][w3c-T14] | Invalid mustUnderstand on a known application header | Partial | [Invalid attribute check][invalid-must-understand] shares T39's unknown block to verify rejection of the invalid lexical value. The upstream receiver generates a Sender Fault for its known application header. [Reply XML shared with T39][t39-reply]. |
| [T15][w3c-T15] | Unknown mandatory header for another role | Adapted | [Header role check][roles] keeps the same Header block and Body marker as the targeted case, changes the role, and checks HTTP 200, a successful SOAP outcome without an error or Fault, and the accepted marker through XPath without an error. The upstream receiver ignores the block and sends an empty SOAP Body. [Reply XML][t15-reply]. |
| [T16][w3c-T16] | Forward an unknown mandatory header for a later role | Outside | Requires preserving a block at an intermediary for a downstream receiver. |
| [T17][w3c-T17] | Unknown mandatory header targeted at next | Adapted | [Header role check][roles] withholds content for a SOAP 1.2 reply targeting next with mustUnderstand=1. The upstream node generates a MustUnderstand Fault. [Reply XML][t17-mandatory-next-reply]. |
| [T18][w3c-T18] | Forward a header for role none | Outside | Requires intermediary forwarding and a receiving peer that ignores the block. |
| [T19][w3c-T19] | Ignore a mandatory header for role none | Adapted | [Header role check][roles] accepts the Body when the unknown block targets none. The synthetic reply uses mustUnderstand=1 so only the role changes from the next control. The upstream request uses true and the peer returns an empty Body. [Reply XML][t19-mandatory-none-reply]. |
| [T21][w3c-T21] | Intermediary stops forwarding after mandatory-header failure | Outside | Requires a peer Fault and proof that the second hop received no message. |
| [T22][w3c-T22] | Process a known mandatory header and application Body together | Outside | Requires application-specific header and Body handlers at the peer. |
| [T23][w3c-T23] | Return exactly one Fault for multiple Header errors | Outside | Fault selection and generation are peer behavior. [Fault projection][fault-structure] exercises the shape of received Faults. |
| [T24][w3c-T24] | Reject an Envelope in an unrelated namespace | Adapted | The [public namespace check][t24-k6] preserves HTTP 200 and rejects the unrelated namespace with XML_INVALID at stage xml, withholding Body, Fault and XPath content. The upstream peer generates a VersionMismatch Fault. [Reply XML][t24-reply]. |
| [T25][w3c-T25] | Reject an external DTD | Adapted | The [public external DTD check][t25-k6] asserts XML_INVALID and withheld content for a reply with an inert SYSTEM identifier. The upstream peer generates a Fault describing unsupported DTDs. [Reply XML][t25-reply]. |
| [T26][w3c-T26] | Ignore an XML processing instruction | Outside | The [client XML policy][architecture] deliberately rejects processing instructions. [Declaration and XML rejection][declaration] verifies the restriction. |
| [T27][w3c-T27] | Reject a complex value in a string array | Outside | Peer validates SOAP Encoding item types. |
| [T28][w3c-T28] | Reject encodingStyle on Body | Adapted | [Public k6 wrapper check][wrapper-k6] rejects SOAP 1.2-qualified `encodingStyle` on Body and withholds content. The upstream node generates a Fault. [Reply XML][t28-reply] · [Qualified wrapper control check][wrapper-control-k6] · [Control XML][t28-t71-t72-qualified-wrapper-control-reply]. |
| [T29][w3c-T29] | Accept a long absolute role URI | Adapted | [Long role URI check][long-role] exposes the Body marker in a reply whose optional Header block uses a 2,048-byte absolute role URI within the default XML limits. The upstream receiver returns an empty Body. [Reply XML][t29-reply]. |
| [T30][w3c-T30] | SOAP 1.1 request to a SOAP 1.2 peer | Adapted | [VersionMismatch check][version-fault] projects SOAP_FAULT and the qualified SOAP 1.1 code from a synthetic HTTP 500 reply with a supplied Upgrade Header block. The [Envelope version assertion][envelope] separately checks that SOAP 1.2 validation rejects a SOAP 1.1 Envelope with XML_INVALID. Peer Fault generation and Upgrade advertisement remain outside the client test. [Reply XML][t30-reply]. |
| [T31][w3c-T31] | RPC void return omits the return accessor | Outside | Requires a peer RPC binding and interpretation of the return accessor. |
| [T32][w3c-T32] | RPC returns the value of a required header | Outside | Requires the peer to understand the application header and dispatch echoHeader. |
| [T33][w3c-T33] | Missing RPC procedure returns a qualified Subcode | Adapted | The [public ProcedureNotPresent check][procedure-not-present-fault] parses a synthetic HTTP 400 reply, asserts the SOAP 1.2 Sender Code and exactly one SOAP RPC ProcedureNotPresent Subcode, and reads the Reason via Body-scoped XPath. RPC dispatch and Fault generation belong to the peer. [Reply XML shared with XMLP-12][t33-procedure-not-present-fault-reply]. |
| [T34][w3c-T34] | Ignore a SOAP 1.1 mustUnderstand attribute in a SOAP 1.2 header | Adapted | [Public k6 checks][t34-k6] exercise reply acceptance and native attribute precedence. [Signed][t34-signed] and [recovered][t34-encrypted] Header tests exercise the [compatibility decision][t34-adr] under configured receive protection. Reply variants include [foreign only][t34-foreign-only-reply] · [mandatory native first][t34-mandatory-native-first-reply] · [mandatory foreign first][t34-mandatory-foreign-first-reply] · [optional native first][t34-optional-native-first-reply] · [optional foreign first][t34-optional-foreign-first-reply] · [foreign actor][t34-foreign-actor-reply]. |
| [T35][w3c-T35] | Unknown mandatory header with omitted role | Adapted | [Header role check][roles] asserts POLICY_VIOLATION and withholds Body, Fault, and XPath for an unknown mandatory block with no role. The [plain SOAP 1.1][optional-content] and [signed-header][signed-header] tests also check withholding. The upstream peer generates a Fault. [Mandatory 1 reply][t38-default-role-1-reply] · [Mandatory true reply][t13-default-role-true-reply]. |
| [T36][w3c-T36] | Explicit ultimateReceiver on an unknown mandatory header | Adapted | [Header role check][roles] targets this role with 1 and asserts content withholding. The upstream case checks peer Fault generation. [Reply XML shared with T12][t12-reply]. |
| [T37][w3c-T37] | Header omits mustUnderstand | Adapted | [Omitted attribute check][omitted-must-understand] shares T10's Body marker assertion. The upstream receiver returns a valid reply with an empty Body. [Reply XML shared with T10][t37-reply]. |
| [T38][w3c-T38] | Four lexical forms of mustUnderstand | Partial | [Header role check][roles] exercises all four lexical forms with an omitted role. It verifies equivalent client outcomes for 1 and true, and for 0 and false. The upstream case also exercises application Header block processing at the peer. Reply variants use [0][t38-default-role-0-reply] · [1][t38-default-role-1-reply] · [true][t13-default-role-true-reply] · [false][t11-default-role-false-reply]. |
| [T39][w3c-T39] | Unknown Header block with invalid mustUnderstand | Adapted | [Invalid attribute check][invalid-must-understand] asserts XML_INVALID at parse, null Body and Fault, and XPath CONTENT_UNAVAILABLE. The upstream receiver generates a Sender Fault. [Reply XML shared with T14][t39-reply]. |
| [T40][w3c-T40] | IPv6 literal in the Header block namespace URI | Adapted | [IPv6 namespace check][ipv6-header-namespace] exposes the Body marker in a loopback reply with an unknown ultimateReceiver block, mustUnderstand=false, and a bracketed IPv6 documentation address in its namespace URI. [Reply XML][t40-reply]. |
| [T41][w3c-T41] | RPC typed struct echo | Outside | Peer handles XSD typing and RPC echo semantics. |
| [T42][w3c-T42] | SOAP Encoding array of structs | Outside | Peer interprets the encoded struct item type. |
| [T43][w3c-T43] | RPC struct expanded into scalar outputs | Outside | Peer converts typed struct fields to RPC output parameters. |
| [T44][w3c-T44] | RPC scalar parameters combined into a struct | Outside | Peer assigns scalar parameters to a typed result. |
| [T45][w3c-T45] | RPC nested struct echo | Outside | Peer handles nested typed structs. Object payload mapping builds XML without XSD typing. |
| [T46][w3c-T46] | RPC nested array echo | Outside | Peer interprets nested SOAP Encoding arrays. |
| [T47][w3c-T47] | SOAP Encoding float array | Outside | Peer interprets float item types. |
| [T48][w3c-T48] | SOAP Encoding string array with itemType | Outside | Peer interprets explicit string item typing. |
| [T49][w3c-T49] | SOAP Encoding string array without itemType | Outside | Peer infers array item typing. |
| [T50][w3c-T50] | SOAP Encoding integer array | Outside | Peer interprets integer item types. |
| [T51][w3c-T51] | RPC Base64 binary echo | Outside | Peer interprets Base64 type semantics. The client can carry caller-authored text. |
| [T52][w3c-T52] | RPC boolean encoded as 1 | Outside | Peer interprets an XSD boolean. JavaScript payload formatting does not supply XSD typing. |
| [T53][w3c-T53] | RPC date echo | Outside | Peer interprets a typed date. |
| [T54][w3c-T54] | RPC decimal echo | Outside | Peer interprets a typed decimal. |
| [T55][w3c-T55] | RPC float echo | Outside | Peer interprets a typed float. |
| [T56][w3c-T56] | SOAP Encoding reference has no target | Outside | Peer resolves application encoding references and generates a Fault. WS-Security reference tests exercise a different contract. |
| [T57][w3c-T57] | SOAP Encoding reference resolves to a unique ID | Outside | Peer resolves an application encoding reference and echoes the target. |
| [T58][w3c-T58] | SOAP Encoding integer array contains invalid items | Outside | Peer validates encoded array item types and generates a Fault. |
| [T59][w3c-T59] | SOAP Encoding ref and id occur on the same element | Outside | Peer validates application encoding reference rules. |
| [T60][w3c-T60] | SOAP Encoding array size uses a wildcard | Outside | Peer interprets the wildcard and counts RPC array items. |
| [T61][w3c-T61] | SOAP Encoding wildcard in a later dimension | Outside | Peer validates dimensions and generates a Fault. |
| [T62][w3c-T62] | Concatenate Header blocks and forward | Outside | Requires intermediary application processing and a second hop. |
| [T63][w3c-T63] | Validate a country code carried in a mandatory header | Outside | Requires a peer handler for the application header and its fault semantics. |
| [T64][w3c-T64] | XML notation declaration | Adapted | The [public notation check][t64-k6] asserts XML_INVALID and withheld content for an internal subset that declares a notation. The upstream peer generates a Fault. [Reply XML][t64-reply]. |
| [T65][w3c-T65] | Unparsed entity declaration | Adapted | The [public unparsed entity check][t65-k6] asserts XML_INVALID and withheld content for an internal subset with an inert NDATA entity. This matches the described request shape. The published sample only declares elements, and the upstream peer generates a Fault. [Reply XML][t65-reply]. |
| [T66][w3c-T66] | Accept an explicit UTF-8 XML declaration | Adapted | [Public echo check][echo] compares declared and undeclared accepted Body content and asserts the marker. The upstream peer responds to an application header. |
| [T67][w3c-T67] | Accept an XML declaration with standalone=yes | Adapted | The [public standalone check][t67-k6] accepts a SOAP 1.2 reply with an XML 1.0 standalone declaration and no declared encoding, then queries its Body marker. The upstream peer answers a standalone request with an application reply Header. [Reply XML][t67-reply]. |
| [T68][w3c-T68] | Accept extra Envelope and Header whitespace | Adapted | The [public whitespace checks][t68-k6] accept compact and formatted SOAP 1.2 replies and assert the same namespace-aware Body XPath value. The upstream peer answers the whitespace-varied request with an application reply Header. [Compact reply][t68-compact-reply] · [Formatted reply][t68-formatted-reply]. |
| [T69][w3c-T69] | Reject a missing Body | Adapted | [Public k6 T69 check][t69-k6] rejects an HTTP 200 SOAP 1.2 reply that retains its Header and omits Body. The upstream receiving peer generates a Fault. [Reply XML][t69-reply] · [Valid Envelope control check][envelope-control-k6] · [Control XML][t69-t70-valid-envelope-control-reply]. |
| [T70][w3c-T70] | Reject a Trailer following Header and Body | Adapted | [Public k6 T70 check][t70-k6] rejects an HTTP 200 SOAP 1.2 reply with an unqualified Trailer after Body and withholds the Body marker. The upstream receiving peer generates a Fault. [Reply XML][t70-reply] · [Valid Envelope control check][envelope-control-k6] · [Control XML][t69-t70-valid-envelope-control-reply]. |
| [T71][w3c-T71] | Reject an unqualified attribute on Envelope | Adapted | [Public k6 wrapper check][wrapper-k6] rejects an unqualified Envelope attribute. [Signed wire][wrapper-signed] and [recovered snapshot][wrapper-recovered] checks verify the respective error boundaries. The upstream node generates a Fault. [Reply XML][t71-reply] · [Qualified wrapper control check][wrapper-control-k6] · [Control XML][t28-t71-t72-qualified-wrapper-control-reply]. |
| [T72][w3c-T72] | Reject encodingStyle on Envelope | Adapted | [Public k6 wrapper check][wrapper-k6] rejects SOAP 1.2-qualified `encodingStyle` on Envelope and withholds content. The upstream node generates a Fault. [Reply XML][t72-reply] · [Qualified wrapper control check][wrapper-control-k6] · [Control XML][t28-t71-t72-qualified-wrapper-control-reply]. |
| [T73][w3c-T73] | RPC echo with encodingStyle on payload and argument | Outside | Peer interprets encoding-style scopes and RPC return semantics. |
| [T74][w3c-T74] | SOAP role and mustUnderstand occur on a descendant | Adapted | [Descendant attribute check][descendant-header-attributes] exposes the Body marker when a child of an optional block carries both attributes. The upstream receiver ignores the unknown block and responds to a separate known application header. [Reply XML][t74-reply]. |
| [T75][w3c-T75] | Resolve a relative XLink against xml:base | Outside | Requires peer processing of an application reference. Client XPath reads XML content without link resolution. |
| [T76][w3c-T76] | Inline and referenced strings produce the same RPC result | Outside | Peer interprets SOAP Encoding references and checks semantic equivalence. |
| [T77][w3c-T77] | RPC distinguishes absent arguments and xsi:nil | Outside | Peer interprets argument presence and XSD nil semantics. |
| [T78][w3c-T78] | Known header explicitly targets ultimateReceiver | Outside | Peer processes the application header and generates a reply header. |
| [T79][w3c-T79] | Intermediary forwards a header to ultimateReceiver | Outside | Requires a second hop and application processing by the peer. |
| [T80][w3c-T80] | Unsupported encoding produces DataEncodingUnknown | Adapted | The [public DataEncodingUnknown check][data-encoding-unknown-fault] parses a synthetic HTTP 500 reply, asserts the qualified SOAP 1.2 Code and an empty Subcode array, and reads the Reason via Body-scoped XPath. Detecting unsupported encoding and generating the Fault belong to the peer. [Reply XML shared with XMLP-9][t80-data-encoding-unknown-fault-reply]. |

## HTTP binding

| W3C case | Behavior | Status | Evidence and next action |
| --- | --- | --- | --- |
| [TH1][w3c-TH1] | SOAP 1.2 POST returns HTTP 200 with SOAP XML | Direct | [Public echo check][echo] and [receiver request check][wire] assert a SOAP 1.2 exchange with the expected request and reply media types, HTTP 200, and an accepted Body marker. This evidence covers the HTTP binding behavior with a synthetic echo payload. |
| [TH2][w3c-TH2] | Missing Body yields HTTP 400 Sender Fault | Adapted | The [public peer Fault checks][peer-faults] use a synthetic HTTP 400 SOAP 1.2 Sender reply and assert the status, qualified Fault code, and Reason via Body-scoped XPath. The fixture supplies the outcome. Fault generation after a request with a missing Body is outside the client test. [Reply XML shared with XMLP-7][th2-sender-fault-reply]. |
| [TH3][w3c-TH3] | SOAP 1.1 request yields HTTP 500 VersionMismatch | Adapted | The [opposite-version reply check][opposite-version-fault] asserts that a SOAP 1.1 client preserves HTTP 500 for a supplied SOAP 1.2 VersionMismatch Fault and returns ok false, XML_INVALID at stage xml, and null Body and Fault. Body-scoped XPath returns CONTENT_UNAVAILABLE and a null value. Peer Fault and Upgrade generation are outside the client test. [Reply XML shared with XMLP-5][th3-reply]. |
| [TH4][w3c-TH4] | Mandatory header failure yields HTTP 500 MustUnderstand | Adapted | The [public peer Fault checks][peer-faults] use a synthetic HTTP 500 SOAP 1.2 MustUnderstand reply and assert the status, qualified Fault code, and Reason via Body-scoped XPath. The fixture supplies the outcome. Peer handling of a mandatory header and Fault generation are outside the client test. [Reply XML shared with XMLP-6][th4-must-understand-fault-reply]. |
| [TH5][w3c-TH5] | Unsupported media type yields HTTP 415 | Adapted | The [bare 415 reply check][unsupported-media-reply] asserts HTTP 415, ok false, BODY_UNAVAILABLE, and null Body and Fault. Body-scoped XPath returns CONTENT_UNAVAILABLE and a null value. Both the fixture POST and its reply have empty bodies, and the reply omits Content-Type. The peer's decision to reject the request media type is outside the client test. |

## SOAPBuilders

| W3C case | Behavior | Status | Evidence and next action |
| --- | --- | --- | --- |
| [SBR1-echoString][w3c-SBR1-echoString] | RPC string round trip | Outside | Peer implements typed RPC. [Public echo check][echo] covers XML string transport as adjacent evidence. |
| [SBR1-echoStringArray][w3c-SBR1-echoStringArray] | RPC string array round trip | Outside | Peer implements typed SOAP arrays. [Object payload check][object] covers ordered repeated XML elements as adjacent evidence. |
| [SBR1-echoInteger][w3c-SBR1-echoInteger] | RPC integer round trip | Outside | Peer interprets an XSD integer value. |
| [SBR1-echoIntegerArray][w3c-SBR1-echoIntegerArray] | RPC integer array round trip | Outside | Peer interprets an encoded array of integers. |
| [SBR1-echoFloat][w3c-SBR1-echoFloat] | RPC float round trip | Outside | Peer interprets an XSD floating-point value. |
| [SBR1-echoFloatArray][w3c-SBR1-echoFloatArray] | RPC float array round trip | Outside | Peer interprets an encoded array of floats. |
| [SBR1-echoStruct][w3c-SBR1-echoStruct] | RPC struct round trip | Outside | Peer interprets a schema-typed struct. [Object payload check][object] covers nested XML construction as adjacent evidence. |
| [SBR1-echoStructArray][w3c-SBR1-echoStructArray] | RPC array of structs round trip | Outside | Peer handles arrays of schema-typed structs. |
| [SBR1-echoVoid][w3c-SBR1-echoVoid] | RPC void request and result | Outside | Peer supplies the RPC void response shape. |
| [SBR1-echoBase64][w3c-SBR1-echoBase64] | RPC Base64 round trip | Outside | Peer interprets binary data encoded as Base64. |
| [SBR1-echoDate][w3c-SBR1-echoDate] | RPC date round trip | Outside | Peer interprets a schema-typed date. |
| [SBR2-echoHexBinary][w3c-SBR2-echoHexBinary] | RPC hex binary round trip | Outside | Peer interprets a schema-typed hex binary value. |
| [SBR2-echoDecimal][w3c-SBR2-echoDecimal] | RPC decimal round trip | Outside | Peer interprets a schema-typed decimal. |
| [SBR2-echoBoolean][w3c-SBR2-echoBoolean] | RPC boolean round trip | Outside | Peer interprets a schema-typed boolean. |
| [SBR2-echoStructAsSimpleTypes][w3c-SBR2-echoStructAsSimpleTypes] | RPC struct converted to scalars | Outside | Peer maps typed struct members to RPC output parameters. |
| [SBR2-echoSimpleTypesAsStruct][w3c-SBR2-echoSimpleTypesAsStruct] | RPC scalars converted to struct | Outside | Peer binds typed input parameters to a result struct. |
| [SBR2-echo2DStringArray][w3c-SBR2-echo2DStringArray] | RPC two-dimensional string array | Outside | Peer interprets SOAP Encoding dimensions and items. |
| [SBR2-echoNestedStruct][w3c-SBR2-echoNestedStruct] | RPC nested struct round trip | Outside | Peer binds nested schema-typed structures. |
| [SBR2-echoNestedArray][w3c-SBR2-echoNestedArray] | RPC nested array round trip | Outside | Peer binds nested encoded arrays. |
| [SBR2-echoMeStringRequest][w3c-SBR2-echoMeStringRequest] | Application string Header block echo | Outside | Peer recognizes and echoes the test Header block. Client XPath is scoped to accepted Body content. |
| [SBR2-echoMeStructRequest][w3c-SBR2-echoMeStructRequest] | Application struct Header block echo | Outside | Peer recognizes and echoes the typed Header block. |
| [SBR2-echoMeUnknown][w3c-SBR2-echoMeUnknown] | Optional and mandatory unknown blocks for next or an unrelated role | Adapted | [Optional next][optional-next-role] and [optional unrelated-role][optional-other-role] replies omit mustUnderstand and expose the Body marker. [Mandatory next][mandatory-next-role] withholds content and [mandatory unrelated role][mandatory-other-role] exposes the marker. The upstream receiver generates the MustUnderstand Fault. [Optional next reply][sbr2-echo-me-unknown-optional-next-reply] · [Optional unrelated-role reply][t5-reply] · [Mandatory next reply][t17-mandatory-next-reply] · [Mandatory unrelated-role reply][t15-reply]. |

## XMLP interoperability

| W3C case | Behavior | Status | Evidence and next action |
| --- | --- | --- | --- |
| [XMLP-1][w3c-XMLP-1] | RPC argument omitted | Outside | Peer determines the RPC default result or Fault for a missing argument. |
| [XMLP-2][w3c-XMLP-2] | HTTP GET returns a document-style SOAP reply | Partial | k6 owns HTTP GET. [Public echo check][echo] verifies parsing an HTTP 200 SOAP reply received via POST. Add a GET fixture only if the client contract needs explicit evidence. |
| [XMLP-3][w3c-XMLP-3] | HTTP GET returns an RPC-style SOAP reply | Outside | k6 owns HTTP GET. Peer produces the RPC result and its typed interpretation is outside the client contract. |
| [XMLP-4][w3c-XMLP-4] | RPC parameter order differs | Outside | Peer binds RPC arguments by the expected rules. Ordered XML output is a separate contract. |
| [XMLP-5][w3c-XMLP-5] | SOAP 1.1 request yields a SOAP 1.2 VersionMismatch reply | Adapted | The [opposite-version reply check][opposite-version-fault] preserves HTTP 500 and withholds Body, Fault, and XPath content when a SOAP 1.1 client parses a supplied SOAP 1.2 VersionMismatch Fault. Peer Fault and Upgrade generation are outside the client test. [Reply XML shared with TH3][th3-reply]. |
| [XMLP-6][w3c-XMLP-6] | Mandatory unknown header yields HTTP 500 MustUnderstand | Adapted | The [public peer Fault checks][peer-faults] assert the fixture's HTTP 500, qualified MustUnderstand code, and Reason via Body-scoped XPath. Peer Fault generation is outside the client test. [Reply XML shared with TH4][th4-must-understand-fault-reply]. |
| [XMLP-7][w3c-XMLP-7] | HTTP 400 SOAP 1.2 Sender Fault | Adapted | The [public peer Fault checks][peer-faults] assert the fixture's HTTP 400, qualified Sender code, and Reason via Body-scoped XPath. Peer RPC dispatch and Fault generation are outside the client test. [Reply XML shared with TH2][th2-sender-fault-reply]. |
| [XMLP-8][w3c-XMLP-8] | HTTP 500 SOAP 1.2 Receiver Fault | Adapted | The [public Fault checks][fault] send a local `<synthetic/>` request and assert HTTP 500, the qualified Receiver code, the synthetic Reason, and a Detail containing the fixture-only `<fixture/>` element. In the upstream `echoReceiverFault` exchange, RPC dispatch and Fault generation belong to the peer. [Shared request XML][fault-request] · [SOAP 1.2 reply XML][xmlp8-receiver-fault-reply]. |
| [XMLP-9][w3c-XMLP-9] | Unknown encoding on an RPC argument | Adapted | The [public DataEncodingUnknown check][data-encoding-unknown-fault] shares the T80 HTTP 500 fixture and asserts the Code, empty Subcode array, and Reason. The peer detects the unsupported encoding on the RPC argument and generates the Fault. [Reply XML shared with T80][t80-data-encoding-unknown-fault-reply]. |
| [XMLP-10][w3c-XMLP-10] | RPC call includes typed and untyped arguments | Outside | Peer interprets a mix of explicitly typed and untyped RPC parameters. |
| [XMLP-11][w3c-XMLP-11] | Invalid integer argument yields BadArguments Subcode | Adapted | The [public BadArguments check][bad-arguments-fault] parses a synthetic HTTP 400 reply, asserts the SOAP 1.2 Sender Code and exactly one SOAP RPC BadArguments Subcode, and reads the Reason via Body-scoped XPath. The peer validates the integer argument and generates the Fault. [Reply XML][xmlp11-bad-arguments-fault-reply]. |
| [XMLP-12][w3c-XMLP-12] | Unknown operation yields ProcedureNotPresent Subcode | Adapted | The [public ProcedureNotPresent check][procedure-not-present-fault] shares the T33 HTTP 400 fixture and asserts the Sender Code, exact SOAP RPC Subcode, and Reason. The peer rejects the unknown operation and generates the Fault. [Reply XML shared with T33][t33-procedure-not-present-fault-reply]. |
| [XMLP-13][w3c-XMLP-13] | Forwarding intermediary returns original message | Outside | Requires operating an intermediary and checking preserved wire content. |
| [XMLP-14][w3c-XMLP-14] | Active intermediary processes and forwards a message | Outside | Requires a peer to act as an active intermediary. |
| [XMLP-15][w3c-XMLP-15] | Intermediary removes optional next Header block | Outside | Requires removal from a forwarded Envelope. |
| [XMLP-16][w3c-XMLP-16] | Intermediary retains optional none Header block | Outside | Requires preservation across a forwarding hop. |
| [XMLP-17][w3c-XMLP-17] | Intermediary retains ultimateReceiver Header block | Outside | Requires preservation across a forwarding hop. |
| [XMLP-18][w3c-XMLP-18] | Intermediary retains a targeted header marked relay=true | Outside | Requires SOAP forwarding and relay semantics. |
| [XMLP-19][w3c-XMLP-19] | Mandatory next header stops intermediary forwarding | Outside | Requires a peer Fault and no forwarded exchange. [Header role check][roles] provides adjacent ultimate-receiver rejection evidence. [UltimateReceiver reply XML][t12-reply]. |

## Default-role and Fault adaptations

The public custom-k6 loopback runs the [explicit-role controls][roles] and
four replies with omitted role and the same Body marker. Both mandatory
values, `1` and `true`, return `POLICY_VIOLATION` at `parse`, null Body and
Fault, and XPath `CONTENT_UNAVAILABLE`. Both optional values, `0` and
`false`, expose the marker through XPath. These checks draw on [T11][w3c-T11],
[T13][w3c-T13], [T35][w3c-T35], and [T38][w3c-T38]. The same fixture with a
mandatory block withholds content for `next` and exposes it for `none`, adapting
[T17][w3c-T17] and [T19][w3c-T19] to the client role policy.

For the client side of [T30][w3c-T30], a SOAP 1.1-configured client parses a
synthetic SOAP 1.1 reply and exposes the qualified `VersionMismatch` code.
The supplied `Upgrade` Header block is fixture data, and the POST has no body.
The test asserts Fault projection, with peer generation and version selection
outside its scope.

The [public peer Fault checks][peer-faults] use the [SOAP 1.2 HTTP Fault mapping][http-fault-mapping]
for `DataEncodingUnknown` (HTTP 500) and `Sender` with an RPC Subcode (HTTP 400).
Each reply preserves its HTTP status, returns `ok: false` with `SOAP_FAULT` at
stage `parse`, and exposes its synthetic Reason through namespace-aware Body
XPath with no query error.

## Foreign mustUnderstand in SOAP 1.2 replies

In upstream [T34][w3c-T34], the receiving node ignores the unknown request
Header block and returns an empty Body. The [public k6 adaptation][t34-k6]
receives a synthetic reply containing a Body marker. XPath exposes the
marker if the block carries only SOAP 1.1-qualified `mustUnderstand` or if its
SOAP 1.2-qualified value is optional. A native mandatory value yields
`POLICY_VIOLATION` at `parse` in either attribute order, while a SOAP
1.1-qualified `actor` yields `XML_INVALID`. Both errors withhold Body, Fault
and XPath content.

The [signed Header regression][t34-signed] requires a trusted signature and
checks that changing the foreign attribute after signing invalidates it.
The [recovered Header regression][t34-encrypted] requires selected Header
encryption and verifies that the marker is queryable after recovery under both
protection orders. See [ADR-0008][t34-adr] for the scope of the exception.

## SOAP 1.2 Envelope and Body attributes

The [public k6 loopback][wrapper-k6] adapts [T28][w3c-T28], [T71][w3c-T71]
and [T72][w3c-T72] to response acceptance. Each invalid reply returns
`XML_INVALID` at stage `xml` with null Body and Fault and XPath
`CONTENT_UNAVAILABLE`. The [positive check][wrapper-control-k6] accepts qualified
extension attributes on both wrappers and exposes a Body child with SOAP
`encodingStyle` set to the standard `encoding/none` URI. [Control reply XML][t28-t71-t72-qualified-wrapper-control-reply]

With signature verification required, the [signed wire test][wrapper-signed]
leaves both verification flags null for an invalid Envelope. Its control
verifies a trusted signed Body with `wsu:Id`, qualified wrapper metadata and
legal `encodingStyle` on the Body child. The [recovered snapshot test][wrapper-recovered]
asserts `DECRYPTION_FAILED` at stage `security` with the same content withholding.
The upstream cases exercise Fault generation by the receiving node. These
adaptations exercise local client rejection, as recorded in [ADR-0009][wrapper-adr].

[collection]: https://www.w3.org/TR/2007/REC-soap12-testcollection-20070427/#tests
[contracts]: contracts.md
[architecture]: architecture.md#5-payload-envelopes-and-headers
[echo]: ../test/e2e/http.js#L30
[fault]: ../test/e2e/http.js#L90
[roles]: ../test/e2e/http.js#L130
[mandatory-other-role]: ../test/e2e/http.js#L137
[mandatory-next-role]: ../test/e2e/http.js#L142
[optional-other-role]: ../test/e2e/http.js#L297
[long-role]: ../test/e2e/http.js#L298
[ipv6-header-namespace]: ../test/e2e/http.js#L299
[optional-next-role]: ../test/e2e/http.js#L300
[t34-k6]: ../test/e2e/http.js#L154
[omitted-must-understand]: ../test/e2e/http.js#L172
[invalid-must-understand]: ../test/e2e/http.js#L176
[descendant-header-attributes]: ../test/e2e/http.js#L180
[version-fault]: ../test/e2e/http.js#L103
[peer-faults]: ../test/e2e/http.js#L199
[data-encoding-unknown-fault]: ../test/e2e/http.js#L204-L220
[procedure-not-present-fault]: ../test/e2e/http.js#L205-L220
[bad-arguments-fault]: ../test/e2e/http.js#L206-L220
[http-fault-mapping]: https://www.w3.org/TR/soap12-part2/#tabresstatereccodes
[opposite-version-fault]: ../test/e2e/http.js#L234
[unsupported-media-reply]: ../test/e2e/http.js#L245
[wire]: ../test/e2e/http_test.go#L68
[fixed-requests-k6]: ../test/e2e/http_test.go#L128
[fixed-replies-http]: ../test/fixture/fixed_replies_test.go#L12
[object]: ../test/e2e/object.js#L5
[envelope]: ../internal/message/message_test.go#L109
[declaration]: ../internal/message/xml_declaration_test.go#L7
[fault-structure]: ../internal/message/fault_test.go#L9
[optional-content]: ../internal/message/response_test.go#L86
[signed-header]: ../internal/wssec/headers_test.go#L63
[t34-signed]: ../internal/wssec/headers_test.go#L107-L120
[t34-encrypted]: ../internal/wssec/header_encryption_test.go#L30
[t34-adr]: adr/0008-soap12-foreign-must-understand.md
[wrapper-k6]: ../test/e2e/http.js#L253
[wrapper-control-k6]: ../test/e2e/http.js#L187
[t24-k6]: ../test/e2e/http.js#L255
[t25-k6]: ../test/e2e/http.js#L256
[t64-k6]: ../test/e2e/http.js#L258
[t65-k6]: ../test/e2e/http.js#L259
[t67-k6]: ../test/e2e/http.js#L285
[t68-k6]: ../test/e2e/http.js#L290
[t69-k6]: ../test/e2e/http.js#L260
[t70-k6]: ../test/e2e/http.js#L261
[envelope-control-k6]: ../test/e2e/http.js#L280
[wrapper-signed]: ../internal/adapter/receive_test.go#L52
[wrapper-recovered]: ../internal/wssec/response_encryption_test.go#L143
[wrapper-adr]: adr/0009-soap12-response-wrapper-attributes.md

[fault-request]: ../test/fixture/testdata/soap12/fault-request.xml
[fault-soap11-reply]: ../test/fixture/testdata/soap12/fault-soap11-reply.xml
[sbr2-echo-me-unknown-optional-next-reply]: ../test/fixture/testdata/soap12/sbr2-echo-me-unknown-optional-next-reply.xml
[t11-default-role-false-reply]: ../test/fixture/testdata/soap12/t11-default-role-false-reply.xml
[t12-reply]: ../test/fixture/testdata/soap12/t12-reply.xml
[t13-default-role-true-reply]: ../test/fixture/testdata/soap12/t13-default-role-true-reply.xml
[t15-reply]: ../test/fixture/testdata/soap12/t15-reply.xml
[t17-mandatory-next-reply]: ../test/fixture/testdata/soap12/t17-mandatory-next-reply.xml
[t19-mandatory-none-reply]: ../test/fixture/testdata/soap12/t19-mandatory-none-reply.xml
[t24-reply]: ../test/fixture/testdata/soap12/t24-reply.xml
[t25-reply]: ../test/fixture/testdata/soap12/t25-reply.xml
[t28-reply]: ../test/fixture/testdata/soap12/t28-reply.xml
[t28-t71-t72-qualified-wrapper-control-reply]: ../test/fixture/testdata/soap12/t28-t71-t72-qualified-wrapper-control-reply.xml
[t29-reply]: ../test/fixture/testdata/soap12/t29-reply.xml
[t30-reply]: ../test/fixture/testdata/soap12/t30-reply.xml
[t33-procedure-not-present-fault-reply]: ../test/fixture/testdata/soap12/t33-procedure-not-present-fault-reply.xml
[t34-foreign-actor-reply]: ../test/fixture/testdata/soap12/t34-foreign-actor-reply.xml
[t34-foreign-only-reply]: ../test/fixture/testdata/soap12/t34-foreign-only-reply.xml
[t34-mandatory-foreign-first-reply]: ../test/fixture/testdata/soap12/t34-mandatory-foreign-first-reply.xml
[t34-mandatory-native-first-reply]: ../test/fixture/testdata/soap12/t34-mandatory-native-first-reply.xml
[t34-optional-foreign-first-reply]: ../test/fixture/testdata/soap12/t34-optional-foreign-first-reply.xml
[t34-optional-native-first-reply]: ../test/fixture/testdata/soap12/t34-optional-native-first-reply.xml
[t37-reply]: ../test/fixture/testdata/soap12/t37-reply.xml
[t38-default-role-0-reply]: ../test/fixture/testdata/soap12/t38-default-role-0-reply.xml
[t38-default-role-1-reply]: ../test/fixture/testdata/soap12/t38-default-role-1-reply.xml
[t39-reply]: ../test/fixture/testdata/soap12/t39-reply.xml
[t40-reply]: ../test/fixture/testdata/soap12/t40-reply.xml
[t5-reply]: ../test/fixture/testdata/soap12/t5-reply.xml
[t64-reply]: ../test/fixture/testdata/soap12/t64-reply.xml
[t65-reply]: ../test/fixture/testdata/soap12/t65-reply.xml
[t67-reply]: ../test/fixture/testdata/soap12/t67-reply.xml
[t68-compact-reply]: ../test/fixture/testdata/soap12/t68-compact-reply.xml
[t68-formatted-reply]: ../test/fixture/testdata/soap12/t68-formatted-reply.xml
[t69-reply]: ../test/fixture/testdata/soap12/t69-reply.xml
[t69-t70-valid-envelope-control-reply]: ../test/fixture/testdata/soap12/t69-t70-valid-envelope-control-reply.xml
[t70-reply]: ../test/fixture/testdata/soap12/t70-reply.xml
[t71-reply]: ../test/fixture/testdata/soap12/t71-reply.xml
[t72-reply]: ../test/fixture/testdata/soap12/t72-reply.xml
[t74-reply]: ../test/fixture/testdata/soap12/t74-reply.xml
[t80-data-encoding-unknown-fault-reply]: ../test/fixture/testdata/soap12/t80-data-encoding-unknown-fault-reply.xml
[th2-sender-fault-reply]: ../test/fixture/testdata/soap12/th2-sender-fault-reply.xml
[th3-reply]: ../test/fixture/testdata/soap12/th3-reply.xml
[th4-must-understand-fault-reply]: ../test/fixture/testdata/soap12/th4-must-understand-fault-reply.xml
[xmlp11-bad-arguments-fault-reply]: ../test/fixture/testdata/soap12/xmlp11-bad-arguments-fault-reply.xml
[xmlp8-receiver-fault-reply]: ../test/fixture/testdata/soap12/xmlp8-receiver-fault-reply.xml

[w3c-T1]: https://www.w3.org/TR/2007/REC-soap12-testcollection-20070427/#T1
[w3c-T2]: https://www.w3.org/TR/2007/REC-soap12-testcollection-20070427/#T2
[w3c-T3]: https://www.w3.org/TR/2007/REC-soap12-testcollection-20070427/#T3
[w3c-T4]: https://www.w3.org/TR/2007/REC-soap12-testcollection-20070427/#T4
[w3c-T5]: https://www.w3.org/TR/2007/REC-soap12-testcollection-20070427/#T5
[w3c-T6]: https://www.w3.org/TR/2007/REC-soap12-testcollection-20070427/#T6
[w3c-T7]: https://www.w3.org/TR/2007/REC-soap12-testcollection-20070427/#T7
[w3c-T8]: https://www.w3.org/TR/2007/REC-soap12-testcollection-20070427/#T8
[w3c-T9]: https://www.w3.org/TR/2007/REC-soap12-testcollection-20070427/#T9
[w3c-T10]: https://www.w3.org/TR/2007/REC-soap12-testcollection-20070427/#T10
[w3c-T11]: https://www.w3.org/TR/2007/REC-soap12-testcollection-20070427/#T11
[w3c-T12]: https://www.w3.org/TR/2007/REC-soap12-testcollection-20070427/#T12
[w3c-T13]: https://www.w3.org/TR/2007/REC-soap12-testcollection-20070427/#T13
[w3c-T14]: https://www.w3.org/TR/2007/REC-soap12-testcollection-20070427/#T14
[w3c-T15]: https://www.w3.org/TR/2007/REC-soap12-testcollection-20070427/#T15
[w3c-T16]: https://www.w3.org/TR/2007/REC-soap12-testcollection-20070427/#T16
[w3c-T17]: https://www.w3.org/TR/2007/REC-soap12-testcollection-20070427/#T17
[w3c-T18]: https://www.w3.org/TR/2007/REC-soap12-testcollection-20070427/#T18
[w3c-T19]: https://www.w3.org/TR/2007/REC-soap12-testcollection-20070427/#T19
[w3c-T21]: https://www.w3.org/TR/2007/REC-soap12-testcollection-20070427/#T21
[w3c-T22]: https://www.w3.org/TR/2007/REC-soap12-testcollection-20070427/#T22
[w3c-T23]: https://www.w3.org/TR/2007/REC-soap12-testcollection-20070427/#T23
[w3c-T24]: https://www.w3.org/TR/2007/REC-soap12-testcollection-20070427/#T24
[w3c-T25]: https://www.w3.org/TR/2007/REC-soap12-testcollection-20070427/#T25
[w3c-T26]: https://www.w3.org/TR/2007/REC-soap12-testcollection-20070427/#T26
[w3c-T27]: https://www.w3.org/TR/2007/REC-soap12-testcollection-20070427/#T27
[w3c-T28]: https://www.w3.org/TR/2007/REC-soap12-testcollection-20070427/#T28
[w3c-T29]: https://www.w3.org/TR/2007/REC-soap12-testcollection-20070427/#T29
[w3c-T30]: https://www.w3.org/TR/2007/REC-soap12-testcollection-20070427/#T30
[w3c-T31]: https://www.w3.org/TR/2007/REC-soap12-testcollection-20070427/#T31
[w3c-T32]: https://www.w3.org/TR/2007/REC-soap12-testcollection-20070427/#T32
[w3c-T33]: https://www.w3.org/TR/2007/REC-soap12-testcollection-20070427/#T33
[w3c-T34]: https://www.w3.org/TR/2007/REC-soap12-testcollection-20070427/#T34
[w3c-T35]: https://www.w3.org/TR/2007/REC-soap12-testcollection-20070427/#T35
[w3c-T36]: https://www.w3.org/TR/2007/REC-soap12-testcollection-20070427/#T36
[w3c-T37]: https://www.w3.org/TR/2007/REC-soap12-testcollection-20070427/#T37
[w3c-T38]: https://www.w3.org/TR/2007/REC-soap12-testcollection-20070427/#T38
[w3c-T39]: https://www.w3.org/TR/2007/REC-soap12-testcollection-20070427/#T39
[w3c-T40]: https://www.w3.org/TR/2007/REC-soap12-testcollection-20070427/#T40
[w3c-T41]: https://www.w3.org/TR/2007/REC-soap12-testcollection-20070427/#T41
[w3c-T42]: https://www.w3.org/TR/2007/REC-soap12-testcollection-20070427/#T42
[w3c-T43]: https://www.w3.org/TR/2007/REC-soap12-testcollection-20070427/#T43
[w3c-T44]: https://www.w3.org/TR/2007/REC-soap12-testcollection-20070427/#T44
[w3c-T45]: https://www.w3.org/TR/2007/REC-soap12-testcollection-20070427/#T45
[w3c-T46]: https://www.w3.org/TR/2007/REC-soap12-testcollection-20070427/#T46
[w3c-T47]: https://www.w3.org/TR/2007/REC-soap12-testcollection-20070427/#T47
[w3c-T48]: https://www.w3.org/TR/2007/REC-soap12-testcollection-20070427/#T48
[w3c-T49]: https://www.w3.org/TR/2007/REC-soap12-testcollection-20070427/#T49
[w3c-T50]: https://www.w3.org/TR/2007/REC-soap12-testcollection-20070427/#T50
[w3c-T51]: https://www.w3.org/TR/2007/REC-soap12-testcollection-20070427/#T51
[w3c-T52]: https://www.w3.org/TR/2007/REC-soap12-testcollection-20070427/#T52
[w3c-T53]: https://www.w3.org/TR/2007/REC-soap12-testcollection-20070427/#T53
[w3c-T54]: https://www.w3.org/TR/2007/REC-soap12-testcollection-20070427/#T54
[w3c-T55]: https://www.w3.org/TR/2007/REC-soap12-testcollection-20070427/#T55
[w3c-T56]: https://www.w3.org/TR/2007/REC-soap12-testcollection-20070427/#T56
[w3c-T57]: https://www.w3.org/TR/2007/REC-soap12-testcollection-20070427/#T57
[w3c-T58]: https://www.w3.org/TR/2007/REC-soap12-testcollection-20070427/#T58
[w3c-T59]: https://www.w3.org/TR/2007/REC-soap12-testcollection-20070427/#T59
[w3c-T60]: https://www.w3.org/TR/2007/REC-soap12-testcollection-20070427/#T60
[w3c-T61]: https://www.w3.org/TR/2007/REC-soap12-testcollection-20070427/#T61
[w3c-T62]: https://www.w3.org/TR/2007/REC-soap12-testcollection-20070427/#T62
[w3c-T63]: https://www.w3.org/TR/2007/REC-soap12-testcollection-20070427/#T63
[w3c-T64]: https://www.w3.org/TR/2007/REC-soap12-testcollection-20070427/#T64
[w3c-T65]: https://www.w3.org/TR/2007/REC-soap12-testcollection-20070427/#T65
[w3c-T66]: https://www.w3.org/TR/2007/REC-soap12-testcollection-20070427/#T66
[w3c-T67]: https://www.w3.org/TR/2007/REC-soap12-testcollection-20070427/#T67
[w3c-T68]: https://www.w3.org/TR/2007/REC-soap12-testcollection-20070427/#T68
[w3c-T69]: https://www.w3.org/TR/2007/REC-soap12-testcollection-20070427/#T69
[w3c-T70]: https://www.w3.org/TR/2007/REC-soap12-testcollection-20070427/#T70
[w3c-T71]: https://www.w3.org/TR/2007/REC-soap12-testcollection-20070427/#T71
[w3c-T72]: https://www.w3.org/TR/2007/REC-soap12-testcollection-20070427/#T72
[w3c-T73]: https://www.w3.org/TR/2007/REC-soap12-testcollection-20070427/#T73
[w3c-T74]: https://www.w3.org/TR/2007/REC-soap12-testcollection-20070427/#T74
[w3c-T75]: https://www.w3.org/TR/2007/REC-soap12-testcollection-20070427/#T75
[w3c-T76]: https://www.w3.org/TR/2007/REC-soap12-testcollection-20070427/#T76
[w3c-T77]: https://www.w3.org/TR/2007/REC-soap12-testcollection-20070427/#T77
[w3c-T78]: https://www.w3.org/TR/2007/REC-soap12-testcollection-20070427/#T78
[w3c-T79]: https://www.w3.org/TR/2007/REC-soap12-testcollection-20070427/#T79
[w3c-T80]: https://www.w3.org/TR/2007/REC-soap12-testcollection-20070427/#T80
[w3c-TH1]: https://www.w3.org/TR/2007/REC-soap12-testcollection-20070427/#TH1
[w3c-TH2]: https://www.w3.org/TR/2007/REC-soap12-testcollection-20070427/#TH2
[w3c-TH3]: https://www.w3.org/TR/2007/REC-soap12-testcollection-20070427/#TH3
[w3c-TH4]: https://www.w3.org/TR/2007/REC-soap12-testcollection-20070427/#TH4
[w3c-TH5]: https://www.w3.org/TR/2007/REC-soap12-testcollection-20070427/#TH5
[w3c-SBR1-echoString]: https://www.w3.org/TR/2007/REC-soap12-testcollection-20070427/#SBR1-echoString
[w3c-SBR1-echoStringArray]: https://www.w3.org/TR/2007/REC-soap12-testcollection-20070427/#SBR1-echoStringArray
[w3c-SBR1-echoInteger]: https://www.w3.org/TR/2007/REC-soap12-testcollection-20070427/#SBR1-echoInteger
[w3c-SBR1-echoIntegerArray]: https://www.w3.org/TR/2007/REC-soap12-testcollection-20070427/#SBR1-echoIntegerArray
[w3c-SBR1-echoFloat]: https://www.w3.org/TR/2007/REC-soap12-testcollection-20070427/#SBR1-echoFloat
[w3c-SBR1-echoFloatArray]: https://www.w3.org/TR/2007/REC-soap12-testcollection-20070427/#SBR1-echoFloatArray
[w3c-SBR1-echoStruct]: https://www.w3.org/TR/2007/REC-soap12-testcollection-20070427/#SBR1-echoStruct
[w3c-SBR1-echoStructArray]: https://www.w3.org/TR/2007/REC-soap12-testcollection-20070427/#SBR1-echoStructArray
[w3c-SBR1-echoVoid]: https://www.w3.org/TR/2007/REC-soap12-testcollection-20070427/#SBR1-echoVoid
[w3c-SBR1-echoBase64]: https://www.w3.org/TR/2007/REC-soap12-testcollection-20070427/#SBR1-echoBase64
[w3c-SBR1-echoDate]: https://www.w3.org/TR/2007/REC-soap12-testcollection-20070427/#SBR1-echoDate
[w3c-SBR2-echoHexBinary]: https://www.w3.org/TR/2007/REC-soap12-testcollection-20070427/#SBR2-echoHexBinary
[w3c-SBR2-echoDecimal]: https://www.w3.org/TR/2007/REC-soap12-testcollection-20070427/#SBR2-echoDecimal
[w3c-SBR2-echoBoolean]: https://www.w3.org/TR/2007/REC-soap12-testcollection-20070427/#SBR2-echoBoolean
[w3c-SBR2-echoStructAsSimpleTypes]: https://www.w3.org/TR/2007/REC-soap12-testcollection-20070427/#SBR2-echoStructAsSimpleTypes
[w3c-SBR2-echoSimpleTypesAsStruct]: https://www.w3.org/TR/2007/REC-soap12-testcollection-20070427/#SBR2-echoSimpleTypesAsStruct
[w3c-SBR2-echo2DStringArray]: https://www.w3.org/TR/2007/REC-soap12-testcollection-20070427/#SBR2-echo2DStringArray
[w3c-SBR2-echoNestedStruct]: https://www.w3.org/TR/2007/REC-soap12-testcollection-20070427/#SBR2-echoNestedStruct
[w3c-SBR2-echoNestedArray]: https://www.w3.org/TR/2007/REC-soap12-testcollection-20070427/#SBR2-echoNestedArray
[w3c-SBR2-echoMeStringRequest]: https://www.w3.org/TR/2007/REC-soap12-testcollection-20070427/#SBR2-echoMeStringRequest
[w3c-SBR2-echoMeStructRequest]: https://www.w3.org/TR/2007/REC-soap12-testcollection-20070427/#SBR2-echoMeStructRequest
[w3c-SBR2-echoMeUnknown]: https://www.w3.org/TR/2007/REC-soap12-testcollection-20070427/#SBR2-echoMeUnknown
[w3c-XMLP-1]: https://www.w3.org/TR/2007/REC-soap12-testcollection-20070427/#XMLP-1
[w3c-XMLP-2]: https://www.w3.org/TR/2007/REC-soap12-testcollection-20070427/#XMLP-2
[w3c-XMLP-3]: https://www.w3.org/TR/2007/REC-soap12-testcollection-20070427/#XMLP-3
[w3c-XMLP-4]: https://www.w3.org/TR/2007/REC-soap12-testcollection-20070427/#XMLP-4
[w3c-XMLP-5]: https://www.w3.org/TR/2007/REC-soap12-testcollection-20070427/#XMLP-5
[w3c-XMLP-6]: https://www.w3.org/TR/2007/REC-soap12-testcollection-20070427/#XMLP-6
[w3c-XMLP-7]: https://www.w3.org/TR/2007/REC-soap12-testcollection-20070427/#XMLP-7
[w3c-XMLP-8]: https://www.w3.org/TR/2007/REC-soap12-testcollection-20070427/#XMLP-8
[w3c-XMLP-9]: https://www.w3.org/TR/2007/REC-soap12-testcollection-20070427/#XMLP-9
[w3c-XMLP-10]: https://www.w3.org/TR/2007/REC-soap12-testcollection-20070427/#XMLP-10
[w3c-XMLP-11]: https://www.w3.org/TR/2007/REC-soap12-testcollection-20070427/#XMLP-11
[w3c-XMLP-12]: https://www.w3.org/TR/2007/REC-soap12-testcollection-20070427/#XMLP-12
[w3c-XMLP-13]: https://www.w3.org/TR/2007/REC-soap12-testcollection-20070427/#XMLP-13
[w3c-XMLP-14]: https://www.w3.org/TR/2007/REC-soap12-testcollection-20070427/#XMLP-14
[w3c-XMLP-15]: https://www.w3.org/TR/2007/REC-soap12-testcollection-20070427/#XMLP-15
[w3c-XMLP-16]: https://www.w3.org/TR/2007/REC-soap12-testcollection-20070427/#XMLP-16
[w3c-XMLP-17]: https://www.w3.org/TR/2007/REC-soap12-testcollection-20070427/#XMLP-17
[w3c-XMLP-18]: https://www.w3.org/TR/2007/REC-soap12-testcollection-20070427/#XMLP-18
[w3c-XMLP-19]: https://www.w3.org/TR/2007/REC-soap12-testcollection-20070427/#XMLP-19
