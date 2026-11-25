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

The case names are summarized here. The existing loopback fixtures use
original synthetic messages. Check provenance and applicable reuse terms
before incorporating upstream payloads.

## Numbered cases

| W3C case | Behavior | Status | Evidence and next action |
| --- | --- | --- | --- |
| [T1][w3c-T1] | Known header targeted at next | Outside | Peer processes the application header and produces a reply header. Client header policy does not implement echoOk. |
| [T2][w3c-T2] | Known header targeted at an application role | Outside | Peer assumes a custom role and produces a reply header. |
| [T3][w3c-T3] | Known header with no role | Outside | Peer processes the application header and produces a reply header. Default-role rejection of unknown mandatory headers is tracked below. |
| [T4][w3c-T4] | Known header targeted at ultimateReceiver | Outside | Peer processes the application header and produces a reply header. |
| [T5][w3c-T5] | Optional header for another application role | Partial | [Header role check][roles] covers ignoring a mandatory header for another role. A reply with an optional header would isolate this variant. |
| [T6][w3c-T6] | Forward a header for another role | Outside | Requires an intermediary to preserve the block on forwarding. |
| [T7][w3c-T7] | Remove an optional targeted header | Outside | Requires an intermediary to remove its own block before forwarding. |
| [T8][w3c-T8] | Remove only the block for the intermediary | Outside | Requires intermediary role-based removal and preservation of the other blocks. |
| [T9][w3c-T9] | Forward an ultimateReceiver header | Outside | Requires an intermediary to preserve a block for the ultimate receiver. |
| [T10][w3c-T10] | Unknown header without mustUnderstand | Partial | [Body-scoped XPath][xpath-tests] accepts an optional unknown SOAP 1.1 block with no role. Add a SOAP 1.2 reply for the explicit ultimateReceiver role and assert the accepted Body. |
| [T11][w3c-T11] | Unknown header with mustUnderstand=false | Adapted | [Header role check][roles] accepts an unknown block with mustUnderstand=false and makes the Body marker queryable. The reply omits the role. The upstream request names ultimateReceiver and the peer sends an empty Body. |
| [T12][w3c-T12] | Unknown mandatory header for ultimateReceiver | Adapted | [Header role check][roles] asserts HTTP 200, a failed SOAP outcome, POLICY_VIOLATION at parse, null Body and Fault, and CONTENT_UNAVAILABLE with a null XPath value. The upstream receiver instead generates a MustUnderstand Fault with NotUnderstood. |
| [T13][w3c-T13] | Unknown mandatory header with mustUnderstand=true | Adapted | [Header role check][roles] withholds content for an unknown block with mustUnderstand=true and omitted role. The upstream request names ultimateReceiver and the peer generates a MustUnderstand Fault. |
| [T14][w3c-T14] | Invalid mustUnderstand on a known application header | Gap | Assert XML_INVALID and withheld Body on a reply with the invalid value. Peer Fault generation is separate. |
| [T15][w3c-T15] | Unknown mandatory header for another role | Adapted | [Header role check][roles] keeps the same Header block and Body marker as the targeted case, changes the role, and checks HTTP 200, a successful SOAP outcome without an error or Fault, and the accepted marker through XPath without an error. The upstream receiver ignores the block and sends an empty SOAP Body. |
| [T16][w3c-T16] | Forward an unknown mandatory header for a later role | Outside | Requires preserving a block at an intermediary for a downstream receiver. |
| [T17][w3c-T17] | Unknown mandatory header targeted at next | Partial | [Header role check][roles] uses ultimateReceiver. Add next and assert the same client rejection. Fault generation belongs to the peer. |
| [T18][w3c-T18] | Forward a header for role none | Outside | Requires intermediary forwarding and a receiving peer that ignores the block. |
| [T19][w3c-T19] | Ignore a mandatory header for role none | Partial | [Header role check][roles] uses an unrelated application role. Add the standard none role and assert acceptance. |
| [T21][w3c-T21] | Intermediary stops forwarding after mandatory-header failure | Outside | Requires a peer Fault and proof that the second hop received no message. |
| [T22][w3c-T22] | Process a known mandatory header and application Body together | Outside | Requires application-specific header and Body handlers at the peer. |
| [T23][w3c-T23] | Return exactly one Fault for multiple Header errors | Outside | Fault selection and generation are peer behavior. [Fault projection][fault-structure] exercises the shape of received Faults. |
| [T24][w3c-T24] | Reject an Envelope in an unrelated namespace | Partial | [Envelope structure][envelope] rejects a missing namespace and a SOAP version mismatch. Add an unrelated namespace at Client.parse if needed. VersionMismatch generation is peer behavior. |
| [T25][w3c-T25] | Reject an external DTD | Partial | [Declaration and XML rejection][declaration] checks a local DOCTYPE. A fixture can verify external declaration rejection without any resolution. Generation of a Fault describing unsupported DTDs is peer behavior. |
| [T26][w3c-T26] | Ignore an XML processing instruction | Outside | The [client XML policy][architecture] deliberately rejects processing instructions. [Declaration and XML rejection][declaration] verifies the restriction. |
| [T27][w3c-T27] | Reject a complex value in a string array | Outside | Peer validates SOAP Encoding item types. |
| [T28][w3c-T28] | Reject encodingStyle on Body | Decision | [Envelope structure][envelope] does not check this attribute. Decide whether SOAP Envelope structural validation should enforce its placement before specifying an assertion. |
| [T29][w3c-T29] | Accept a long absolute role URI | Gap | Add an optional Header block with a synthetic long role URI within configured XML limits and assert Body acceptance. |
| [T30][w3c-T30] | SOAP 1.1 request to a SOAP 1.2 peer | Adapted | [VersionMismatch check][version-fault] projects SOAP_FAULT and the qualified SOAP 1.1 code from a synthetic HTTP 500 reply with a supplied Upgrade Header block. [Envelope structure][envelope] separately checks wrong-version rejection. Peer Fault generation and Upgrade advertisement remain outside the client test. |
| [T31][w3c-T31] | RPC void return omits the return accessor | Outside | Requires a peer RPC binding and interpretation of the return accessor. |
| [T32][w3c-T32] | RPC returns the value of a required header | Outside | Requires the peer to understand the application header and dispatch echoHeader. |
| [T33][w3c-T33] | Missing RPC procedure returns a qualified Subcode | Partial | [Fault projection][fault-structure] asserts a Sender code and ordered qualified Subcodes. Add this specific peer-supplied Subcode only if useful to client callers. RPC dispatch stays at the peer. |
| [T34][w3c-T34] | Ignore a SOAP 1.1 mustUnderstand attribute in a SOAP 1.2 header | Decision | [Current response policy][header-policy] returns XML_INVALID for SOAP attributes from the other Envelope namespace. The upstream receiver ignores this header. Decide which client behavior to specify before adding a regression assertion. |
| [T35][w3c-T35] | Unknown mandatory header with omitted role | Adapted | [Header role check][roles] asserts POLICY_VIOLATION and withholds Body, Fault, and XPath for an unknown mandatory block with no role. The [plain SOAP 1.1][optional-content] and [signed-header][signed-header] tests also check withholding. The upstream peer generates a Fault. |
| [T36][w3c-T36] | Explicit ultimateReceiver on an unknown mandatory header | Adapted | [Header role check][roles] targets this role with 1 and asserts content withholding. The upstream case checks peer Fault generation. |
| [T37][w3c-T37] | Header omits mustUnderstand | Partial | [Body-scoped XPath][xpath-tests] covers the SOAP 1.1 counterpart. Share the SOAP 1.2 omitted-mustUnderstand acceptance check with the earlier optional-header case. |
| [T38][w3c-T38] | Four lexical forms of mustUnderstand | Partial | [Header role check][roles] exercises 1, true, and false with omitted role. [Header metadata tests][header-tests] also build a SOAP 1.2 block with true. The receive matrix lacks 0 and does not exercise upstream application-header processing. |
| [T39][w3c-T39] | Unknown Header block with invalid mustUnderstand | Gap | Add a synthetic reply and assert XML_INVALID with no queryable Body. A Sender Fault is the upstream peer outcome. |
| [T40][w3c-T40] | IPv6 literal in the Header block namespace URI | Gap | Use an optional unknown reply header with an IPv6 literal in its namespace URI and verify Body acceptance without network access. |
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
| [T64][w3c-T64] | XML notation declaration | Partial | [Declaration and XML rejection][declaration] covers DOCTYPE rejection. Add a synthetic notation declaration only if separate regression evidence is needed. |
| [T65][w3c-T65] | Unparsed entity declaration | Partial | [Payload validity][invalid-payload] checks entity and DTD input rejection. A receive-side unparsed-entity fixture would isolate the upstream shape without resolving entities. |
| [T66][w3c-T66] | Accept an explicit UTF-8 XML declaration | Adapted | [Public echo check][echo] compares declared and undeclared accepted Body content and asserts the marker. The upstream peer responds to an application header. |
| [T67][w3c-T67] | Accept an XML declaration with standalone=yes | Partial | [Declaration and XML rejection][declaration] asserts standalone=yes with UTF-8 on a SOAP 1.1 reply. Add a standalone-only SOAP 1.2 variant if extending the declaration matrix. |
| [T68][w3c-T68] | Accept extra Envelope and Header whitespace | Gap | Compare compact and formatted synthetic SOAP 1.2 replies at Client.parse and assert equivalent XPath values. |
| [T69][w3c-T69] | Reject a missing Body | Partial | [Envelope structure][envelope] rejects a SOAP 1.1 Envelope without Body. Add SOAP 1.2 response acceptance coverage for this shape. A peer would generate the Fault. |
| [T70][w3c-T70] | Reject a Trailer following Header and Body | Partial | [Envelope structure][envelope] rejects an unexpected direct Envelope child before Body and extra content after the Envelope. Add a SOAP 1.2 child after Body for the exact receive shape. |
| [T71][w3c-T71] | Reject an unqualified attribute on Envelope | Decision | [Current Envelope validator][validator] checks XML attribute names and duplicates. Decide whether to enforce this SOAP-specific restriction on replies before adding a test. |
| [T72][w3c-T72] | Reject encodingStyle on Envelope | Decision | [Current Envelope validator][validator] does not enforce this placement rule. Resolve applicability with the related Body attribute case. |
| [T73][w3c-T73] | RPC echo with encodingStyle on payload and argument | Outside | Peer interprets encoding-style scopes and RPC return semantics. |
| [T74][w3c-T74] | SOAP role and mustUnderstand occur on a descendant | Gap | Add an optional unknown reply Header block with those attributes on a child and assert Body acceptance. |
| [T75][w3c-T75] | Resolve a relative XLink against xml:base | Outside | Requires peer processing of an application reference. Client XPath reads XML content without link resolution. |
| [T76][w3c-T76] | Inline and referenced strings produce the same RPC result | Outside | Peer interprets SOAP Encoding references and checks semantic equivalence. |
| [T77][w3c-T77] | RPC distinguishes absent arguments and xsi:nil | Outside | Peer interprets argument presence and XSD nil semantics. |
| [T78][w3c-T78] | Known header explicitly targets ultimateReceiver | Outside | Peer processes the application header and generates a reply header. |
| [T79][w3c-T79] | Intermediary forwards a header to ultimateReceiver | Outside | Requires a second hop and application processing by the peer. |
| [T80][w3c-T80] | Unsupported encoding produces DataEncodingUnknown | Partial | [Public Fault checks][fault] cover qualified Fault projection. A client test could supply that code explicitly. Detecting unsupported payload encoding and generating the Fault belong to the peer. |

## HTTP binding

| W3C case | Behavior | Status | Evidence and next action |
| --- | --- | --- | --- |
| [TH1][w3c-TH1] | SOAP 1.2 POST returns HTTP 200 with SOAP XML | Direct | [Public echo check][echo] and [receiver request check][wire] assert a SOAP 1.2 exchange with the expected request and reply media types, HTTP 200, and an accepted Body marker. This evidence covers the HTTP binding behavior with a synthetic echo payload. |
| [TH2][w3c-TH2] | Missing Body yields HTTP 400 Sender Fault | Partial | [Envelope structure][envelope] covers missing Body rejection and [Fault projection][fault-structure] covers Sender at other statuses. Add a peer-supplied HTTP 400 Sender reply if prioritizing Fault projection. |
| [TH3][w3c-TH3] | SOAP 1.1 request yields HTTP 500 VersionMismatch | Partial | [VersionMismatch check][version-fault] asserts HTTP 500 and Fault projection for a SOAP 1.1 reply. The upstream binding example supplies a SOAP 1.2 Fault instead and tests what the peer returns. |
| [TH4][w3c-TH4] | Mandatory header failure yields HTTP 500 MustUnderstand | Partial | [Header role check][roles] covers local rejection, and [public Fault checks][fault] cover HTTP 500 projection with other codes. Consider a supplied MustUnderstand reply if the client outcome needs evidence. |
| [TH5][w3c-TH5] | Unsupported media type yields HTTP 415 | Outside | Request media negotiation is tested at the peer. [Plain response cases][plain-tests] cover a generic HTTP error result at a different status. |

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
| [SBR2-echoMeUnknown][w3c-SBR2-echoMeUnknown] | Optional and mandatory unknown blocks for next or an unrelated role | Partial | [Header role check][roles] accepts a mandatory block for an unrelated role. Add acceptance for the optional variants and rejection for a mandatory next block if extending this matrix. The peer still owns Fault generation. |

## XMLP interoperability

| W3C case | Behavior | Status | Evidence and next action |
| --- | --- | --- | --- |
| [XMLP-1][w3c-XMLP-1] | RPC argument omitted | Outside | Peer determines the RPC default result or Fault for a missing argument. |
| [XMLP-2][w3c-XMLP-2] | HTTP GET returns a document-style SOAP reply | Partial | k6 owns HTTP GET. [Public echo check][echo] verifies parsing an HTTP 200 SOAP reply received via POST. Add a GET fixture only if the client contract needs explicit evidence. |
| [XMLP-3][w3c-XMLP-3] | HTTP GET returns an RPC-style SOAP reply | Outside | k6 owns HTTP GET. Peer produces the RPC result and its typed interpretation is outside the client contract. |
| [XMLP-4][w3c-XMLP-4] | RPC parameter order differs | Outside | Peer binds RPC arguments by the expected rules. Ordered XML output is a separate contract. |
| [XMLP-5][w3c-XMLP-5] | SOAP 1.1 request yields a SOAP 1.2 VersionMismatch reply | Partial | [Envelope structure][envelope] covers a configured-version mismatch in the opposite direction. A separate SOAP 1.1 Client.parse test could show withholding on a SOAP 1.2 reply. Peer HTTP status and Upgrade generation are separate. |
| [XMLP-6][w3c-XMLP-6] | Mandatory unknown header yields HTTP 500 MustUnderstand | Partial | [Header role check][roles] covers local withholding and [public Fault checks][fault] cover other HTTP 500 Faults. Share the supplied MustUnderstand Fault projection proposed for the HTTP binding case. |
| [XMLP-7][w3c-XMLP-7] | HTTP 400 SOAP 1.2 Sender Fault | Partial | [Fault projection][fault-structure] asserts Sender with HTTP 200 and 500. Assert preservation of HTTP 400 and the qualified Fault code at Client.parse if adding a public status matrix. |
| [XMLP-8][w3c-XMLP-8] | HTTP 500 SOAP 1.2 Receiver Fault | Direct | [Public Fault checks][fault] assert HTTP 500 and the qualified Receiver code, reason, and Detail from a synthetic reply. This covers the client-visible outcome. |
| [XMLP-9][w3c-XMLP-9] | Unknown encoding on an RPC argument | Partial | [Public Fault checks][fault] exercise projection with other codes. A client test could assert a supplied DataEncodingUnknown Fault. Argument encoding and fault generation belong to the peer. |
| [XMLP-10][w3c-XMLP-10] | RPC call includes typed and untyped arguments | Outside | Peer interprets a mix of explicitly typed and untyped RPC parameters. |
| [XMLP-11][w3c-XMLP-11] | Invalid integer argument yields BadArguments Subcode | Partial | [Fault projection][fault-structure] covers qualified Sender Subcodes generally. A supplied BadArguments Fault could exercise that exact projection. The peer validates the RPC argument. |
| [XMLP-12][w3c-XMLP-12] | Unknown operation yields ProcedureNotPresent Subcode | Partial | [Fault projection][fault-structure] covers qualified Sender Subcodes generally. Share a supplied ProcedureNotPresent fixture with the missing-procedure case if selected. |
| [XMLP-13][w3c-XMLP-13] | Forwarding intermediary returns original message | Outside | Requires operating an intermediary and checking preserved wire content. |
| [XMLP-14][w3c-XMLP-14] | Active intermediary processes and forwards a message | Outside | Requires a peer to act as an active intermediary. |
| [XMLP-15][w3c-XMLP-15] | Intermediary removes optional next Header block | Outside | Requires removal from a forwarded Envelope. |
| [XMLP-16][w3c-XMLP-16] | Intermediary retains optional none Header block | Outside | Requires preservation across a forwarding hop. |
| [XMLP-17][w3c-XMLP-17] | Intermediary retains ultimateReceiver Header block | Outside | Requires preservation across a forwarding hop. |
| [XMLP-18][w3c-XMLP-18] | Intermediary retains a targeted header marked relay=true | Outside | Requires SOAP forwarding and relay semantics. |
| [XMLP-19][w3c-XMLP-19] | Mandatory next header stops intermediary forwarding | Outside | Requires a peer Fault and no forwarded exchange. [Header role check][roles] provides adjacent ultimate-receiver rejection evidence. |

## Default-role and Fault adaptations

The public custom-k6 loopback runs the [explicit-role controls][roles] and
three replies with omitted role and the same Body marker. Both mandatory
values, `1` and `true`, return `POLICY_VIOLATION` at `parse`, null Body and
Fault, and XPath `CONTENT_UNAVAILABLE`. The `false` variant exposes the marker
through XPath. These checks draw on [T11][w3c-T11], [T13][w3c-T13],
[T35][w3c-T35], and [T38][w3c-T38].

For the client side of [T30][w3c-T30], a SOAP 1.1-configured client parses a
synthetic SOAP 1.1 reply and exposes the qualified `VersionMismatch` code.
The supplied `Upgrade` Header block is fixture data. The test asserts Fault
projection, with peer generation and version selection outside its scope.

Resolve the mixed-version mustUnderstand policy before adding an adaptation
of [T34][w3c-T34]. Keep the Envelope attribute placement questions separate as well.

[collection]: https://www.w3.org/TR/2007/REC-soap12-testcollection-20070427/#tests
[contracts]: contracts.md
[architecture]: architecture.md#5-payload-envelopes-and-headers
[echo]: ../test/e2e/http.js#L29
[fault]: ../test/e2e/http.js#L89
[roles]: ../test/e2e/http.js#L123
[version-fault]: ../test/e2e/http.js#L102
[wire]: ../test/e2e/http_test.go#L65
[object]: ../test/e2e/object.js#L5
[invalid-payload]: ../internal/message/message_test.go#L55
[envelope]: ../internal/message/message_test.go#L81
[declaration]: ../internal/message/xml_declaration_test.go#L7
[fault-structure]: ../internal/message/fault_test.go#L9
[header-tests]: ../internal/message/headers_test.go#L60
[plain-tests]: ../internal/message/response_test.go#L15
[xpath-tests]: ../internal/message/response_test.go#L38
[optional-content]: ../internal/message/response_test.go#L86
[signed-header]: ../internal/wssec/headers_test.go#L62
[header-policy]: ../internal/message/response.go#L336
[validator]: ../internal/message/xml.go#L75

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
