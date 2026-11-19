# Plain SOAP Client API

PR-4 enables raw-XML `build()` and plain-response `parse()` on the named `Client`
export. Security, keys, object payloads, custom headers/WS-Addressing, production
SOAP metrics and payload diagnostics remain unavailable and are rejected as
unsupported options. Plain results make no authenticity claim.

```js
import { Client } from 'k6/x/soap';
import http from 'k6/http';
import { check } from 'k6';

export const options = { thresholds: { checks: ['rate==1'] } };
const client = new Client({url:'https://example.test/service',soapVersion:'1.1'});
export default function () {
  const request = client.build('Echo',
    '<m:Echo xmlns:m="urn:example">hello</m:Echo>', {soapAction:'urn:echo'});
  const response = http.post(request.url, request.body, {
    headers:request.headers, responseType:'text', redirects:0,
  });
  const parsed = client.parse(response);
  check(parsed, {'SOAP accepted':p=>p.ok});
  const matches = parsed.xpath('//m:Result',{m:'urn:example'});
}
```

Construct clients in init. `url` is required and must be an absolute HTTP(S) URL
with a host and no credentials or fragment. `soapVersion` is `1.1` (default) or
`1.2`. `limits` accepts positive `bytes`, `depth`, `nodes`, and `attributes`, no
larger than the defaults in [the message boundary](message-boundary.md). Omitted
limits use defaults; explicit zero or unsupported increases fail. `debug:false`
is accepted; debug output is not yet implemented. Unknown option keys and invalid
types are rejected. No implicit JavaScript string/number coercion is performed.

`build(operation,rawXML,{soapAction})` and `parse(response)` require execution
context and check VU cancellation. Local errors throw TypeError with stable
`code` and `stage` properties; diagnostics omit XML, credentials and supplied
URLs. Build returns `{url,body,headers,buildDuration}`; duration is milliseconds.
Only raw operation strings and soapAction are currently accepted, following
PR-3's operation/namespace/header/limit rules.

Parse accepts a k6 response or `{status,body}` object. Status is an integer
0–599. Text bodies and attached ArrayBuffers are accepted; binary data must be
UTF-8 XML. Missing/null/empty/discarded bodies yield BODY_UNAVAILABLE. Other body
types are local INVALID_ARGUMENT errors. Status 0 yields TRANSPORT_ERROR before
looking at body; non-2xx responses may still carry accepted SOAP Faults.

Results contain `{ok,status,body,fault,error,sigVerified,timestampValid,xpath}`.
In plain mode both verification flags are null. `ok` requires accepted SOAP XML,
HTTP 2xx and no direct Body Fault. `body` is accepted Body inner XML, reserialized
for inspection; it is not canonical or suitable for signature verification.
Rejected XML/policy/limit results expose null body/fault. Empty 202/204 is not a
successful one-way SOAP operation in this version.

Errors are null or `{code,stage,message}`. Precedence is transport/unavailable
body, XML/limits/policy, SOAP_FAULT, HTTP_STATUS. Accepted Faults are retained on
HTTP 200 or error status. Fault fields are `code:{namespace,localName}`, `subcodes`,
`reason`, `reasons:[{lang,text}]`, `role`, `node`, and `detail` (inner XML).
Unavailable fields are null or empty arrays. SOAP 1.2 prefers English Reason text,
then the first supplied language. Malformed required Fault fields fail as XML_INVALID.

Parsing rejects targeted unknown mandatory SOAP headers and encryption structures
that plain mode cannot consume. Supported WS-Addressing header names are recognized;
this does not enable signing, correlation or policy negotiation. Optional unrecognized
headers are ignored. Signature verification is skipped; plaintext is unverified.

## XPath boundary

`parsed.xpath(expression,nsMap)` returns `{value,error}` without changing the
original result. Scalars retain string/number/boolean type; node sets return an
array of string-values in document order. Fault and HTTP-error results with
accepted content remain queryable. Rejected/unavailable content returns
CONTENT_UNAVAILABLE. Invalid expressions/maps/prefixes return XPATH_INVALID.

Evaluation sees a detached Body element with no envelope, header or sibling
links; ancestor/absolute paths cannot escape that projection. Use relative paths
or `//prefix:Result`. Default namespaces need explicit query prefixes. Limits are
4096 expression bytes, 64 prefix bindings (4096 bytes each), 1000 result items
and total returned string bytes no larger than the client XML byte budget.
Namespace wildcard expansion has a 32 KiB compiled-expression cap. These are
finite input/output limits, not a hard execution-time guarantee for a costly
user-supplied XPath expression. No global compilation cache is used.

Pinned dependencies are xmlquery v1.5.2 and xpath v1.3.9 (MIT). The adapter binds
unprefixed name tests to the empty namespace and expands namespace wildcards to
URI predicates because the engine otherwise uses source-prefix matching. A small
navigator adapter preserves CDATA string-values. Literal strings, axes, operators,
functions, prefix maps and cursor copying/movement have regression tests.
See the [xmlquery API](https://pkg.go.dev/github.com/antchfx/xmlquery) and
[XPath API](https://pkg.go.dev/github.com/antchfx/xpath). Compilation/evaluation
errors and library panics become sanitized result errors.

`make smoke e2e` exercises the actual custom k6 binary, including text/binary echo,
both SOAP fault versions, discarded bodies, HTTP timeouts and disconnects. Unit
and fuzz seeds cover malformed remote data, resource boundaries, namespace/scalar
semantics and Body isolation. These establish CP-A for plain SOAP, not secured
message interoperability.
