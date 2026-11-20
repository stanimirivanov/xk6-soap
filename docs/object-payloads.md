# Deterministic object payloads

PR-15 adds object payloads to `Client.build(operation,payload,opts)`. Set a nonempty
`namespace` on the Client constructor. This wraps the object in that namespace's
operation element; it does not discover a service schema or infer XSD types.

```js
const client=new Client({url:'https://example.test/service',namespace:'urn:orders'});
const request=client.build('Order',{
  '@id':'synthetic',
  customer:'Alice & Bob',
  line:[{sku:'A',quantity:2},{sku:'B',quantity:1}],
  note:{'@lang':'en','#text':'Handle <carefully>'},
  empty:{},
  omitted:[],
});
```

The operation uses a default namespace, inherited by unprefixed child elements.
Unprefixed attributes have no namespace. The example's operation XML is:

```xml
<Order xmlns="urn:orders" id="synthetic"><customer>Alice &amp; Bob</customer><line><sku>A</sku><quantity>2</quantity></line><line><sku>B</sku><quantity>1</quantity></line><note lang="en">Handle &lt;carefully&gt;</note><empty></empty></Order>
```

Only plain JavaScript objects (including null-prototype objects) and ordinary dense
arrays at named child properties are mapped. Own enumerable string keys follow
JavaScript enumeration order, captured as a key snapshot per object before walking
values. Attributes retain their relative order and are emitted before content as
XML requires; children are not sorted. `@name` creates a scalar attribute; `#text`
creates scalar text. Arrays repeat the named element in index order, empty arrays
emit nothing and empty objects emit paired empty elements. Strings, finite numbers
and booleans become text using JavaScript scalar formatting (`-0` becomes `0`).

Accessor values are read once in traversal order through own property descriptors;
inherited fields are never fetched. Added keys do not enter an existing snapshot;
deleting a pending key causes rejection instead of reading a prototype fallback.
Getter exceptions are sanitized. Non-enumerable object properties are ignored;
enumerable symbol keys are rejected. Dense array indices must be own properties;
holes, extra array properties, nested arrays and custom array prototypes are rejected.
Shared noncyclic subobjects can be reused. Cycles on the active traversal path fail.

Null, undefined, functions, symbols, BigInt, non-finite numbers, boxed primitives,
Dates, Maps/Sets, typed arrays, proxies and custom object prototypes are rejected.
Attribute/text values cannot be objects or arrays. `#text` cannot coexist with any
named child property, even an empty array. Prefixes, namespace-declaration keys,
invalid XML names/characters and unpaired UTF-16 surrogates are rejected. Object
namespace values cannot be empty, reserved XML/SOAP namespaces or contain whitespace
or invalid XML characters. Unknown per-build namespace overrides remain rejected.

The Sobek adapter captures an ordered runtime-independent tree; it does not export
payload objects to Go maps. Shared module state remains limited to key and metric ownership;
payload trees, intrinsic references and JavaScript values stay per VU/request.
The standard Go XML encoder owns escaping, with bounded output. Capture applies
byte/node/depth/attribute budgets and checks cancellation during traversal. The
existing final envelope validator enforces the configured complete-envelope limits,
including wrapper overhead, before security processing. Mapping failures throw
sanitized `INVALID_ARGUMENT` or `LIMIT_EXCEEDED` errors at the payload boundary;
cancellation retains `CANCELLED`. No partial request is returned.

Raw primitive XML strings retain their existing lexical path, including CDATA and
multiple namespaces, regardless of a Client's object namespace. They are inserted
as the sole operation element, without another object wrapper. Use raw XML when
children/attributes need different namespaces or prefixed names. Object input does
not provide header/WS-Addressing inputs; those remain separate tasks.

Tests cover exact envelope/order fixtures, shared references, mutations/getters,
namespace inheritance, attributes/text, escaping, Unicode, invalid inputs and output
budgets, plus a final-wire signature check. Native k6 echo E2E verifies both SOAP
versions and confirms object payload sentinels do not appear in diagnostic output.
