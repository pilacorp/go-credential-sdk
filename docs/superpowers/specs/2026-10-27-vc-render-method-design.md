# VC Render Method SDK Support

Status: Draft for review  
Audience: Go Credential SDK maintainers and implementers  
Scope: JSON-LD Verifiable Credentials secured with W3C Data Integrity

## 1. Summary

Add support for the W3C Verifiable Credential Render Method extension to the SDK.

The first release will support both sides of the flow:

- issuer-side creation of VC render methods and templates;
- consumer-side reading, selecting, and processing render methods.

Specifically, it will:

- model and preserve `renderMethod` in credentials;
- support one or more render-method entries;
- implement authoring and consumer support for all three standard render suites: `summary`, `html`, and `static`;
- resolve RFC 6901 JSON Pointers;
- support embedded and externally referenced templates;
- validate and, when present, verify digests for externally referenced templates;
- create all three standard render suites: `summary`, `html`, and `static`;
- expose HTML and static render methods as validated metadata/payloads; client applications own actual rendering and delivery.

The feature is experimental because the W3C Render Method specification and its suite details may evolve. The implementation target for this specification is the published W3C Working Draft on the Recommendation Track at `/TR/vc-render-method/`, not the editor's draft. The SDK must isolate the API and avoid making unrelated credential APIs depend on this feature.

## 2. Problem

A VC contains signed claims, but normally does not express how an issuer expects those claims to be presented to a human. Wallets must choose fields, labels, ordering, layout, branding, and accessibility behavior themselves. This can cause important claims to be omitted or relabeled even though the credential remains cryptographically valid.

The W3C Render Method extension lets an issuer attach signed rendering instructions to a VC. A client can select a supported method and render the credential according to that method. Unsupported suites are ignored so a credential can carry multiple alternatives.

## 3. Goals

### 3.1 In scope

1. Let issuers create VC render methods with embedded or referenced templates.
2. Represent the VC `renderMethod` property in `CredentialContents` and credential payloads.
3. Preserve render methods through JSON-LD parsing, serialization, canonicalization, signing, and verification paths.
4. Accept both a single render-method object and an array on input.
5. Provide constructors for the `summary`, `html`, and `static` suites.
6. Provide a normalized API for selecting supported suites.
7. Implement deterministic `summary` template processing, complete `html` render artifact preparation, and `static` payload resolution.
8. Validate summary templates before and after pointer substitution.
9. Support `data:` templates and fetched templates through an injectable fetcher.
10. Generate and verify SHA-256 multihash digests when requested.
11. Provide validated HTML/static metadata and payloads for client-side rendering; for `html`, the SDK prepares the filtered credential and the `srcdoc` wrapper (CSP, data block, and the wrapper-side lifecycle script) but does not execute it; the host page owns the sandboxed iframe, its CSP, and the `MessageChannel`.
12. Document the experimental status, security boundaries, and compatibility behavior.

### 3.2 Non-goals

- Executing HTML/JavaScript templates in Go or any SDK runtime.
- Starting or controlling a browser/WebView runtime.
- Rendering PDFs, images, audio, haptic output, or NFC payloads.
- Defining a registry for custom render suites.
- Fetching external resources referenced by an HTML template.
- Guaranteeing that a wallet actually uses or faithfully displays a render method.
- Treating render metadata as a replacement for credential proof verification.

## 4. Compatibility and normative behavior

The SDK follows the published W3C Render Method specification where practical:

- `renderMethod` represents one or more rendering methods.
- A supported method has `type: "SuiteRenderMethod"` and a recognized `renderSuite`.
- Unknown or unsupported suites are ignored by render selection.
- `renderProperty` uses RFC 6901 JSON Pointer syntax.
- `summary` templates use JSON Pointer strings to reference values in the VC.
- `fields[].label` must be a literal string; `fields[].value` must be a JSON Pointer.
- A failed required validation returns an error.
- A missing pointer in a required summary member returns an error; a missing pointer in an optional summary member omits that member. Missing HTML `renderProperty` pointers return an error.

The implementation must not infer that a render method is trustworthy merely because the containing VC is signed. If an external digest is present, it MUST pass verification before use. Digest fields remain optional because the TR defines them as optional; template retrieval remains privacy-sensitive.

## 5. Data model

### 5.1 Credential contents

Add a field to `credential/vc.CredentialContents`:

```go
RenderMethods []RenderMethod `json:"renderMethod,omitempty"`
```

The internal representation is always a slice. Parsing accepts either an object or an array to handle the W3C data model and existing credentials.

### 5.2 Render method

```go
type RenderMethod struct {
	ID               string            `json:"id,omitempty"`
	Type             string            `json:"type"`
	RenderSuite      string            `json:"renderSuite"`
	Name             string            `json:"name,omitempty"`
	Description      string            `json:"description,omitempty"`
	RenderProperty   []string          `json:"renderProperty,omitempty"`
	Template         json.RawMessage   `json:"template,omitempty"`
	DigestMultibase  string            `json:"digestMultibase,omitempty"`
	OutputPreference *OutputPreference `json:"outputPreference,omitempty"`
	DeliveryMode     string            `json:"deliveryMode,omitempty"`
}
```

The public model uses a typed template wrapper. The wire encoder converts it to the suite-specific JSON representation.

```go
type Template struct {
	Embedded  *EmbeddedTemplate
	Reference *TemplateReference
}

type EmbeddedTemplate struct {
	MediaType string
	Bytes     []byte
}
```

Exactly one of `Embedded` or `Reference` MUST be set. Embedded templates do not require a digest and the SDK MUST NOT add one automatically. External references MAY include `DigestMultibase`; when present, it MUST be valid and pass verification before use.

```go
type TemplateReference struct {
	ID              string `json:"id"`
	MediaType       string `json:"mediaType,omitempty"`
	DigestMultibase string `json:"digestMultibase,omitempty"`
}

type OutputPreference struct {
	AccessMode []string     `json:"accessMode,omitempty"`
	MediaType  string       `json:"mediaType,omitempty"`
	Style      *RenderStyle `json:"style,omitempty"`
}

type RenderStyle struct {
	Width  string `json:"width,omitempty"`
	Height string `json:"height,omitempty"`
}
```

For supported suites, unknown properties are rejected during authoring and strict validation. An entry whose `renderSuite` is not supported by the SDK is retained as an opaque entry and ignored by suite-specific processors, as required by the W3C processing rule. The model retains top-level `id` and `digestMultibase` even when remote render-method processing is deferred.

### 5.3 JSON-LD render-method context

The VC v2 context defines the top-level `renderMethod` property. The SDK does not automatically add a context. When render methods are used, the active JSON-LD context MUST define every render-method term used by the credential; otherwise authoring/signing fails. The W3C Credentials Examples v2 context is accepted, and an issuer MAY provide an equivalent custom context.

The SDK MUST preserve the caller's context and MUST reject conflicting definitions that would change the meaning of render-method terms. Canonicalization tests MUST verify that all supported render-method fields survive when the caller supplies the required context.

### 5.3 Suite-specific object rules

The common object is interpreted according to `renderSuite`.

#### 5.3.1 `summary`

For `summary`:

- `template` MUST be, or dereference to, a JSON document conforming to `SummaryObject`.
- `renderProperty` is not used to select exposed fields; the JSON Pointers in the summary template define exposure.
- `outputPreference` MAY be present. `accessMode` and `style` are display hints.
- The template and rendered output share the same object shape.
- String members MAY contain JSON Pointers, except `fields[].label`.
- `fields[].label` MUST be a literal string.
- `fields[].value` MUST be a JSON Pointer string.
- Compound values assembled from multiple pointers are not supported.

```go
type SummaryTemplate struct {
	Name        string         `json:"name"`
	Description string         `json:"description"`
	Icon        string         `json:"icon,omitempty"`
	Theme       *SummaryTheme  `json:"theme,omitempty"`
	Fields      []SummaryField `json:"fields"`
	ValidFrom   string         `json:"validFrom,omitempty"`
	ValidUntil  string         `json:"validUntil,omitempty"`
}

type SummaryTheme struct {
	PrimaryColor string `json:"primaryColor,omitempty"`
	AccentColor  string `json:"accentColor,omitempty"`
}

type SummaryField struct {
	Label     string `json:"label"`
	Value     string `json:"value"`
	Language  string `json:"language,omitempty"`
	Direction string `json:"direction,omitempty"`
}
```

`name`, `description`, `fields`, and each field's `label` and `value` are required. `icon`, `theme`, `validFrom`, and `validUntil` are optional.

#### 5.3.2 `html`

For `html`:

- `template` provides an HTML fragment through a `data:` URL or a referenced template object.
- The fragment MUST NOT contain `<html>`, `<head>`, or `<body>` elements.
- `renderProperty` MAY restrict the VC data passed to the template.
- If `renderProperty` is absent, the entire VC is presumed to be shared with the template environment.
- `outputPreference` MAY provide `accessMode`, `mediaType`, and iframe `style.width`/`style.height` hints.
- The template is expected to read a filtered credential from an `application/vc` data block.
- The SDK authoring and consumer APIs validate, resolve, filter, and package the HTML payload into a complete render artifact; the client application owns execution and browser/WebView lifecycle.

#### 5.3.3 `static`

For `static`:

- `template` provides a static binary payload, commonly through a `data:` URL or a referenced object.
- `deliveryMode` identifies the intended delivery mechanism, such as `nfc`. It is optional, as in the W3C TR; the SDK does not require it and returns it unchanged in `StaticOutput`.
- `renderProperty` MAY identify the VC properties represented by the static payload.
- `outputPreference` is generally not used.
- The SDK returns verified payload bytes and metadata; interpretation and delivery belong to the application layer.

#### 5.3.4 Render method `id`

When the common `id` property is present, it identifies the render method and
must follow the URL Standard, as WD-20261013 §2.2 requires. The SDK validates
it with a URL Standard parser. To render from `id`, a
consumer calls `RenderMethod.Dereference` with its fetcher, then renders the
returned method. Rendering otherwise uses `template`.

When present, `digestMultibase` is checked while dereferencing the remote
method. This is distinct from `template.digestMultibase`, which protects the
template bytes referenced by `template`.

## 6. Validation

### 6.1 Common validation

When creating a credential through structured contents:

- `type` is required and must equal `SuiteRenderMethod` for a suite method;
- `renderSuite` is required and non-empty;
- `id` and `template.id`, when present, must parse under the URL Standard (WD-20261013 §2.2);
- a URL is refused above 8 KiB, unless it is a `data:` URL of the form `data:<media type>,<data>`, which holds a template. `data://...` has an authority and is bounded like any other URL. The URL Standard sets no limit; this one bounds the parser's time on one id taken from a credential. It does not bound the number of ids: a credential filled with 8 KiB ids that are all userinfo takes about 6 s of parsing per MiB, so the application bounds the credential size;
- a `Fetcher` receives the id as the URL Standard parser serializes it, so a check on its host sees the host that is requested. An RFC 3986 client still refuses some of these URLs, such as one with a `%` that starts no escape, and the fetch fails;
- for a suite this SDK renders, a `data:` URL in `template.id` carries the template in the credential, read by the same rule as a `data:` string in `template`, so `Validate()` decodes it, verifies its `digestMultibase` when present, and applies the suite content rules before signing;
- every `renderProperty` must be a valid JSON Pointer;
- `template`, when present, must match the wire shape required by its suite;
- external template references MAY include `digestMultibase`;
- every `digestMultibase` that is present (on the render method or on its template reference) is syntax-checked by `Validate()`: it MUST be multibase `u` (base64url-nopad) wrapping a SHA-2-256 multihash (`0x12`, 32-byte hash), as the W3C TR requires. Values using other multibase encodings, such as base58btc `z` seen in the TR's non-normative examples, are rejected;
- embedded templates MUST NOT require or receive an automatically generated digest;
- digest strings are syntax-checked and verified before an external template is processed;
- after retrieval and digest verification, an external template MUST pass the same suite-specific content validation as an embedded template, because its content is not covered by the credential signature;
- when an external template reference omits `mediaType`, the suite's expected media type is assumed for that validation (`application/json` for `summary`, `text/html` for `html`); a `mediaType` that is present must match as it does for embedded templates.

Unknown `renderSuite` values are not rejected by credential parsing. They are retained but ignored by suite-specific renderers.

### 6.2 Summary template validation

The summary validator requires:

- `name`, `description`, and `fields` are present and not null (as in the W3C TR, REQUIRED means present: an empty string or an empty `fields` array is allowed);
- each field has `label` and `value`, present and not null;
- each `label` is a literal string;
- each `value` starts with `/` and is a valid JSON Pointer;
- optional `theme`, language, direction, and validity properties have the expected types;
- unsupported additional properties are rejected; the initial release has no permissive summary-template mode.

The output is validated again after pointer substitution. Missing pointers in required members fail; missing pointers in optional summary members omit those members.

## 7. Issuer-side authoring API

The SDK must support creating render methods before the credential is signed. A render method is part of the credential payload and therefore becomes protected by the credential proof when signing occurs.

### 7.1 Object-first authoring API

Render methods are declarative data objects that map directly to the W3C object model. The primary authoring API MUST use a single `RenderMethod` struct literal; `renderSuite` selects suite-specific validation. Functional options are not required.

```go
summaryMethod := vc.RenderMethod{
	Type:        "SuiteRenderMethod",
	RenderSuite: "summary",
	Name:        "Degree summary",
	Description: "Display the main degree information",
	Template:    template,
}

htmlMethod := vc.RenderMethod{
	Type:          "SuiteRenderMethod",
	RenderSuite:   "html",
	RenderProperty: []string{
		"/issuer/name",
		"/credentialSubject/name",
	},
	Template: template,
}

staticMethod := vc.RenderMethod{
	Type:         "SuiteRenderMethod",
	RenderSuite:  "static",
	Template:     payload,
	MediaType:    "application/pdf",
	DeliveryMode: "download",
}

if err := summaryMethod.Validate(); err != nil {
	return err
}
if err := htmlMethod.Validate(); err != nil {
	return err
}
if err := staticMethod.Validate(); err != nil {
	return err
}
```

The suite-specific objects are converted to the common `RenderMethod` wire representation when attached to a credential. The SDK MAY provide small constructors as convenience helpers, but they MUST NOT be the only way to create a method and MUST NOT hide the object fields behind functional options.

For common embedded and referenced-template cases, convenience helpers MAY be provided:

```go
embedded, err := render.NewEmbeddedTemplate(template)

referenced := vc.RenderMethod{
	Type:        "SuiteRenderMethod",
	RenderSuite: "summary",
	Template: vc.TemplateReference{
		ID:              "https://example.com/templates/degree.json",
		MediaType:       "application/json",
		DigestMultibase: digest,
	},
}
```

The authoring API must:

- validate the suite-specific structure locally;
- validate JSON Pointers in `renderProperty` and summary fields;
- serialize embedded templates as `data:` URLs or the suite-defined embedded object;
- accept external template references without requiring a network call by default;
- optionally validate an external template through an injected fetcher;
- accept optional `digestMultibase` for external template references and verify it when present;
- do not automatically calculate or add a digest for embedded templates;
- return or convert to a `RenderMethod` that can be placed in `CredentialContents.RenderMethods`.

### 7.2 Adding methods to a credential

The issuer creates the credential with render methods already attached:

```go
credential, err := vc.NewJSONCredential(vc.CredentialContents{
	Context: []interface{}{"https://www.w3.org/ns/credentials/v2"},
	Types:   []string{"VerifiableCredential", "UniversityDegreeCredential"},
	Issuer:  "did:example:issuer",
	Subject: []vc.Subject{{CustomFields: map[string]interface{}{
		"name":   "Nguyen Van A",
		"degree": "Bachelor of Science",
	}}},
	RenderMethods: []vc.RenderMethod{summaryMethod, htmlMethod},
})

err = credential.AddProofByProvider(signer)
```

`renderMethod` must be present in the signing input. Modifying it after signing must invalidate verification. The SDK must not provide a mutation path that silently changes render metadata while retaining a valid proof.

### 7.3 Authoring-time network behavior

Creating a render method with an external template reference must not require network access by default. The issuer may opt into validation through an explicit validation call:

```go
method := vc.RenderMethod{
	Type:        "SuiteRenderMethod",
	RenderSuite: "summary",
	Template: vc.TemplateReference{
		ID:              url,
		MediaType:       "application/json",
		DigestMultibase: digest,
	},
}

err := method.ValidateExternalTemplate(ctx, fetcher)
```

If validation is requested, fetching, media-type validation, template validation, and digest verification must complete before the method is returned.

## 8. Consumer-side rendering API

Expose the render-method models, validators, fetchers, and consumer APIs
directly from the existing `credential/vc` package. A separate
`credential/vc/render` package is not required; render methods are part of the
VC data model and follow the SDK's existing package organization.

```go
type Fetcher interface {
	Fetch(ctx context.Context, ref TemplateReference) ([]byte, error)
}

type RenderOptions struct {
	Fetcher Fetcher
	// MaxSummaryOutputBytes caps the total size of values copied from the
	// credential into a summary. Zero or less uses a 1 MiB default.
	MaxSummaryOutputBytes int
}

func (m RenderMethod) RenderSummary(
	ctx context.Context,
	credential CredentialData,
	opts RenderOptions,
) (*SummaryTemplate, error)
```

The renderer must reject a method whose suite is not `summary`.

```go
```

### 8.1 Processing algorithm

1. Decode the template from an embedded `data:` URL or load it through `Fetcher`.
2. For an external template, verify `digestMultibase` when present; embedded templates have no digest requirement.
3. Validate the summary template.
4. Recursively inspect string-valued template properties.
5. Resolve strings beginning with `/` as RFC 6901 pointers against the credential.
6. Convert resolved non-string scalar values to their JSON string representation.
7. Omit missing optional summary members and return an error for missing required summary members.
8. Preserve literal strings unchanged.
9. Charge each resolved value against `MaxSummaryOutputBytes` and stop with an
   error when the budget is exceeded.
10. Return the normalized `SummaryTemplate`.

No field may combine values from multiple pointers. The SDK follows the current suite definition that each field value resolves from one pointer.

## 9. Template retrieval and integrity

External retrieval is injected through `Fetcher`; the core renderer must not create an unrestricted HTTP client.

The default HTTP implementation, if provided, must support:

- caller-supplied `http.Client`;
- request context and timeout;
- maximum response size;
- media-type checking;
- bounded redirects;
- digest verification before parsing;
- no credential data in request URLs or headers;
- no sensitive payload logging.

The normative digest format is a multibase value using base64url-no-padding (`u`) containing a SHA-256 multihash. Digest values remain optional; when supplied, the SDK validates and verifies them.

## 10. HTML render artifact boundary

The SDK will prepare the complete HTML render artifact but will not execute HTML or create a browser runtime.

For HTML, the SDK returns:

```go
type HTMLRenderArtifact struct {
	SrcDoc         string
	Width          string
	Height         string
}
```

The SDK must:

- validate the HTML fragment shape;
- fetch and digest-check an external payload before exposing it to the client;
- filter the credential using `renderProperty` and the W3C `selectJsonLd` algorithm;
- create the `application/vc` data block;
- create wrapper code containing the filtered credential and HTML payload;
- include the required CSP restrictions;
- return `srcdoc` integration data for the client-owned sandboxed iframe;
- include the wrapper script of WD-20261013 §3.2, which receives the `MessageChannel` port and defines `window.renderMethodReady`; the host page creates the `MessageChannel` and waits for the ready or error message;
- never evaluate template JavaScript or start a browser/WebView runtime.

The client application is responsible for creating or selecting the actual iframe/WebView, assigning `srcdoc`, executing the artifact, handling the ready/error result, and controlling the user-facing lifecycle. The SDK returns code and data; it does not run them.

For static methods, the SDK may return verified bytes plus `mediaType` and `deliveryMode`; it must not interpret the payload as trusted UI content.

## 11. JSON-LD Data Integrity behavior

This specification covers only JSON-LD Verifiable Credentials secured with Data Integrity. `renderMethod` is part of the document whose canonical representation is signed. Therefore:

- adding or modifying `renderMethod` after signing must invalidate verification;
- parsing and serializing must preserve the property without changing its semantic shape unexpectedly;
- every render-method term used by a credential must resolve through the active JSON-LD context;
- canonicalization must preserve the complete render-method object, including suite-specific fields;
- if a render-method term cannot be resolved, signing must fail rather than silently signing a partial object;
- an unrecognized render suite must not cause otherwise valid credential verification to fail.

VC-JWT, VC-JOSE, and SD-JWT are not processed by the render-method consumer
APIs, but their credential payload paths MUST preserve `renderMethod` unchanged.

## 12. Security and privacy requirements

- Never execute untrusted HTML/JavaScript in the Go process.
- Never treat a verified VC as proof that its template is safe.
- Verify supplied external template digests before parsing or rendering.
- Limit external response size and execution time.
- Avoid network fetching when an embedded template is available.
- Do not send credential claims to template servers.
- Do not fetch secondary assets from HTML templates in the SDK.
- Make missing pointers and invalid templates visible errors by default.
- Document tracking risks of externally hosted templates.

## 13. Testing and acceptance criteria

The feature is accepted when:

1. A credential with one render method round-trips through creation, serialization, and parsing.
2. A credential with multiple render methods preserves order.
3. Object and array input forms are both accepted.
4. Unknown suites are preserved and ignored by supported renderers.
5. A valid summary template produces the expected output for nested objects and arrays.
6. Pointer escaping for `~0` and `~1` works.
7. Missing pointers follow the configured policy.
8. Invalid summary templates fail before rendering.
9. Invalid resolved output fails after rendering.
10. Correct digests pass and incorrect digests fail.
11. External template fetching honors timeout and size limits.
12. The SDK creates an HTML artifact with only the claims selected by `renderProperty`.
13. The SDK never executes HTML/JavaScript; the client integration executes the returned artifact in its isolated environment.
14. Modifying signed render metadata causes proof verification failure.
15. Existing credential tests and public APIs remain compatible.

Required verification commands:

```bash
go test ./credential/...
go test ./...
go vet ./...
```

## 14. Decisions

The following decisions are fixed for this specification:

1. The public credential field is `RenderMethods []RenderMethod`; the wire property remains `renderMethod`.
2. The SDK accepts both object and array forms. One method serializes as an object; multiple methods serialize as an array.
3. Suite validation is strict. Unsupported additional fields in a suite object or summary template are rejected.
4. Missing required summary pointers fail; missing optional summary pointers are omitted; missing HTML `renderProperty` pointers fail.
5. Supplied digest values are validated and verified using the TR's SHA-256 multihash rules; digest values remain optional.
6. External template references MAY include `digestMultibase`.
7. Embedded templates do not require a digest, and the SDK does not add one automatically.
8. The initial release includes HTML artifact preparation but returns only `SrcDoc`, `Width`, and `Height`; the client owns the host-page iframe, CSP, sandbox, and lifecycle.
9. The SDK does not automatically add a context. When render methods are used, the active context must define the terms used by the credential. The W3C Credentials Examples v2 context and equivalent issuer-supplied contexts are allowed.

## 15. References

- W3C Verifiable Credential Rendering Methods v1.0: https://www.w3.org/TR/vc-render-method/
- W3C Credentials Examples vocabulary v2: https://www.w3.org/ns/credentials/examples/v2
- W3C Verifiable Credentials Data Model v2.1: https://www.w3.org/TR/vc-data-model-2.1/
- RFC 6901 JSON Pointer: https://www.rfc-editor.org/rfc/rfc6901
- W3C Data Integrity ECDSA Cryptosuites: https://www.w3.org/TR/vc-di-ecdsa/
- RFC 9458 Oblivious HTTP: https://www.rfc-editor.org/rfc/rfc9458
