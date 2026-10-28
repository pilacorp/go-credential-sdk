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
11. Provide validated HTML/static metadata and payloads for client-side rendering; for `html`, the SDK prepares the filtered credential, wrapper, CSP, sandbox, `srcdoc`, and lifecycle communication code but does not execute it.
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
- `deliveryMode` identifies the intended delivery mechanism, such as `nfc`.
- `renderProperty` MAY identify the VC properties represented by the static payload.
- `outputPreference` is generally not used.
- The SDK returns verified payload bytes and metadata; interpretation and delivery belong to the application layer.

#### 5.3.4 Remote render method

When the common `id` property is present, it identifies a remotely referenced render method. The fetched document is expected to provide the render method object and its `digestMultibase` protects the referenced render method. This is distinct from `template.digestMultibase`, which protects the template file referenced by the method.

## 6. Validation

### 6.1 Common validation

When creating a credential through structured contents:

- `type` is required and must equal `SuiteRenderMethod` for a suite method;
- `renderSuite` is required and non-empty;
- `id`, when present, must be a valid URL;
- every `renderProperty` must be a valid JSON Pointer;
- `template`, when present, must match the wire shape required by its suite;
- external template references MAY include `digestMultibase`;
- embedded templates MUST NOT require or receive an automatically generated digest;
- digest strings are syntax-checked and verified before an external template is processed.

Unknown `renderSuite` values are not rejected by credential parsing. They are retained but ignored by suite-specific renderers.

### 6.2 Summary template validation

The summary validator requires:

- `name`;
- `description`;
- `fields` with at least one item;
- each field has `label` and `value`;
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
summaryMethod := render.RenderMethod{
	Type:        "SuiteRenderMethod",
	RenderSuite: "summary",
	Name:        "Degree summary",
	Description: "Display the main degree information",
	Template:    template,
}

htmlMethod := render.RenderMethod{
	Type:          "SuiteRenderMethod",
	RenderSuite:   "html",
	RenderProperty: []string{
		"/issuer/name",
		"/credentialSubject/name",
	},
	Template: template,
}

staticMethod := render.RenderMethod{
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

referenced := render.RenderMethod{
	Type:        "SuiteRenderMethod",
	RenderSuite: "summary",
	Template: render.TemplateReference{
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
method := render.RenderMethod{
	Type:        "SuiteRenderMethod",
	RenderSuite: "summary",
	Template: render.TemplateReference{
		ID:              url,
		MediaType:       "application/json",
		DigestMultibase: digest,
	},
}

err := method.ValidateExternalTemplate(ctx, fetcher)
```

If validation is requested, fetching, media-type validation, template validation, and digest verification must complete before the method is returned.

## 8. Consumer-side rendering API

Create a new package under `credential/vc/render`.

```go
type TemplateFetcher interface {
	Fetch(ctx context.Context, ref TemplateReference) ([]byte, error)
}

type SummaryOptions struct {
	Fetcher          TemplateFetcher
}

func RenderSummary(
	ctx context.Context,
	credential CredentialData,
	method RenderMethod,
	opts SummaryOptions,
) (*SummaryOutput, error)
```

The renderer must reject a method whose suite is not `summary`.

```go
type SummaryOutput struct {
	Name        string         `json:"name"`
	Description string         `json:"description"`
	Icon        string         `json:"icon,omitempty"`
	Theme       *SummaryTheme  `json:"theme,omitempty"`
	Fields      []SummaryField `json:"fields"`
	ValidFrom   string         `json:"validFrom,omitempty"`
	ValidUntil  string         `json:"validUntil,omitempty"`
}

type SummaryField struct {
	Label     string `json:"label"`
	Value     string `json:"value"`
	Language  string `json:"language,omitempty"`
	Direction string `json:"direction,omitempty"`
}
```

### 8.1 Processing algorithm

1. Decode the template from an embedded `data:` URL or load it through `TemplateFetcher`.
2. For an external template, verify `digestMultibase` when present; embedded templates have no digest requirement.
3. Validate the summary template.
4. Recursively inspect string-valued template properties.
5. Resolve strings beginning with `/` as RFC 6901 pointers against the credential.
6. Convert resolved non-string scalar values to their JSON string representation.
7. Omit missing optional summary members and return an error for missing required summary members.
8. Preserve literal strings unchanged.
9. Validate the resulting summary output.
10. Return the normalized `SummaryOutput`.

No field may combine values from multiple pointers. The SDK follows the current suite definition that each field value resolves from one pointer.

## 9. Template retrieval and integrity

External retrieval is injected through `TemplateFetcher`; the core renderer must not create an unrestricted HTTP client.

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
- include the `sandbox="allow-scripts"` and `srcdoc` integration data;
- include ready/error `MessageChannel` communication code;
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

VC-JWT, VC-JOSE, and SD-JWT are not processed by the render package, but their credential payload paths MUST preserve `renderMethod` unchanged.

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

## 14. Implementation phases

### Phase 0 — Contract and compatibility baseline

- Freeze the public model names and object/array wire behavior.
- Add test fixtures for the W3C examples, while correcting invalid example JSON comments.
- Record the specification status and unsupported behaviors.

### Phase 1 — Common data model and VC integration

- Add `RenderMethod`, `TemplateReference`, `OutputPreference`, and suite-specific model types.
- Add `CredentialContents.RenderMethods`.
- Serialize `renderMethod` into the JSON-LD VC document.
- Parse both a single object and an array.
- Require the active JSON-LD context to define every render-method term used; do not auto-insert a context.
- Ensure render metadata is included in the Data Integrity signing input and survives round trips.
- Fail signing when any render-method term is unresolved.

### Phase 1.5 — Canonicalization preservation gate

- Canonicalize a VC containing each supported render suite.
- Verify that `renderSuite`, `template`, `renderProperty`, `outputPreference`, `deliveryMode`, and `digestMultibase` survive canonicalization where applicable.
- Fix the current silent-drop behavior for unresolved render terms.
- Reject partial canonicalization rather than issuing a credential.

### Phase 2 — Issuer authoring for all suites

- Implement one `RenderMethod` object model with suite-specific validation.
- Implement `Validate()` for each suite and summary template.
- Provide constructors only as optional convenience helpers; struct literals remain the primary authoring API.
- Implement embedded and referenced payloads for all suites.
- Add helpers for external template references.
- Accept optional `digestMultibase` for external template references and verify it when present.
- Do not require or automatically add a digest for embedded templates.
- Ensure authoring does not require network access unless explicitly requested.

### Phase 3 — Integrity and retrieval foundation

- Implement RFC 6901 JSON Pointer parsing.
- Implement multibase/multihash SHA-256 generation and verification.
- Add injectable `TemplateFetcher`.
- Add response-size, timeout, media-type, and redirect limits for the optional HTTP fetcher.
- Distinguish render-method digest verification from template digest verification.

### Phase 4 — Consumer support for `summary`

- Select supported summary methods.
- Decode embedded or referenced JSON templates.
- Validate the template.
- Resolve pointers, omit missing optional summary members, and fail missing required members.
- Validate the rendered summary output.
- Add deterministic golden tests.

This phase implements the complete Go-side `summary` renderer. It does not mean that `summary` is the only supported suite; the following phases implement the HTML artifact and static payload consumer paths.

### Phase 5 — HTML render artifact support

- Validate HTML fragment shape.
- Fetch and verify the external HTML payload.
- Apply `renderProperty` using the W3C `selectJsonLd` algorithm.
- Generate the filtered `application/vc` data block.
- Generate wrapper code with CSP, sandbox, `srcdoc`, and ready/error `MessageChannel` code.
- Return the complete HTML artifact and output preferences.
- Do not execute JavaScript or start the client browser/WebView runtime.

### Phase 6 — Consumer support for `static`

- Decode embedded static payloads.
- Fetch and verify referenced payloads.
- Return payload bytes, media type, delivery mode, and selected properties.
- Add fixtures for image, PDF, and opaque binary/NFC payloads.

### Phase 7 — End-to-end verification and release documentation

- Verify that changing any signed render metadata invalidates proofs.
- Verify issuer-created credentials can be consumed by each suite.
- Run compatibility tests for existing JSON-LD credentials without `renderMethod`.
- Add README examples for authoring and consuming all three suites.
- Run `go test ./credential/...`, `go test ./...`, and `go vet ./...`.

VC-JWT, VC-JOSE, SD-JWT, and other securing mechanisms are deferred to a future specification and must not become implicit compatibility requirements for this implementation.

## 15. Decisions

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

## 16. References

- W3C Verifiable Credential Rendering Methods v1.0: https://www.w3.org/TR/vc-render-method/
- W3C Credentials Examples vocabulary v2: https://www.w3.org/ns/credentials/examples/v2
- W3C Verifiable Credentials Data Model v2.1: https://www.w3.org/TR/vc-data-model-2.1/
- RFC 6901 JSON Pointer: https://www.rfc-editor.org/rfc/rfc6901
- W3C Data Integrity ECDSA Cryptosuites: https://www.w3.org/TR/vc-di-ecdsa/
- RFC 9458 Oblivious HTTP: https://www.rfc-editor.org/rfc/rfc9458
