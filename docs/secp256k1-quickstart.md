# Ký VC/VP JSON-LD bằng khoá secp256k1 — `v1.13.1`

> Dành cho anh em trong team. Bản đầy đủ ở [README](../README.md#signing), phần *Signing*.

## Có gì mới

Trước `v1.13.1`, ký một credential **JSON-LD VC 2.0** bằng khoá secp256k1 là không được —
`AddProofByProvider` trả `unsupported key kind secp256k1`. Lý do: `vc-di-ecdsa` chỉ định nghĩa
cryptosuite cho P-256 và P-384, không có secp256k1.

Mà khoá của mình thì toàn secp256k1, document thì VC 2.0. Nên từ `v1.13.1` SDK route khoá
secp256k1 sang suite **`EcdsaSecp256k1Signature2019`** (bản CCG công bố riêng cho curve này).

Đường JWT (`NewJWTCredential`, `ES256K`) không đổi — vẫn chạy như cũ.

```bash
go get github.com/pilacorp/go-credential-sdk@v1.13.1
```

## Dùng thế nào

**Về API thì đúng là chỉ đổi khoá** — không option mới, không type mới, code y như P-256.

Nhưng nếu bạn đang chuyển từ đường **JWT** (`NewJWTCredential` / `ES256K`) sang đường
**JSON-LD** này thì có một thứ mới: JSON-LD **canonicalize** document trước khi ký, còn JWT thì
không. Nên `@context` từ giờ mới thành vấn đề — document chạy tốt với `NewJWTCredential` hoàn
toàn có thể fail ở `NewJSONCredential`. Xem mục [`@context`](#lưu-ý-về-context-chỗ-dễ-sập-nhất) bên dưới
trước khi bạn thêm field riêng.

### Phát hành VC

```go
import (
    "time"

    "github.com/google/uuid"
    "github.com/pilacorp/go-credential-sdk/credential/common/signer"
    "github.com/pilacorp/go-credential-sdk/credential/vc"
)

func init() {
    // DID resolver. Mặc định https://api.ndadid.vn/api/v1/did
    vc.Init("https://auth-dev.pila.vn/api/v1/did")
}

func issue(issuerDID, privHex string) ([]byte, error) {
    // Provider mặc định = secp256k1 (hex private key, có hoặc không có 0x)
    prov, err := signer.NewDefaultProvider(privHex)
    if err != nil {
        return nil, err
    }

    cred, err := vc.NewJSONCredential(vc.CredentialContents{
        Context:   []interface{}{"https://www.w3.org/ns/credentials/v2"},
        ID:        "urn:uuid:" + uuid.NewString(),
        Issuer:    issuerDID,
        Types:     []string{"VerifiableCredential", "IdentityCredential"},
        ValidFrom: time.Now(),
        Subject:   []vc.Subject{{ID: "did:example:subject", CustomFields: map[string]interface{}{
            // "name" có trong credentials/v2 nên dùng được luôn.
            // Field riêng (hoTen, soCMND, ...) phải khai trong @context — xem mục @context.
            "name": "Nguyen Van A",
        }}},
    })
    if err != nil {
        return nil, err
    }

    // WithVerificationMethodKey: trỏ đúng key trong DID document (xem lưu ý 3)
    if err := cred.AddProofByProvider(prov, vc.WithVerificationMethodKey("key-1")); err != nil {
        return nil, err
    }

    return cred.GetContents()
}
```

Có JSON sẵn thì dùng `vc.ParseJSONCredential(raw)` rồi `AddProofByProvider` như trên.

### Verify

```go
cred, err := vc.ParseCredential(raw)      // tự nhận JSON-LD / JWT / SD-JWT
if err != nil {
    return err
}

return cred.Verify()                       // thêm vc.WithCheckRevocation(), vc.WithSchemaValidation() nếu cần
```

### VP

Giống hệt, đổi package:

```go
pres, err := vp.ParseJSONPresentation(raw)
if err != nil {
    return err
}
err = pres.AddProofByProvider(prov,
    vp.WithVerificationMethodKey("key-1"),
    vp.WithChallenge("nonce-abc"),          // verifier cấp
    vp.WithDomain("verifier.example"),
)
```

## Proof ra trông thế nào

Output thật từ `v1.13.1`:

```jsonc
{
  "@context": [
    "https://www.w3.org/ns/credentials/v2",
    "https://w3id.org/security/suites/secp256k1-2019/v1"   // SDK tự thêm, xem lưu ý 2
  ],
  "id": "urn:uuid:demo-001",
  "type": ["VerifiableCredential"],
  "issuer": "did:nda:testnet:0x8b3b1dee8e00cb95f8b2a1d1a9a7cb8fe7d490ce",
  "validFrom": "2026-01-01T00:00:00Z",
  "credentialSubject": { "id": "did:example:subject", "name": "Nguyen Van A" },
  "proof": {
    "type": "EcdsaSecp256k1Signature2019",
    "created": "2026-10-06T03:02:56Z",
    "proofPurpose": "assertionMethod",
    "verificationMethod": "did:nda:testnet:0x8b3b...90ce#key-1",
    "jws": "eyJhbGciOiJFUzI1NksiLCJiNjQiOmZhbHNlLCJjcml0IjpbImI2NCJdfQ.._Sgct0yfA6HPIztbLMfVA85Vp6fBVHRdU3mM1TJY9d91w5eUjhumcxCKaV2-jp7xRK0eJmheloGamxTljq76qg"
  }
}
```

Khác P-256 ba điểm, nếu bên bạn đang parse proof thì để ý:

| | P-256 | secp256k1 |
|---|---|---|
| `proof.type` | `DataIntegrityProof` | `EcdsaSecp256k1Signature2019` |
| `proof.cryptosuite` | `ecdsa-rdfc-2019` | **không có** (suite đã tự gọi tên trong `type`) |
| chữ ký nằm ở | `proofValue` (multibase) | `jws` (detached JWS, `header..signature`) |

Header của JWS là cố định, đúng theo spec: `{"alg":"ES256K","b64":false,"crit":["b64"]}`.

## Lưu ý về `@context` (chỗ dễ sập nhất)

Mọi thứ dưới đây tôi đã chạy thật trên `v1.13.1`, không phải suy luận.

### 1. Mọi field phải được một context nào đó định nghĩa

Đây là lỗi hay gặp nhất. Thêm một field mà không context nào biết tới → **ký fail**:

```
jsonmap: failed to canonicalize the document: failed to canonicalize document:
expand: invalid property: Dropping property that did not expand into an absolute IRI or keyword.
```

Message **không nói field nào** sai, nên dễ mất thời gian. Fail ở mọi vị trí — top-level, trong
`credentialSubject`, trong object lồng:

```jsonc
// ✗ FAIL — "hoTen" không được định nghĩa
{"@context": ["https://www.w3.org/ns/credentials/v2"],
 "credentialSubject": {"id": "did:example:s", "hoTen": "Nguyen Van A"}}
```

Cách sửa, chọn một:

```jsonc
// ✓ Cách 1 — @vocab, gọn, mọi field lạ đều qua (dùng cái này nếu không cần semantic chặt)
{"@context": ["https://www.w3.org/ns/credentials/v2",
              {"@vocab": "https://pila.vn/vocab#"}],
 "credentialSubject": {"id": "did:example:s", "hoTen": "A", "hoSo": {"noiCap": "HN"}}}

// ✓ Cách 2 — khai từng term
{"@context": ["https://www.w3.org/ns/credentials/v2",
              {"hoTen": "https://pila.vn/v#hoTen"}],
 "credentialSubject": {"id": "did:example:s", "hoTen": "A"}}
```

### 2. Field phải đúng data model của context

| Field | `credentials/v2` | `2018/credentials/v1` |
|---|---|---|
| `validFrom` / `validUntil` | ✓ | ✓ |
| `issuanceDate` / `expirationDate` | **✗** | ✓ |
| `name` / `description` | ✓ | **✗** |

Nên: `issuanceDate` trên document v2 → fail. `name` trên document v1.1 → fail. Cả hai cùng
một message ở mục 1.

### 3. Context URL không nhúng sẵn thì phải ra mạng

SDK nhúng sẵn 7 context, canonicalize offline được:

```
https://www.w3.org/2018/credentials/v1          (+ .jsonld)
https://www.w3.org/ns/credentials/v2            (+ .jsonld)
https://www.w3.org/ns/credentials/examples/v2   (+ .jsonld)
https://w3id.org/security/v1
https://w3id.org/security/v2
https://w3id.org/security/data-integrity/v2
https://w3id.org/security/suites/secp256k1-2019/v1
```

Mọi URL khác — kể cả `https://w3id.org/vc/status-list/2021/v1` hay context riêng của bên bạn —
bị **fetch qua HTTP mỗi lần canonicalize**, tức là cả lúc ký và lúc verify. URL chết thì ký fail:

```
expand: loading remote context failed: dereferencing a URL did not result in a valid
JSON-LD context (https://example.invalid/ctx.jsonld): ... no such host
```

Nếu service của bạn chạy trong môi trường không ra được internet, đừng để URL ngoài trong
`@context` — dùng `@vocab` inline (cách 1 ở trên) hoặc host context đó nội bộ.

### 4. Những thứ KHÔNG phải lo

Tôi có test, đều chạy bình thường:

- `"@context": "https://..."` dạng **string đơn** thay vì mảng → OK, SDK tự chuẩn hoá.
- Bạn **tự thêm sẵn** `secp256k1-2019/v1` → SDK không thêm trùng.
- Bạn tự thêm `security/v2` → SDK **không** thêm gì (suite đã được định nghĩa ở đó).
- Suite context đứng **trước** `credentials/v2` → vẫn ký và verify được (dù VCDM 2.0 nói v2 phải
  đứng đầu — đường JSON-LD không enforce thứ tự này).
- Bạn tự định nghĩa term `proof` trong context riêng → bị bỏ qua, không lỗi. Canonicalize vẫn
  ra `https://w3id.org/security#proof` vì `proof` trong v2 là `@protected`.

## Bốn lưu ý còn lại

**1. Không chọn suite được — khoá quyết định.** Không có option nào để chỉ định suite. SDK đọc
key type của verification method đã bind (lấy từ DID document lúc ký) rồi tự chọn:

```go
jsonmap.SigningSuiteForKey(verificationmethod.KeySecp256k1) // "EcdsaSecp256k1Signature2019"
jsonmap.SigningSuiteForKey(verificationmethod.KeyP256)      // "DataIntegrityProof"
jsonmap.SigningSuiteForKey(verificationmethod.KeyRSA)       // err: unsupported key kind RSA for JSON-LD signing
```

Hàm này mới thêm ở `v1.13.1`, dùng để tra trước khi ký nếu cần.

**2. SDK tự thêm context `secp256k1-2019/v1`.** Suite cần term của nó được định nghĩa, mà
`credentials/v2` chỉ định nghĩa Data Integrity. Context đó được append **sau** context gốc của
bạn, document giữ nguyên mọi property 2.0 đã có (kể cả `BitstringStatusListEntry`). Chi tiết các
trường hợp ở mục [`@context`](#lưu-ý-về-context-chỗ-dễ-sập-nhất) phía trên.

**3. DID document phải publish khoá secp256k1.** Verification method type phải là
`EcdsaSecp256k1VerificationKey2019`. Và nếu DID của bạn giữ **nhiều loại khoá** (vừa secp256k1
vừa P-256), **phải** pin bằng `WithVerificationMethodKey("key-1")` — không pin thì SDK lấy VM
active mới nhất, lệch loại khoá với signer là bị từ chối ngay lúc ký.

**4. Chỉ dùng trong nội bộ NDA/PILA.** `EcdsaSecp256k1Signature2019` là CCG report, không phải
W3C Recommendation, và bản thân nó ghi *"is not fit for production deployment"*. Verifier bên
ngoài rất có thể từ chối embedded proof dùng secp256k1 bất kể suite nào. Cần interop thật ra
ngoài thì dùng **P-256 + `ecdsa-rdfc-2019`**.

## Bảng tra nhanh

| Credential type | Khoá | Suite / alg |
|---|---|---|
| `JSONCredential` / `JSONPresentation` | secp256k1 | `EcdsaSecp256k1Signature2019` ← **mới** |
| `JSONCredential` / `JSONPresentation` | P-256 | `DataIntegrityProof` / `ecdsa-rdfc-2019` |
| `JWTCredential` / `JWTPresentation` | secp256k1 | `ES256K` |
| `JWTCredential` / `JWTPresentation` | P-256 | `ES256` |
| `ECDSASDCredential` | P-256 | `ecdsa-sd-2023` |

Combination nào khác → báo lỗi lúc ký. P-384 và RSA chưa ký được (RSA verify-only).

---

Có gì không chạy thì ping mình, hoặc xem test e2e để lấy mẫu:
`credential/vc/secp256k1_suite_e2e_test.go`, `credential/vp/secp256k1_suite_e2e_test.go`.
