# `digitalcredential` — IETF SD-JWT VC

IETF SD-JWT VC (`dc+sd-jwt`); for a W3C VC secured with SD-JWT (`vc+sd-jwt`) use `credential/vc`.

Module `github.com/pilacorp/go-credential-sdk/digitalcredential`, tagged `digitalcredential/v0.x.y`. It imports
neither go-ethereum nor the root module of go-credential-sdk; it imports module `jose`.

`statuslist` builds Token Status Lists (draft-ietf-oauth-status-list-21): `New(size, bits)` or `FromBytes(b, bits)`
makes a list of 1-, 2-, 4- or 8-bit entries (§4.1), `Set` and `Get` write and read entry `i`, `Encode` and
`Decode(lst, bits)` convert the byte array to and from `lst` (ZLIB, then base64url, §4.2), and `SignToken` signs a
Status List Token (§5.1) with a `jws.Signer`. The bit width is the issuer's choice. A list holds at most 16 MiB once
inflated, and `Decode` refuses a larger one, a preset dictionary and a bad checksum; `SignToken` refuses a token over
1 MiB, the cap the Status List Token checker (next change) applies. That token holds only about 576 KiB of list bytes
that do not compress: a larger list signs only while it compresses well, and `SignToken` refuses it once status changes
make it less compressible, so size or split lists for the highest change rate expected (draft 21 §13.4, App. B).
Checking a token comes later.

`internal/safehttp` fetches documents whose URL comes from a token, such as a status list or issuer metadata: HTTPS on
every hop, a bounded number of redirects, time and size bounds (draft-ietf-oauth-sd-jwt-vc-19 §3), and no connection
to an address that is not globally reachable (§7.1). Status lists get the same rules as this SDK's policy, since
draft-ietf-oauth-status-list-21 §6.2 leaves them to the Relying Party. The address check cannot know hosts reachable
only inside your own network; block those with your egress policy.
