# `digitalcredential` — IETF SD-JWT VC

IETF SD-JWT VC (`dc+sd-jwt`); for a W3C VC secured with SD-JWT (`vc+sd-jwt`) use `credential/vc`.

Module `github.com/pilacorp/go-credential-sdk/digitalcredential`, tagged `digitalcredential/v0.x.y`. It imports
neither go-ethereum nor the root module of go-credential-sdk. The API is not exported yet.

`internal/safehttp` fetches documents whose URL comes from a token, such as a status list or issuer metadata: HTTPS on
every hop, a bounded number of redirects, time and size bounds (draft-ietf-oauth-sd-jwt-vc-19 §3), and no connection
to an address that is not globally reachable (§7.1). Status lists get the same rules as this SDK's policy, since
draft-ietf-oauth-status-list-21 §6.2 leaves them to the Relying Party. The address check cannot know hosts reachable
only inside your own network; block those with your egress policy.
