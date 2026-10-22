module github.com/pilacorp/go-credential-sdk/digitalcredential

go 1.24.0

toolchain go1.24.3

require github.com/pilacorp/go-credential-sdk/jose v0.0.0-20261022214927-2be10a89b74d

require github.com/decred/dcrd/dcrec/secp256k1/v4 v4.4.0

// Until jose/v0.1.0 is tagged, jose is read from this repository; the
// placeholder version above is pinned to a real pseudo-version at commit time.
replace github.com/pilacorp/go-credential-sdk/jose => ../jose
