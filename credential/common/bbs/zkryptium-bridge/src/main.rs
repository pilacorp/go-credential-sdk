use serde::{Deserialize, Serialize};
use std::io::{self, Read};
use zkryptium::{
    bbsplus::keys::{BBSplusPublicKey, BBSplusSecretKey},
    schemes::{
        algorithms::BbsBls12381Sha256,
        generics::{PoKSignature, Signature},
    },
};

#[derive(Deserialize)]
struct Request {
    op: String,
    #[serde(rename = "privateKeyHex")]
    private_key_hex: Option<String>,
    #[serde(rename = "publicKeyHex")]
    public_key_hex: Option<String>,
    #[serde(rename = "signatureHex")]
    signature_hex: Option<String>,
    #[serde(rename = "proofHex")]
    proof_hex: Option<String>,
    #[serde(rename = "headerHex")]
    header_hex: Option<String>,
    #[serde(rename = "presentationHeaderHex")]
    presentation_header_hex: Option<String>,
    #[serde(rename = "messagesHex")]
    messages_hex: Option<Vec<String>>,
    #[serde(rename = "disclosedIndexes")]
    disclosed_indexes: Option<Vec<usize>>,
}

#[derive(Serialize)]
struct Response {
    #[serde(rename = "publicKeyHex", skip_serializing_if = "Option::is_none")]
    public_key_hex: Option<String>,
    #[serde(rename = "signatureHex", skip_serializing_if = "Option::is_none")]
    signature_hex: Option<String>,
    #[serde(rename = "proofHex", skip_serializing_if = "Option::is_none")]
    proof_hex: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    ok: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

fn main() {
    let mut input = String::new();
    if let Err(err) = io::stdin().read_to_string(&mut input) {
        print_response(Response {
            public_key_hex: None,
            signature_hex: None,
            proof_hex: None,
            ok: None,
            error: Some(format!("read stdin: {err}")),
        });
        return;
    }

    let req: Request = match serde_json::from_str(&input) {
        Ok(v) => v,
        Err(err) => {
            print_response(Response {
                public_key_hex: None,
                signature_hex: None,
                proof_hex: None,
                ok: None,
                error: Some(format!("decode request: {err}")),
            });
            return;
        }
    };

    let resp = handle(req);
    print_response(resp);
}

fn handle(req: Request) -> Response {
    match handle_inner(req) {
        Ok(resp) => resp,
        Err(err) => Response {
            public_key_hex: None,
            signature_hex: None,
            proof_hex: None,
            ok: None,
            error: Some(err),
        },
    }
}

fn handle_inner(req: Request) -> Result<Response, String> {
    match req.op.as_str() {
        "public_key" => {
            let sk = parse_secret_key(req.private_key_hex.as_deref())?;
            let pk = sk.public_key();
            Ok(Response {
                public_key_hex: Some(hex::encode(pk.to_bytes())),
                signature_hex: None,
                proof_hex: None,
                ok: Some(true),
                error: None,
            })
        }
        "sign" => {
            let sk = parse_secret_key(req.private_key_hex.as_deref())?;
            let pk = parse_public_key(req.public_key_hex.as_deref())?;
            let messages = parse_messages(req.messages_hex.as_ref())?;
            let header = parse_bytes(req.header_hex.as_deref())?;
            let sig = Signature::<BbsBls12381Sha256>::sign(
                Some(&messages),
                &sk,
                &pk,
                Some(&header),
            )
            .map_err(|e| format!("sign: {e}"))?;
            Ok(Response {
                public_key_hex: None,
                signature_hex: Some(hex::encode(sig.to_bytes())),
                proof_hex: None,
                ok: Some(true),
                error: None,
            })
        }
        "verify" => {
            let pk = parse_public_key(req.public_key_hex.as_deref())?;
            let sig_bytes = parse_bytes(req.signature_hex.as_deref())?;
            let sig_arr: [u8; 80] = sig_bytes
                .try_into()
                .map_err(|_| "signature from bytes: invalid length".to_owned())?;
            let sig = Signature::<BbsBls12381Sha256>::from_bytes(&sig_arr)
                .map_err(|e| format!("signature from bytes: {e}"))?;
            let messages = parse_messages(req.messages_hex.as_ref())?;
            let header = parse_bytes(req.header_hex.as_deref())?;
            sig.verify(&pk, Some(&messages), Some(&header))
                .map_err(|e| format!("verify: {e}"))?;
            Ok(ok_resp())
        }
        "proof_gen" => {
            let pk = parse_public_key(req.public_key_hex.as_deref())?;
            let sig = parse_bytes(req.signature_hex.as_deref())?;
            let header = parse_bytes(req.header_hex.as_deref())?;
            let ph = parse_bytes(req.presentation_header_hex.as_deref())?;
            let messages = parse_messages(req.messages_hex.as_ref())?;
            let disclosed = req.disclosed_indexes.unwrap_or_default();
            let proof = PoKSignature::<BbsBls12381Sha256>::proof_gen(
                &pk,
                &sig,
                Some(&header),
                Some(&ph),
                Some(&messages),
                Some(&disclosed),
            )
            .map_err(|e| format!("proof_gen: {e}"))?;
            Ok(Response {
                public_key_hex: None,
                signature_hex: None,
                proof_hex: Some(hex::encode(proof.to_bytes())),
                ok: Some(true),
                error: None,
            })
        }
        "proof_verify" => {
            let pk = parse_public_key(req.public_key_hex.as_deref())?;
            let proof_bytes = parse_bytes(req.proof_hex.as_deref())?;
            let proof = PoKSignature::<BbsBls12381Sha256>::from_bytes(&proof_bytes)
                .map_err(|e| format!("proof from bytes: {e}"))?;
            let header = parse_bytes(req.header_hex.as_deref())?;
            let ph = parse_bytes(req.presentation_header_hex.as_deref())?;
            let messages = parse_messages(req.messages_hex.as_ref())?;
            let disclosed = req.disclosed_indexes.unwrap_or_default();
            proof
                .proof_verify(&pk, Some(&messages), Some(&disclosed), Some(&header), Some(&ph))
                .map_err(|e| format!("proof_verify: {e}"))?;
            Ok(ok_resp())
        }
        other => Err(format!("unsupported op: {other}")),
    }
}

fn parse_secret_key(hex_str: Option<&str>) -> Result<BBSplusSecretKey, String> {
    let raw = parse_bytes(hex_str)?;
    BBSplusSecretKey::from_bytes(&raw).map_err(|e| format!("secret key: {e}"))
}

fn parse_public_key(hex_str: Option<&str>) -> Result<BBSplusPublicKey, String> {
    let raw = parse_bytes(hex_str)?;
    BBSplusPublicKey::from_bytes(&raw).map_err(|e| format!("public key: {e}"))
}

fn parse_messages(values: Option<&Vec<String>>) -> Result<Vec<Vec<u8>>, String> {
    values
        .cloned()
        .unwrap_or_default()
        .into_iter()
        .map(|v| hex::decode(v).map_err(|e| format!("message hex: {e}")))
        .collect()
}

fn parse_bytes(hex_str: Option<&str>) -> Result<Vec<u8>, String> {
    let s = hex_str.unwrap_or("");
    if s.is_empty() {
        return Ok(vec![]);
    }
    hex::decode(s).map_err(|e| format!("hex decode: {e}"))
}

fn ok_resp() -> Response {
    Response {
        public_key_hex: None,
        signature_hex: None,
        proof_hex: None,
        ok: Some(true),
        error: None,
    }
}

fn print_response(resp: Response) {
    match serde_json::to_string(&resp) {
        Ok(s) => println!("{s}"),
        Err(err) => println!("{{\"error\":\"encode response: {err}\"}}"),
    }
}
