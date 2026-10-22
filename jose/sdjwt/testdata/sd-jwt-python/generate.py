# Generates the JSON vectors in this directory from the test cases of
# sd-jwt-python (https://github.com/openwallet-foundation-labs/sd-jwt-python,
# Apache-2.0), commit c5fda017d15e65a6c61a31e696bcdbdab2966b1e:
#   tests/testcases/settings.yml           -> settings.json
#   tests/testcases/<case>/specification.yml -> <case>.json
#
# The specifications hold only the input claims, the holder's selection and the
# expected verified claims. The issued disclosures and payload are produced by
# sd-jwt-python's own SDJWTIssuer, the selection by SDJWTHolder, exactly as
# tests/test_e2e_testcases.py does (random.seed(random_seed), then the issuer
# with unsafe_randomness); signing is skipped, since issuer signatures are not
# compared. The verified claims are re-checked with SDJWTVerifier before a
# file is written.
#
# Usage (PyYAML required, jwcrypto not needed):
#   python3 generate.py <sd-jwt-python checkout> <output dir>
import json
import random
import sys
import types
from pathlib import Path


def stub_jwcrypto():
    class Unused:
        def __init__(self, *args, **kwargs):
            raise RuntimeError("signing is not used by this generator")

    root = types.ModuleType("jwcrypto")
    jws = types.ModuleType("jwcrypto.jws")
    jwk = types.ModuleType("jwcrypto.jwk")
    jws.JWS = Unused
    jwk.JWK = Unused
    jwk.JWKSet = Unused
    sys.modules.update({"jwcrypto": root, "jwcrypto.jws": jws, "jwcrypto.jwk": jwk})


def public_jwk(jwk):
    return {k: jwk[k] for k in ("kty", "crv", "x", "y")}


def main(checkout, out_dir):
    stub_jwcrypto()
    sys.path.insert(0, str(Path(checkout) / "src"))
    from sd_jwt.common import SDJWTCommon, SDObj
    from sd_jwt.holder import SDJWTHolder
    from sd_jwt.issuer import SDJWTIssuer
    from sd_jwt.utils.demo_utils import load_yaml_settings
    from sd_jwt.utils.yaml_specification import load_yaml_specification, remove_sdobj_wrappers
    from sd_jwt.verifier import SDJWTVerifier

    cases_dir = Path(checkout) / "tests" / "testcases"
    out_dir = Path(out_dir)
    base_settings = load_yaml_settings(cases_dir / "settings.yml")
    keys = base_settings["key_settings"]
    write(out_dir / "settings.json", {
        "source": "sd-jwt-python c5fda017 tests/testcases/settings.yml",
        "issuer": base_settings["identifiers"]["issuer"],
        "verifier": base_settings["identifiers"]["verifier"],
        "issuer_key": keys["issuer_keys"][0],
        "holder_key": keys["holder_key"],
        "key_binding_nonce": base_settings["key_binding_nonce"],
    })

    # Paths of the !sd markers, in the order SDJWTIssuer._create_sd_claims
    # creates their disclosures (children first, then the claim itself).
    def sd_paths(obj, path, out):
        if isinstance(obj, dict):
            for k, v in obj.items():
                name = k.value if isinstance(k, SDObj) else k
                sd_paths(v, path + [name], out)
                if isinstance(k, SDObj):
                    out.append(path + [name])
        elif isinstance(obj, list):
            for i, v in enumerate(obj):
                if isinstance(v, SDObj):
                    sd_paths(v.value, path + [i], out)
                    out.append(path + [i])
                else:
                    sd_paths(v, path + [i], out)

    for spec_file in sorted(cases_dir.glob("*/specification.yml")):
        case = spec_file.parent.name
        spec = load_yaml_specification(spec_file)
        settings = dict(base_settings)
        settings.update(spec.get("settings_override", {}))
        key_binding = spec.get("key_binding", False)
        if spec.get("add_decoy_claims", False):
            sys.exit(f"{case}: decoys are random and cannot be reproduced")

        user_claims = {"iss": settings["identifiers"]["issuer"]}
        user_claims.update(spec["user_claims"])

        random.seed(settings["random_seed"])  # as demo_utils.get_jwk does
        SDJWTCommon.unsafe_randomness = True
        issuer = SDJWTIssuer.__new__(SDJWTIssuer)
        SDJWTCommon.__init__(issuer, "compact")
        issuer._user_claims = user_claims
        issuer._holder_key = None
        issuer._add_decoy_claims = False
        issuer.ii_disclosures = []
        issuer.decoy_digests = []
        issuer._check_for_sd_claim(user_claims)
        issuer._assemble_sd_jwt_payload()
        payload = json.loads(json.dumps(issuer.sd_jwt_payload))
        if key_binding:
            payload["cnf"] = {"jwk": public_jwk(keys["holder_key"])}
        disclosures = [d.b64 for d in issuer.ii_disclosures]

        paths = []
        sd_paths(user_claims, [], paths)
        if len(paths) != len(disclosures):
            sys.exit(f"{case}: {len(paths)} paths for {len(disclosures)} disclosures")
        conceal = []
        for path, d in zip(paths, issuer.ii_disclosures):
            item = json.loads(d.json)
            if isinstance(path[-1], int) != (len(item) == 2) or (len(item) == 3 and item[1] != path[-1]):
                sys.exit(f"{case}: path {path} does not match disclosure {item}")
            conceal.append({"path": path, "salt": item[0]})

        holder = SDJWTHolder.__new__(SDJWTHolder)
        SDJWTCommon.__init__(holder, "compact")
        holder._create_hash_mappings(disclosures)
        holder.hs_disclosures = []
        holder._select_disclosures(payload, spec["holder_disclosed_claims"])
        presented = list(holder.hs_disclosures)

        expected = remove_sdobj_wrappers(spec["expect_verified_user_claims"])
        expected["iss"] = settings["identifiers"]["issuer"]
        if key_binding:
            expected["cnf"] = {"jwk": public_jwk(keys["holder_key"])}
        verifier = SDJWTVerifier.__new__(SDJWTVerifier)
        SDJWTCommon.__init__(verifier, "compact")
        verifier._create_hash_mappings(presented)
        verifier._sd_jwt_payload = payload
        if verifier._extract_sd_claims() != expected:
            sys.exit(f"{case}: sd-jwt-python does not verify to the expected claims")

        write(out_dir / f"{case}.json", {
            "source": f"sd-jwt-python c5fda017 tests/testcases/{case}/specification.yml",
            "user_claims": remove_sdobj_wrappers(user_claims),
            "conceal": conceal,
            "disclosures": disclosures,
            "payload": payload,
            "holder_disclosed_claims": spec["holder_disclosed_claims"],
            "presented": presented,
            "expect_verified_user_claims": expected,
            "key_binding": key_binding,
        })


def write(path, value):
    path.write_text(json.dumps(value, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


if __name__ == "__main__":
    if len(sys.argv) != 3:
        sys.exit("usage: generate.py <sd-jwt-python checkout> <output dir>")
    main(sys.argv[1], sys.argv[2])
