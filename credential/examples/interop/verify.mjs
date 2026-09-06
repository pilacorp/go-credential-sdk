/**
 * Verifies the credential written by main.go using @digitalbazaar/vc, the
 * reference JavaScript implementation.
 *
 * @digitalbazaar/vc is not a dependency of this repo, so point this script at a
 * checkout of it. Clone and install it once:
 *
 *   git clone https://github.com/digitalbazaar/vc ../vc && (cd ../vc && npm install)
 *
 * Then:
 *
 *   go run ./credential/examples/interop
 *   node credential/examples/interop/verify.mjs
 *
 * Paths default relative to this repo, not to your working directory, so both
 * commands work from anywhere. Override the checkout location with
 * --vc-dir=PATH or VC_DIR=PATH, and the credential with a positional argument.
 */
import fs from 'fs';
import path from 'path';
import {createRequire} from 'module';
import {fileURLToPath, pathToFileURL} from 'url';

// Resolve defaults against this script's location, not the caller's working
// directory, so it runs the same from anywhere.
const scriptDir = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(scriptDir, '..', '..', '..');

const args = process.argv.slice(2);
const inputArg = args.find(a => !a.startsWith('--'));
const vcDir = path.resolve(
  args.find(a => a.startsWith('--vc-dir='))?.slice('--vc-dir='.length) ??
  process.env.VC_DIR ?? path.join(repoRoot, '..', 'vc'));

// Look for the credential where the caller pointed, then where main.go writes it.
const name = inputArg ?? 'vc.json';
const candidates = [...new Set([path.resolve(name), path.resolve(repoRoot, name)])];
const inputFile = candidates.find(fs.existsSync);
if (!inputFile) {
  console.error(
    `No credential found. Looked in:\n${candidates.map(c => `  ${c}`).join('\n')}\n\n` +
    `Issue one first:\n  (cd ${repoRoot} && go run ./credential/examples/interop)`);
  process.exit(2);
}

if (!fs.existsSync(path.join(vcDir, 'lib', 'index.js')) ||
    !fs.existsSync(path.join(vcDir, 'node_modules'))) {
  console.error(
    `No installed @digitalbazaar/vc checkout at ${vcDir}\n\n` +
    `  git clone https://github.com/digitalbazaar/vc ${path.join(repoRoot, '..', 'vc')}\n` +
    `  (cd ${path.join(repoRoot, '..', 'vc')} && npm install)\n\n` +
    `Or point at an existing one: --vc-dir=PATH (or VC_DIR=PATH).`);
  process.exit(2);
}

// Resolve the library and its cryptosuite packages out of that checkout, so
// this script can run from anywhere. Some of them resolve to a CommonJS build,
// whose exports arrive under `default`, so merge both shapes.
const requireFromVc = createRequire(path.join(vcDir, 'package.json'));
async function load(specifier) {
  const mod = await import(pathToFileURL(requireFromVc.resolve(specifier)).href);
  return {...(mod.default ?? {}), ...mod};
}

const vc = await import(pathToFileURL(path.join(vcDir, 'lib', 'index.js')).href);
const {cryptosuite} = await load('@digitalbazaar/ecdsa-rdfc-2019-cryptosuite');
const {DataIntegrityProof} = await load('@digitalbazaar/data-integrity');
const {contexts: credentialsContexts} = await load('@digitalbazaar/credentials-context');
const {contexts: multikeyContexts} = await load('@digitalbazaar/multikey-context');
const {contexts: didContexts} = await load('did-context');

const {credential, publicKeyMultibase} = JSON.parse(fs.readFileSync(inputFile, 'utf8'));

const keyId = credential.proof.verificationMethod;   // did:example:issuer#key-1
const controllerId = keyId.split('#')[0];            // did:example:issuer

// Stands in for a resolvable DID document: the issuer's public key, and the
// issuer granting that key the assertionMethod purpose.
const keyDocument = {
  '@context': 'https://w3id.org/security/multikey/v1',
  id: keyId,
  type: 'Multikey',
  controller: controllerId,
  publicKeyMultibase
};
const controllerDocument = {
  '@context': ['https://www.w3.org/ns/did/v1', 'https://w3id.org/security/multikey/v1'],
  id: controllerId,
  assertionMethod: [keyDocument]
};

// No network fallback: a context that is not bundled fails loudly.
const contexts = new Map([
  ...credentialsContexts, ...multikeyContexts, ...didContexts
]);
async function documentLoader(url) {
  if (contexts.has(url)) {
    return {contextUrl: null, documentUrl: url, document: contexts.get(url)};
  }
  if (url === keyId) return {contextUrl: null, documentUrl: url, document: keyDocument};
  if (url === controllerId) {
    return {contextUrl: null, documentUrl: url, document: controllerDocument};
  }
  throw new Error(`refusing to fetch ${url}: every context must be bundled`);
}

const result = await vc.verifyCredential({
  credential,
  suite: new DataIntegrityProof({cryptosuite}),
  documentLoader
});

if (result.verified) {
  console.log(`${path.basename(inputFile)}: verified`);
  process.exit(0);
}

let reason = '';
const findError = r => {
  if (r?.error) reason ||= r.error.errors?.[0]?.message ?? r.error.message;
  (r?.results ?? []).forEach(findError);
};
findError(result);
console.error(`${path.basename(inputFile)}: NOT verified — ${reason}`);
process.exit(1);
