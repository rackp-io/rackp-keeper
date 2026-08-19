// test-unit.mjs — known-answer tests against schemas/test-vectors/
// (RFC-0001 §6: implementations SHOULD validate against the published
// vectors before first interoperation). Exercises the same JCS / hashing /
// signing conventions the worker uses. Run: npm run test:unit
import { readFileSync } from 'node:fs';
import { webcrypto } from 'node:crypto';
import { transformSync } from 'esbuild';
import assert from 'node:assert/strict';

const { subtle } = webcrypto;

// The shipped canonicalizer and digest, loaded from src/crypto.ts itself: these
// vectors are only a guard against drift if they exercise the code the worker
// deploys rather than a copy of it kept alongside them.
const { jcs, sha256hex } = await import(
  'data:text/javascript;base64,' +
  Buffer.from(
    transformSync(readFileSync('./src/crypto.ts', 'utf8'), { loader: 'ts', format: 'esm' }).code,
  ).toString('base64')
);

function fromBase64url(s) {
  return Buffer.from(s.replace(/-/g, '+').replace(/_/g, '/'), 'base64');
}
function toBase64url(buf) {
  return Buffer.from(buf).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}

async function importVerifyKey(publicKeyB64url) {
  return subtle.importKey('raw', fromBase64url(publicKeyB64url), { name: 'Ed25519' }, false, ['verify']);
}
async function importSignKeyFromSeed(seedHex) {
  // Raw 32-byte Ed25519 seed -> PKCS#8 (RFC 8410 wrapping).
  const seed = Buffer.from(seedHex, 'hex');
  const prefix = Buffer.from('302e020100300506032b657004220420', 'hex');
  return subtle.importKey('pkcs8', Buffer.concat([prefix, seed]), { name: 'Ed25519' }, false, ['sign']);
}

let passed = 0;
const ok = (name) => {
  passed++;
  console.log(`  ok: ${name}`);
};

// --- JCS vectors -----------------------------------------------------------
const jcsVectors = JSON.parse(readFileSync('./schemas/test-vectors/jcs.json', 'utf8'));
console.log('JCS canonicalization:');
for (const v of jcsVectors.vectors) {
  assert.equal(jcs(v.input), v.canonical, v.description);
  ok(v.description);
}

// --- signature vectors -----------------------------------------------------
const sigVectors = JSON.parse(readFileSync('./schemas/test-vectors/signature.json', 'utf8'));
console.log('message signatures:');
{
  const verifyKey = await importVerifyKey(sigVectors.public_key);
  const signKey = await importSignKeyFromSeed(sigVectors.secret_key_hex);
  for (const v of sigVectors.vectors) {
    assert.equal(jcs(v.message_body), v.canonical, `${v.description}: canonical`);
    const sig = await subtle.sign('Ed25519', signKey, Buffer.from(v.canonical, 'utf8'));
    assert.equal(toBase64url(sig), v.signature, `${v.description}: signature reproduces`);
    const valid = await subtle.verify(
      'Ed25519', verifyKey, fromBase64url(v.signature), Buffer.from(v.canonical, 'utf8'),
    );
    assert.equal(valid, true, `${v.description}: verifies`);
    ok(v.description);
  }
}

// --- end-to-end CLAIM_ANCHOR vector ----------------------------------------
const anchorVector = JSON.parse(readFileSync('./schemas/test-vectors/claim_anchor.json', 'utf8'));
console.log('CLAIM_ANCHOR pipeline:');
{
  assert.equal(jcs(anchorVector.anchored_payload), anchorVector.payload_canonical, 'payload canonical');
  assert.equal(await sha256hex(anchorVector.payload_canonical), anchorVector.data_hash, 'data_hash');
  const { signature, ...body } = anchorVector.message;
  assert.equal(jcs(body), anchorVector.message_body_canonical, 'message body canonical');
  const signKey = await importSignKeyFromSeed(anchorVector.secret_key_hex);
  const sig = await subtle.sign('Ed25519', signKey, Buffer.from(anchorVector.message_body_canonical, 'utf8'));
  assert.equal(toBase64url(sig), anchorVector.message.signature, 'signature reproduces');
  ok('full anchored_payload -> data_hash -> signature pipeline');
}

console.log(`\nall ${passed} known-answer checks passed`);
