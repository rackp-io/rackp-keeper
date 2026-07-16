// genkey.mjs — generate the Keeper's Ed25519 signing key pair.
// Prints the private JWK (feed to `wrangler secret put KEEPER_SIGNING_KEY`
// or .dev.vars for local dev) and the public key in the protocol's unpadded
// Base64url form (publish alongside the keeper endpoint).
import { webcrypto } from 'node:crypto';

const { subtle } = webcrypto;

const pair = await subtle.generateKey({ name: 'Ed25519' }, true, ['sign', 'verify']);
const jwk = await subtle.exportKey('jwk', pair.privateKey);
const raw = new Uint8Array(await subtle.exportKey('raw', pair.publicKey));
let bin = '';
for (const b of raw) bin += String.fromCharCode(b);
const publicKey = btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');

console.log('KEEPER_SIGNING_KEY (secret, private JWK):');
console.log(JSON.stringify({ kty: jwk.kty, crv: jwk.crv, d: jwk.d, x: jwk.x }));
console.log('');
console.log('public key (unpadded Base64url, publish):');
console.log(publicKey);
