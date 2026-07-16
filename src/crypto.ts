/**
 * JCS (RFC 8785) canonical JSON serialization.
 * Keys sorted by UTF-16 code units; numbers via ECMAScript ToString (which is
 * what RFC 8785 specifies). Validated against schemas/test-vectors/jcs.json.
 */
export function jcs(value: unknown): string {
  if (value === null || typeof value !== 'object') {
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return '[' + (value as unknown[]).map(jcs).join(',') + ']';
  }
  const keys = Object.keys(value as object).sort();
  return (
    '{' +
    keys
      .map((k) => JSON.stringify(k) + ':' + jcs((value as Record<string, unknown>)[k]))
      .join(',') +
    '}'
  );
}

export async function sha256hex(text: string): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(text));
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, '0')).join('');
}

/** SHA-256 over the JCS canonicalization of a message (TRANSPORT-BINDING §2 message_hash). */
export async function messageHash(message: unknown): Promise<string> {
  return sha256hex(jcs(message));
}

function base64urlDecode(s: string): Uint8Array {
  const b64 = s.replace(/-/g, '+').replace(/_/g, '/');
  const binary = atob(b64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

function base64urlEncode(bytes: Uint8Array): string {
  let binary = '';
  for (const b of bytes) binary += String.fromCharCode(b);
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}

/**
 * Verify an Ed25519 signature over the JCS canonicalization of `body`
 * (all fields except `signature`), per RFC-0001 §6 signing convention.
 */
export async function verifyEd25519(
  publicKeyBase64url: string,
  canonicalMessage: string,
  signatureBase64url: string,
): Promise<boolean> {
  try {
    const key = await crypto.subtle.importKey(
      'raw',
      base64urlDecode(publicKeyBase64url),
      { name: 'Ed25519' },
      false,
      ['verify'],
    );
    return await crypto.subtle.verify(
      'Ed25519',
      key,
      base64urlDecode(signatureBase64url),
      new TextEncoder().encode(canonicalMessage),
    );
  } catch {
    return false;
  }
}

/**
 * The Keeper's own signing key (DELIVERY_RECEIPT / DELIVERY_REJECTION,
 * TRANSPORT-BINDING §2). Supplied via the KEEPER_SIGNING_KEY secret as an
 * Ed25519 JWK JSON string: {"kty":"OKP","crv":"Ed25519","d":"...","x":"..."}.
 * Generate with scripts/genkey.mjs.
 */
export async function importSigningKey(jwkJson: string): Promise<CryptoKey> {
  const jwk = JSON.parse(jwkJson) as JsonWebKey;
  return crypto.subtle.importKey('jwk', jwk, { name: 'Ed25519' }, false, ['sign']);
}

/** The public half of a KEEPER_SIGNING_KEY JWK — already unpadded Base64url
 * (JWK `x`, RFC 8037), so no re-encoding is needed. Published via GET
 * {endpoint} (TRANSPORT-BINDING §1, STD-034); derived rather than stored
 * separately so it can never drift from the key that actually signs. */
export function publicKeyFromSigningKey(jwkJson: string): string {
  return (JSON.parse(jwkJson) as JsonWebKey).x!;
}

/** Sign `body` (JCS of all fields except `signature`) and return the unpadded Base64url signature. */
export async function signBody(key: CryptoKey, bodyWithoutSignature: unknown): Promise<string> {
  const sig = await crypto.subtle.sign(
    'Ed25519',
    key,
    new TextEncoder().encode(jcs(bodyWithoutSignature)),
  );
  return base64urlEncode(new Uint8Array(sig));
}
