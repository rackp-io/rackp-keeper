// test-integration.mjs — end-to-end tests for the single-endpoint transport
// binding (TRANSPORT-BINDING.md). Runs against a local `wrangler dev`
// instance by default:
//   npm run db:migrate:local
//   npx wrangler dev --port 8788     (in another terminal)
//   node test-integration.mjs
// Set BASE_URL to test a deployed instance (uses fresh UUIDs; safe to rerun).
import { createHash, randomUUID, webcrypto } from 'node:crypto';
import assert from 'node:assert/strict';

const { subtle } = webcrypto;
const BASE_URL = process.env.BASE_URL ?? 'http://127.0.0.1:8788';
// Public half of the dev signing key in .dev.vars — used to verify that the
// Keeper actually signs its receipts.
const KEEPER_PUBLIC_KEY = process.env.KEEPER_PUBLIC_KEY ?? 'M5iiOHeV4hOY-I5IOHCB7ozOvuVY2wT-89LnjUwWZF0';
const KEEPER_TERMINAL_ID = process.env.KEEPER_TERMINAL_ID ?? 'b3e1c9d2-4f6a-4a3b-8c5d-9e7f01234567';

// ── crypto helpers ───────────────────────────────────────────────────────────
function jcs(value) {
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return '[' + value.map(jcs).join(',') + ']';
  const keys = Object.keys(value).sort();
  return '{' + keys.map((k) => JSON.stringify(k) + ':' + jcs(value[k])).join(',') + '}';
}
const sha256hex = (s) => createHash('sha256').update(s, 'utf8').digest('hex');
const toB64url = (buf) =>
  Buffer.from(buf).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
const fromB64url = (s) => Buffer.from(s.replace(/-/g, '+').replace(/_/g, '/'), 'base64');
// Millisecond precision: retry-style messages in this suite differ only by
// timestamp, and second-precision would make them byte-identical — which the
// idempotency ledger (binding §4) correctly absorbs by design.
const now = () => new Date().toISOString();
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

/** A protocol terminal: Ed25519 keypair + per-terminal anchor sequence. */
async function terminal() {
  const pair = await subtle.generateKey({ name: 'Ed25519' }, true, ['sign', 'verify']);
  const raw = new Uint8Array(await subtle.exportKey('raw', pair.publicKey));
  return {
    id: randomUUID(),
    publicKey: toB64url(raw),
    seq: 0,
    async sign(body) {
      const sig = await subtle.sign('Ed25519', pair.privateKey, Buffer.from(jcs(body), 'utf8'));
      return toB64url(sig);
    },
  };
}

/** Build a signed CLAIM_ANCHOR for `payload`; attaches public_key at seq 1. */
async function anchor(t, payload, extra = {}) {
  t.seq += 1;
  const body = {
    type: 'CLAIM_ANCHOR',
    terminal_id: t.id,
    claim_id: randomUUID(),
    sequence_number: t.seq,
    timestamp: now(),
    data_hash: sha256hex(jcs(payload)),
    ...(t.seq === 1 ? { public_key: t.publicKey } : {}),
    ...extra,
  };
  return { ...body, signature: await t.sign(body) };
}

async function post(message) {
  const r = await fetch(BASE_URL, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json; charset=utf-8' },
    body: JSON.stringify(message),
  });
  return { status: r.status, body: await r.json().catch(() => null) };
}

let keeperVerifyKey;
async function assertReceipt(res, message, label) {
  assert.equal(res.status, 200, `${label}: expected 200, got ${res.status} ${JSON.stringify(res.body)}`);
  const receipt = res.body;
  assert.equal(receipt.type, 'DELIVERY_RECEIPT', `${label}: receipt type`);
  assert.equal(receipt.message_hash, sha256hex(jcs(message)), `${label}: message_hash binds the message`);
  const { signature, ...rest } = receipt;
  const valid = await subtle.verify(
    'Ed25519', keeperVerifyKey, fromB64url(signature), Buffer.from(jcs(rest), 'utf8'),
  );
  assert.equal(valid, true, `${label}: receipt signature verifies against the Keeper's key`);
  return receipt;
}
function assertRejection(res, status, reason, label) {
  assert.equal(res.status, status, `${label}: expected ${status}, got ${res.status} ${JSON.stringify(res.body)}`);
  assert.equal(res.body.type, 'DELIVERY_REJECTION', `${label}: rejection type`);
  assert.equal(res.body.reason, reason, `${label}: reason (got ${res.body.reason}: ${res.body.detail ?? ''})`);
}

// A signed INCIDENT_NOTICE from `signer` (G1). referee_id + signature are required;
// the Keeper verifies against the referee's registered key and binds the incident.
async function signedNotice(signer, fields) {
  const body = {
    type: 'INCIDENT_NOTICE', referee_id: signer.id, recipient_id: KEEPER_TERMINAL_ID,
    timestamp: now(), ...fields,
  };
  return { ...body, signature: await signer.sign(body) };
}

let passed = 0;
const ok = (name) => { passed++; console.log(`  ok: ${name}`); };

// ── tests ────────────────────────────────────────────────────────────────────
keeperVerifyKey = await subtle.importKey(
  'raw', fromB64url(KEEPER_PUBLIC_KEY), { name: 'Ed25519' }, false, ['verify'],
);

// GET: capability summary
{
  const r = await fetch(BASE_URL);
  const body = await r.json();
  assert.equal(r.status, 200);
  assert.equal(body.service, 'rackp-keeper');
  assert.ok(body.accepts.includes('CLAIM_ANCHOR'));
  ok('GET returns capability summary');
}

// ── anchoring, registration, idempotency, rejections ────────────────────────
const actor = await terminal();
const claimant = await terminal();
const referee = await terminal();

{
  const a1 = await anchor(actor, { event: 'draft_saved', n: 1 });
  const r1 = await post(a1);
  await assertReceipt(r1, a1, 'first anchor');
  ok('CLAIM_ANCHOR seq 1 registers the terminal and returns a signed receipt');

  const r1again = await post(a1);
  assert.equal(r1again.status, 200, 'redelivery status');
  assert.deepEqual(r1again.body, r1.body, 'redelivery returns the identical original receipt');
  ok('idempotent redelivery re-returns the original acknowledgment (binding §4)');

  // SESSION_START with the norm_profiles ARRAY (current claim_anchor schema).
  const s = await anchor(actor, { event: 'session' }, {
    action_type: 'SESSION_START',
    norm_profiles: [
      { norm_profile_id: 'rackp.standard.v1', norm_fetch_url: 'https://rackp.io/norms/rackp-standard-v1.json' },
    ],
  });
  await assertReceipt(await post(s), s, 'session start');
  ok('SESSION_START with norm_profiles array is accepted');

  // SESSION_START without norm_profiles must fail the schema's allOf.
  const bad = await anchor(actor, { event: 'bad session' }, { action_type: 'SESSION_START' });
  assertRejection(await post(bad), 400, 'SCHEMA_VIOLATION', 'SESSION_START without norm_profiles');
  actor.seq -= 1; // rejected anchor did not consume the sequence slot server-side
  ok('SESSION_START without norm_profiles -> 400 SCHEMA_VIOLATION');

  // Tampered signature.
  const t = await anchor(actor, { event: 'tampered' });
  t.signature = t.signature.slice(0, -4) + 'AAAA';
  assertRejection(await post(t), 401, 'SIGNATURE_INVALID', 'tampered anchor');
  actor.seq -= 1;
  ok('tampered signature -> 401 SIGNATURE_INVALID');

  // Unknown terminal, seq > 1, no public_key.
  const stranger = await terminal();
  stranger.seq = 5;
  const u = await anchor(stranger, { event: 'no registration' });
  assertRejection(await post(u), 401, 'UNKNOWN_TERMINAL', 'unregistered terminal');
  ok('unregistered terminal without public_key -> 401 UNKNOWN_TERMINAL');

  // Non-monotonic sequence.
  const n1 = await anchor(actor, { event: 'seq a' });
  await assertReceipt(await post(n1), n1, 'seq a');
  const rb = {
    type: 'CLAIM_ANCHOR', terminal_id: actor.id, claim_id: randomUUID(), sequence_number: 1,
    timestamp: now(), data_hash: sha256hex(jcs({ event: 'seq regressed' })), public_key: actor.publicKey,
  };
  const regressed = { ...rb, signature: await actor.sign(rb) };
  assertRejection(await post(regressed), 409, 'SEQUENCE_CONFLICT', 'seq regression');
  ok('non-monotonic sequence_number -> 409 SEQUENCE_CONFLICT');

  // Unknown type.
  const r = await post({ type: 'BOGUS_MESSAGE', timestamp: now() });
  assertRejection(r, 422, 'PROTOCOL_REJECTED', 'unknown type');
  ok('unknown message type -> 422 PROTOCOL_REJECTED');

  // Not JSON.
  const nj = await fetch(BASE_URL, { method: 'POST', body: 'not json{{' });
  assert.equal(nj.status, 400);
  assert.equal((await nj.json()).reason, 'MALFORMED');
  ok('non-JSON body -> 400 MALFORMED');
}

// ── verification query (embedded response) ──────────────────────────────────
{
  const payload = { event: 'evidence', value: 42 };
  const a = await anchor(claimant, payload);
  await assertReceipt(await post(a), a, 'claimant anchor');

  const start = new Date(Date.now() - 3600_000).toISOString();
  const end = new Date(Date.now() + 3600_000).toISOString();
  const missing = sha256hex('nothing anchored this');
  const q = {
    type: 'VERIFICATION_QUERY',
    incident_id: randomUUID(),
    requester_id: referee.id,
    target_terminal_id: claimant.id,
    target_hashes: [a.data_hash, missing],
    original_timestamp_range: { start, end },
    timestamp: now(),
  };
  const res = await post(q);
  const receipt = await assertReceipt(res, q, 'verification');
  const vr = receipt.response;
  assert.equal(vr.type, 'VERIFICATION_RESULT');
  assert.equal(vr.results[0].matched, true);
  assert.equal(vr.results[0].matched_record.claim_id, a.claim_id);
  assert.equal(vr.results[1].matched, false);
  assert.equal(vr.results[1].matched_record, null);
  ok('VERIFICATION_QUERY -> receipt-embedded VERIFICATION_RESULT (match + miss)');

  // Cross-terminal isolation: the same hash queried as the ACTOR's must not match.
  const iso = { ...q, target_terminal_id: actor.id, timestamp: now() };
  const isoReceipt = await assertReceipt(await post(iso), iso, 'isolation');
  assert.equal(isoReceipt.response.results[0].matched, false);
  ok("another terminal's anchored hash does not verify as this party's evidence");
}

// ── referee profile / discovery / stats ─────────────────────────────────────
const profile = {
  type: 'REFEREE_PROFILE',
  network: 'TESTNET',
  referee_id: referee.id,
  public_key: referee.publicKey,
  endpoint: 'https://referee.rackp.io',
  keeper_endpoint: BASE_URL,
  conduct_norms: [{ jurisdiction_code: 'GLOBAL', domain: 'general', norm_profile_id: 'rackp.standard.v1' }],
  availability_status: 'AVAILABLE',
  fee: { model: 'FIXED', amount: 200, currency: 'USD', cancellation_fee: 0.1 },
  assessment_deadline_hours: 720,
  profile_timestamp: now(),
};
{
  await assertReceipt(await post(profile), profile, 'profile');
  const d = { type: 'REFEREE_DISCOVERY_REQUEST', requester_id: claimant.id, timestamp: now(), filters: { fee_model: 'FIXED' } };
  const receipt = await assertReceipt(await post(d), d, 'discovery');
  assert.equal(receipt.response.type, 'REFEREE_DISCOVERY_RESULT');
  assert.ok(receipt.response.profiles.some((p) => p.referee_id === referee.id));
  ok('REFEREE_PROFILE stored; discovery returns it in REFEREE_DISCOVERY_RESULT');
}

// Referee anchors its own actions here (this Keeper doubles as Kr).
const incident = randomUUID();
const certId = `CERT-${incident}-0001`;
{
  const s = await anchor(referee, { event: 'referee session' }, {
    action_type: 'SESSION_START',
    norm_profiles: [{ norm_profile_id: 'rackp.standard.v1', norm_fetch_url: 'https://rackp.io/norms/rackp-standard-v1.json' }],
  });
  await assertReceipt(await post(s), s, 'referee session');
  const issued = await anchor(referee, { event: 'assessment issued' }, {
    action_type: 'ASSESSMENT_ISSUED', incident_id: incident, cert_id: certId,
  });
  await assertReceipt(await post(issued), issued, 'assessment issued');
  const poh = await anchor(referee, { event: 'poh cert' }, {
    action_type: 'POH_CERT_ISSUED', incident_id: randomUUID(), cert_id: 'CERT-POH-0001',
  });
  await assertReceipt(await post(poh), poh, 'poh cert');

  const q = { type: 'REFEREE_STATS_QUERY', terminal_id: referee.id, requester_id: claimant.id, timestamp: now() };
  const receipt = await assertReceipt(await post(q), q, 'stats');
  const st = receipt.response;
  assert.equal(st.found, true);
  assert.equal(st.assessment_count, 1, 'assessment_count');
  assert.equal(st.poh_cert_count, 1, 'poh_cert_count counted separately');
  assert.equal(st.unreceived_count, 2, 'both FIXED issuances owe a receipt');
  assert.equal(st.anchor_continuity, true);
  ok('stats: poh_cert_count separate; unreceived_count opened by both anchors (STD-032)');
}

// ── escrow: deposits, status, pull payment, receipt copy ─────────────────────
{
  const dep = async (who, amount) => {
    const body = {
      type: 'FEE_DEPOSIT', incident_id: incident, depositor_id: who.id,
      amount, currency: 'USD', timestamp: now(),
    };
    return { ...body, signature: await who.sign(body) };
  };
  const d1 = await dep(claimant, 100);
  await assertReceipt(await post(d1), d1, 'claimant deposit');
  const rd = await post(d1); // identical bytes
  assert.equal(rd.status, 200);
  ok('duplicate FEE_DEPOSIT bytes are idempotent (no double escrow)');
  const d2 = await dep(actor, 100);
  await assertReceipt(await post(d2), d2, 'actor deposit');

  const fs = {
    type: 'FEE_STATUS_QUERY', incident_id: incident, referee_id: referee.id,
    terminal_id: claimant.id, timestamp: now(),
  };
  let receipt = await assertReceipt(await post(fs), fs, 'fee status');
  assert.equal(receipt.response.deposited, true);
  assert.equal(receipt.response.prior_assessment_count, 1, 'ASSESSMENT_ISSUED anchor counts as prior verdict');
  assert.deepEqual(receipt.response.prior_verdict_refs, [certId]);
  ok('FEE_STATUS_RESULT: deposited + prior verdict refs from the anchor');

  const open = await signedNotice(referee, {
    incident_id: incident, event_type: 'INCIDENT_OPEN', assessment_deadline_hours: 720,
  });
  await assertReceipt(await post(open), open, 'incident open');

  // Refund before the deadline must be rejected.
  const refundBody = { type: 'FEE_REFUND_CLAIM', incident_id: incident, depositor_id: claimant.id, timestamp: now() };
  const refund1 = { ...refundBody, signature: await claimant.sign(refundBody) };
  receipt = await assertReceipt(await post(refund1), refund1, 'early refund');
  assert.equal(receipt.response.status, 'REJECTED');
  assert.equal(receipt.response.rejection_reason, 'DEADLINE_NOT_ELAPSED');
  assert.ok(receipt.response.deadline_expires_at, 'retry hint present');
  ok('FEE_REFUND_CLAIM before deadline -> REJECTED DEADLINE_NOT_ELAPSED (STD-028)');

  // FEE_CLAIM with an unknown cert.
  const claimBase = { type: 'FEE_CLAIM', incident_id: incident, referee_id: referee.id, currency: 'USD' };
  const badClaim = { ...claimBase, cert_id: 'CERT-UNKNOWN', timestamp: now() };
  const badClaimSigned = { ...badClaim, signature: await referee.sign(badClaim) };
  receipt = await assertReceipt(await post(badClaimSigned), badClaimSigned, 'bad cert claim');
  assert.equal(receipt.response.rejection_reason, 'CERT_NOT_FOUND');
  ok('FEE_CLAIM with unknown cert -> REJECTED CERT_NOT_FOUND');

  // Before ASSESSMENT_COMPLETE the release timer has not started.
  const early = { ...claimBase, cert_id: certId, timestamp: now() };
  const earlySigned = { ...early, signature: await referee.sign(early) };
  receipt = await assertReceipt(await post(earlySigned), earlySigned, 'early claim');
  assert.equal(receipt.response.rejection_reason, 'TIMER_NOT_ELAPSED');
  ok('FEE_CLAIM before ASSESSMENT_COMPLETE -> REJECTED TIMER_NOT_ELAPSED');

  // Complete with an appeal window already in the past (timer elapsed).
  const complete = await signedNotice(referee, {
    incident_id: incident, event_type: 'ASSESSMENT_COMPLETE', cert_id: certId,
    additional_appeal_limit_datetime: new Date(Date.now() - 1000).toISOString(),
  });
  await assertReceipt(await post(complete), complete, 'assessment complete');

  // Refund after completion is the release flow's business.
  const refund2Body = { ...refundBody, timestamp: now() };
  const refund2 = { ...refund2Body, signature: await claimant.sign(refund2Body) };
  receipt = await assertReceipt(await post(refund2), refund2, 'refund after complete');
  assert.equal(receipt.response.rejection_reason, 'ASSESSMENT_COMPLETED');
  ok('FEE_REFUND_CLAIM after ASSESSMENT_COMPLETE -> REJECTED ASSESSMENT_COMPLETED');

  // Appeal suspends the release timer.
  const appeal = await signedNotice(referee, { incident_id: incident, event_type: 'APPEAL_RECEIVED' });
  await assertReceipt(await post(appeal), appeal, 'appeal received');
  const pend = { ...claimBase, cert_id: certId, timestamp: now() };
  const pendSigned = { ...pend, signature: await referee.sign(pend) };
  receipt = await assertReceipt(await post(pendSigned), pendSigned, 'claim during appeal');
  assert.equal(receipt.response.rejection_reason, 'APPEAL_PENDING');
  ok('FEE_CLAIM during a pending appeal -> REJECTED APPEAL_PENDING');
  const rejectAppeal = await signedNotice(referee, { incident_id: incident, event_type: 'APPEAL_REJECTED' });
  await assertReceipt(await post(rejectAppeal), rejectAppeal, 'appeal rejected');

  // Pull payment: full balance released once, exactly once.
  const good = { ...claimBase, cert_id: certId, timestamp: now() };
  const goodSigned = { ...good, signature: await referee.sign(good) };
  receipt = await assertReceipt(await post(goodSigned), goodSigned, 'accepted claim');
  assert.equal(receipt.response.status, 'ACCEPTED');
  assert.equal(receipt.response.released_amount, 200, 'full escrowed balance, not doubled by duplicate deposit');
  ok('FEE_CLAIM after timer -> ACCEPTED, releases exactly the held 200');

  const again = { ...claimBase, cert_id: certId, timestamp: now() };
  const againSigned = { ...again, signature: await referee.sign(again) };
  receipt = await assertReceipt(await post(againSigned), againSigned, 'second claim');
  assert.equal(receipt.response.rejection_reason, 'ALREADY_RELEASED');
  ok('second FEE_CLAIM -> REJECTED ALREADY_RELEASED (no double payment)');

  // Refund after release.
  const refund3Body = { ...refundBody, timestamp: now() };
  const refund3 = { ...refund3Body, signature: await claimant.sign(refund3Body) };
  receipt = await assertReceipt(await post(refund3), refund3, 'refund after release');
  assert.equal(receipt.response.rejection_reason, 'ALREADY_RELEASED');
  ok('FEE_REFUND_CLAIM after release -> REJECTED ALREADY_RELEASED');

  // FEE_RECEIPT settles the escrow and closes the unreceived obligation.
  const receiptBody = {
    type: 'FEE_RECEIPT', incident_id: incident, referee_id: referee.id, cert_id: certId,
    received_amount: 200, currency: 'USD', triggered_by: 'FEE_CLAIM_RESULT', timestamp: now(),
  };
  const feeReceipt = { ...receiptBody, signature: await referee.sign(receiptBody) };
  await assertReceipt(await post(feeReceipt), feeReceipt, 'fee receipt');
  const q = { type: 'REFEREE_STATS_QUERY', terminal_id: referee.id, requester_id: claimant.id, timestamp: now() };
  receipt = await assertReceipt(await post(q), q, 'stats after receipt');
  assert.equal(receipt.response.unreceived_count, 1, 'assessment closed; PoHI cert still owes its receipt');
  ok('FEE_RECEIPT closes unreceived_count for its incident (STD-032)');
}

// ── STD-028 timeout refund with a short declared window ─────────────────────
{
  const inc2 = randomUUID();
  const depBody = { type: 'FEE_DEPOSIT', incident_id: inc2, depositor_id: claimant.id, amount: 50, currency: 'USD', timestamp: now() };
  const depSigned = { ...depBody, signature: await claimant.sign(depBody) };
  await assertReceipt(await post(depSigned), depSigned, 'timeout deposit');
  const open = await signedNotice(referee, {
    incident_id: inc2, event_type: 'INCIDENT_OPEN', assessment_deadline_hours: 0.0002,
  });
  await assertReceipt(await post(open), open, 'short window open');
  await sleep(1500); // 0.0002h = 0.72s

  const rb = { type: 'FEE_REFUND_CLAIM', incident_id: inc2, depositor_id: claimant.id, timestamp: now() };
  const refund = { ...rb, signature: await claimant.sign(rb) };
  let receipt = await assertReceipt(await post(refund), refund, 'timeout refund');
  assert.equal(receipt.response.status, 'ACCEPTED');
  assert.equal(receipt.response.refunded_amount, 50, 'full amount, no cancellation fee');
  ok('deadline elapsed -> FEE_REFUND_CLAIM ACCEPTED in full (escrow EXPIRED)');

  const rb2 = { ...rb, timestamp: now() };
  const refund2 = { ...rb2, signature: await claimant.sign(rb2) };
  receipt = await assertReceipt(await post(refund2), refund2, 'double refund');
  assert.equal(receipt.response.rejection_reason, 'ALREADY_REFUNDED');
  ok('second refund -> REJECTED ALREADY_REFUNDED (no double refund)');

  // A late claim against the EXPIRED escrow confers no payment right.
  const lateBody = { type: 'FEE_CLAIM', incident_id: inc2, referee_id: referee.id, cert_id: certId, currency: 'USD', timestamp: now() };
  const late = { ...lateBody, signature: await referee.sign(lateBody) };
  receipt = await assertReceipt(await post(late), late, 'late claim');
  assert.equal(receipt.response.rejection_reason, 'ESCROW_EXPIRED');
  ok('late FEE_CLAIM on EXPIRED escrow -> REJECTED ESCROW_EXPIRED (STD-028)');
}

// ── mailbox (party-addressed messages) ───────────────────────────────────────
{
  const nb = {
    type: 'ACTOR_NOTIFICATION', incident_id: incident, referee_id: referee.id, claimant_id: claimant.id,
    incident_summary: 'test incident for mailbox delivery',
    incident_timestamp: now(), response_deadline: new Date(Date.now() + 86400_000).toISOString(),
    timestamp: now(),
  };
  const notification = { ...nb, signature: await referee.sign(nb) };
  await assertReceipt(await post(notification), notification, 'mailbox delivery');
  ok('party-addressed ACTOR_NOTIFICATION accepted into the mailbox');

  const qb = { type: 'MAILBOX_QUERY', terminal_id: actor.id, incident_id: incident, timestamp: now() };
  const query = { ...qb, signature: await actor.sign(qb) };
  const receipt = await assertReceipt(await post(query), query, 'mailbox query');
  assert.equal(receipt.response.type, 'MAILBOX_RESULT');
  assert.ok(
    receipt.response.messages.some((m) => m.message.type === 'ACTOR_NOTIFICATION'),
    'held notification is retrievable',
  );
  ok('MAILBOX_QUERY (signed) returns the held message');

  // `since` cursor in the ISO form clients echo back (the mailbox stores
  // SQLite datetime; the ' ' vs 'T' byte difference must not empty the read).
  const qPast = { type: 'MAILBOX_QUERY', terminal_id: actor.id, incident_id: incident, since: new Date(Date.now() - 3600_000).toISOString(), timestamp: now() };
  const rp = await post({ ...qPast, signature: await actor.sign(qPast) });
  assert.equal(rp.status, 200);
  assert.ok(rp.body.response.messages.length >= 1, 'ISO since in the past returns held messages');
  const qFut = { type: 'MAILBOX_QUERY', terminal_id: actor.id, incident_id: incident, since: new Date(Date.now() + 3600_000).toISOString(), timestamp: now() };
  const rf = await post({ ...qFut, signature: await actor.sign(qFut) });
  assert.equal(rf.status, 200);
  assert.equal(rf.body.response.messages.length, 0, 'ISO since in the future returns nothing');
  ok('MAILBOX_QUERY since accepts the ISO cursor form (normalized against stored datetimes)');
}

// ── G2: split-Keeper key distribution via REFEREE_PROFILE ────────────────────
{
  // A Referee that NEVER anchors at this Keeper (the split-Keeper case: it anchors
  // only at its own Kr). Its signed FEE_CLAIM can be verified here only after it
  // publishes its REFEREE_PROFILE, which carries its public_key.
  const splitReferee = await terminal();
  const inc = randomUUID();
  // A FEE_CLAIM claiming to be `refId`, signed by terminal `signer` over the exact body.
  const signedClaim = async (signer, refId) => {
    const body = {
      type: 'FEE_CLAIM', incident_id: inc, referee_id: refId,
      cert_id: 'CERT-NONE', currency: 'USD', timestamp: now(),
    };
    return { ...body, signature: await signer.sign(body) };
  };

  // Before publishing: the Keeper holds no key for it -> UNKNOWN_TERMINAL.
  const early = await signedClaim(splitReferee, splitReferee.id);
  assertRejection(await post(early), 401, 'UNKNOWN_TERMINAL', 'FEE_CLAIM before profile');
  ok('FEE_CLAIM from a Referee that never anchored/published here -> 401 UNKNOWN_TERMINAL (G2)');

  // Publish its profile (carrying public_key). The Keeper registers the key.
  const p = {
    type: 'REFEREE_PROFILE', network: 'TESTNET', referee_id: splitReferee.id,
    public_key: splitReferee.publicKey, endpoint: 'https://split.referee.rackp.io',
    keeper_endpoint: 'https://kr.rackp.io',
    conduct_norms: [{ jurisdiction_code: 'GLOBAL', domain: 'general', norm_profile_id: 'rackp.standard.v1' }],
    availability_status: 'AVAILABLE', fee: { model: 'FIXED', amount: 100, currency: 'USD' },
    profile_timestamp: now(),
  };
  await assertReceipt(await post(p), p, 'split referee profile');

  // Now a signed FEE_CLAIM verifies (reaches business logic -> CERT_NOT_FOUND).
  const verifiable = await signedClaim(splitReferee, splitReferee.id);
  const receipt = await assertReceipt(await post(verifiable), verifiable, 'FEE_CLAIM after profile');
  assert.equal(receipt.response.type, 'FEE_CLAIM_RESULT');
  assert.equal(receipt.response.rejection_reason, 'CERT_NOT_FOUND',
    'verified via profile-registered key; rejected only for lack of a verdict');
  ok('after publishing its REFEREE_PROFILE, the Referee is verified via the profile key (G2)');

  // A forged FEE_CLAIM (someone else signing as the now-registered referee) fails.
  const forger = await terminal();
  assertRejection(await post(await signedClaim(forger, splitReferee.id)), 401, 'SIGNATURE_INVALID', 'forged FEE_CLAIM');
  ok('a FEE_CLAIM signed with the wrong key -> 401 SIGNATURE_INVALID');

  // TOFU: a later profile with a different key does not overwrite the registered one.
  const impostorProfile = { ...p, public_key: forger.publicKey, profile_timestamp: now() };
  await assertReceipt(await post(impostorProfile), impostorProfile, 'impostor profile');
  assertRejection(await post(await signedClaim(forger, splitReferee.id)), 401, 'SIGNATURE_INVALID', 'post-impostor forged claim');
  ok('a later profile with a different key does not overwrite the registered key (TOFU)');
}

// ── G1: INCIDENT_NOTICE authentication + incident binding ────────────────────
{
  const inc = randomUUID();
  // The Referee (key registered via its anchors) opens the incident -> binds to it.
  const open = await signedNotice(referee, { incident_id: inc, event_type: 'INCIDENT_OPEN', assessment_deadline_hours: 720 });
  await assertReceipt(await post(open), open, 'g1 incident open');
  ok('signed INCIDENT_NOTICE(INCIDENT_OPEN) binds the incident to its Referee (G1)');

  // A notice from a terminal whose key the Keeper does not hold -> UNKNOWN_TERMINAL.
  const stranger = await terminal();
  const strangerNotice = await signedNotice(stranger, { incident_id: inc, event_type: 'ASSESSMENT_WITHDRAWN', cancellation_fee: 0 });
  assertRejection(await post(strangerNotice), 401, 'UNKNOWN_TERMINAL', 'notice from unregistered terminal');
  ok('INCIDENT_NOTICE from a terminal with no registered key -> 401 UNKNOWN_TERMINAL (G1)');

  // A DIFFERENT Referee whose key IS registered, but which is not this incident's
  // Referee -> PROTOCOL_REJECTED. Authentication alone is not authorization.
  const otherReferee = await terminal();
  const op = {
    type: 'REFEREE_PROFILE', network: 'TESTNET', referee_id: otherReferee.id,
    public_key: otherReferee.publicKey, endpoint: 'https://other.rackp.io',
    keeper_endpoint: 'https://kr.rackp.io',
    conduct_norms: [{ jurisdiction_code: 'GLOBAL', domain: 'general', norm_profile_id: 'rackp.standard.v1' }],
    availability_status: 'AVAILABLE', fee: { model: 'FIXED', amount: 100, currency: 'USD' }, profile_timestamp: now(),
  };
  await assertReceipt(await post(op), op, 'other referee profile');
  const forged = await signedNotice(otherReferee, { incident_id: inc, event_type: 'ASSESSMENT_WITHDRAWN', cancellation_fee: 0.1 });
  assertRejection(await post(forged), 422, 'PROTOCOL_REJECTED', 'notice from the wrong Referee');
  ok('INCIDENT_NOTICE from a registered but wrong Referee -> 422 PROTOCOL_REJECTED (binding, G1)');

  // The same binding gates FEE_CLAIM and FEE_RECEIPT: a registered but wrong Referee
  // cannot claim or settle an incident bound to another (identity != authorization).
  const wrongClaimBody = { type: 'FEE_CLAIM', incident_id: inc, referee_id: otherReferee.id, cert_id: 'CERT-NONE', currency: 'USD', timestamp: now() };
  const wrongClaim = { ...wrongClaimBody, signature: await otherReferee.sign(wrongClaimBody) };
  assertRejection(await post(wrongClaim), 422, 'PROTOCOL_REJECTED', 'FEE_CLAIM from the wrong Referee');
  ok('FEE_CLAIM from a registered but wrong Referee -> 422 PROTOCOL_REJECTED (binding, G1)');

  const wrongReceiptBody = { type: 'FEE_RECEIPT', incident_id: inc, referee_id: otherReferee.id, cert_id: 'CERT-NONE', received_amount: 100, currency: 'USD', triggered_by: 'FEE_RELEASE', timestamp: now() };
  const wrongReceipt = { ...wrongReceiptBody, signature: await otherReferee.sign(wrongReceiptBody) };
  assertRejection(await post(wrongReceipt), 422, 'PROTOCOL_REJECTED', 'FEE_RECEIPT from the wrong Referee');
  ok('FEE_RECEIPT from a registered but wrong Referee -> 422 PROTOCOL_REJECTED (binding, G1)');
}

// ── G4: ANCHOR_CHAIN_QUERY ledger disclosure (RFC-0001 §6.27/§6.28) ──────────
{
  const inc = randomUUID();
  const party = await terminal();

  // Chain under test: [t0] .. SESSION_START(norm) .. [wStart] w1 w2 w3 [wEnd].
  // Millisecond sleeps separate the timestamps so the window boundaries are
  // unambiguous.
  const t0 = now();
  await sleep(5);
  const ss = await anchor(party, { event: 'session' }, {
    action_type: 'SESSION_START',
    norm_profiles: [{ norm_profile_id: 'jp.example.content.v1', norm_fetch_url: 'https://norms.example/content-v1.json' }],
  });
  await assertReceipt(await post(ss), ss, 'g4 session start');
  await sleep(5);
  const wStart = now();
  await sleep(5);
  const works = [];
  for (let n = 1; n <= 3; n++) {
    const w = await anchor(party, { event: 'work', n });
    await assertReceipt(await post(w), w, `g4 work anchor ${n}`);
    works.push(w);
    await sleep(5);
  }
  const wEnd = now();

  // Bind the incident to `referee` (its key is registered from earlier anchors).
  const open = await signedNotice(referee, { incident_id: inc, event_type: 'INCIDENT_OPEN', assessment_deadline_hours: 720 });
  await assertReceipt(await post(open), open, 'g4 incident open');

  const chainQuery = async (signer, fields = {}) => {
    const body = {
      type: 'ANCHOR_CHAIN_QUERY', incident_id: inc, requester_id: signer.id,
      target_terminal_id: party.id, range: { start: wStart, end: wEnd },
      timestamp: now(), ...fields,
    };
    return { ...body, signature: await signer.sign(body) };
  };

  // The bound Referee reads the window: 3 work anchors, verbatim, ascending
  // seq — and the governing SESSION_START from before the window.
  const q1 = await chainQuery(referee);
  const rc1 = await assertReceipt(await post(q1), q1, 'chain query (bound referee)');
  const res1 = rc1.response;
  assert.equal(res1.type, 'ANCHOR_CHAIN_RESULT');
  assert.equal(res1.count, 3, 'count == in-window anchors');
  assert.equal(res1.truncated, false);
  assert.deepEqual(res1.anchors.map((a) => a.sequence_number), [2, 3, 4], 'ascending seq, window only');
  assert.deepEqual(res1.anchors[0], works[0], 'anchors returned verbatim as stored (signature included)');
  assert.equal(res1.session_start.claim_id, ss.claim_id, 'governing SESSION_START returned from outside the window');
  assert.equal(res1.session_start.norm_profiles[0].norm_profile_id, 'jp.example.content.v1', 'Norm declaration rides the governing SESSION_START (§9.3)');
  ok('ANCHOR_CHAIN_QUERY returns the window ledger + governing SESSION_START (G4)');

  // Widening the window past the session start: SESSION_START joins the
  // in-window anchors, and no earlier declaration governs -> null.
  const q2 = await chainQuery(referee, { range: { start: t0, end: wEnd } });
  const rc2 = await assertReceipt(await post(q2), q2, 'chain query (widened window)');
  assert.equal(rc2.response.count, 4, 'widened window covers the SESSION_START too');
  assert.equal(rc2.response.anchors[0].claim_id, ss.claim_id);
  assert.equal(rc2.response.session_start, null, 'no SESSION_START at or before the widened start -> null');
  ok('widened window: SESSION_START moves into anchors[]; governing declaration is null (MAY deep-verify path)');

  // Authorization (§6.27): unregistered key, registered-but-unbound requester,
  // and the self-query exception.
  const stranger = await terminal();
  assertRejection(await post(await chainQuery(stranger)), 401, 'UNKNOWN_TERMINAL', 'chain query from unregistered terminal');
  ok('ANCHOR_CHAIN_QUERY from an unregistered terminal -> 401 UNKNOWN_TERMINAL');

  const nosy = await terminal();
  const na = await anchor(nosy, { event: 'noise' }); // registers nosy's key
  await assertReceipt(await post(na), na, 'nosy registration anchor');
  assertRejection(await post(await chainQuery(nosy)), 422, 'PROTOCOL_REJECTED', 'chain query from unbound terminal');
  ok('ANCHOR_CHAIN_QUERY from a registered but unbound requester -> 422 PROTOCOL_REJECTED');

  const selfQ = await chainQuery(party, { incident_id: randomUUID(), requester_id: party.id });
  const rcSelf = await assertReceipt(await post(selfQ), selfQ, 'self chain query');
  assert.equal(rcSelf.response.count, 3, 'self-query needs no incident binding');
  ok('a terminal may read its own chain regardless of incident binding (self-query)');
}

// ── POH_CERTIFICATE mailbox delivery (RFC-0001 §8.4 / §4.4) ──────────────────
{
  const cert_id = randomUUID();
  const certBody = {
    type: 'POH_CERTIFICATE', cert_id, issue_date: now(), referee_id: referee.id,
    subject_terminal_id: claimant.id,
    anchor_range: { start: now(), end: now() },
    provenance: { human_ratio: 0.8, ai_ratio: 0.2, confidence_level: 'MEDIUM' },
    keeper: { keeper_id: KEEPER_TERMINAL_ID },
    subject_data_hash: sha256hex('artifact-bytes'),
    cert_url: 'https://referee.rackp.io/certs/' + cert_id,
    proof_hash: sha256hex('proof'),
  };
  const cert = { ...certBody, signature: await referee.sign(certBody) };
  await assertReceipt(await post(cert), cert, 'poh certificate delivery');

  const qb = { type: 'MAILBOX_QUERY', terminal_id: claimant.id, timestamp: now() };
  const q = { ...qb, signature: await claimant.sign(qb) };
  const rc = await assertReceipt(await post(q), q, 'mailbox query for poh certificate');
  const held = rc.response.messages.find((m) => m.message.type === 'POH_CERTIFICATE' && m.message.cert_id === cert_id);
  assert.ok(held, 'POH_CERTIFICATE is held in the mailbox and retrievable by the party');
  ok('POH_CERTIFICATE is accepted as a party-addressed mailbox message (PoHI delivery path)');
}

console.log(`\nall ${passed} integration checks passed against ${BASE_URL}`);
