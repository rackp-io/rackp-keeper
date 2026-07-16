/**
 * rackp-keeper — RACKP Keeper reference implementation.
 *
 * Transport: baseline HTTP binding (docs/TRANSPORT-BINDING.md in the rackp
 * repo). One endpoint; every protocol message is `POST {endpoint}` with a
 * JSON body carrying a `type` field. Acceptance is acknowledged with a
 * signed DELIVERY_RECEIPT (query types carry their protocol response in the
 * receipt's `response` field); definitive failures return a
 * DELIVERY_REJECTION with a 4xx status. Redelivery of identical bytes is
 * idempotent: the original acknowledgment is re-returned unchanged.
 */
import { messageHash, importSigningKey, signBody, publicKeyFromSigningKey } from './crypto';
import { isKnownType, validateMessage } from './validate';
import type { Env, HandlerOutcome, ProtocolMessage } from './types';
import {
  handleClaimAnchor,
  handleVerificationQuery,
  handleAnchorChainQuery,
  handleRefereeStatsQuery,
  handleFeeDeposit,
  handleFeeStatusQuery,
  handleIncidentNotice,
  handleRefereeProfile,
  handleDiscoveryRequest,
  handleFeeClaim,
  handleFeeReceipt,
  handleFeeRefundClaim,
  handleMailboxDeliver,
  handleMailboxQuery,
} from './handlers';

const MAX_BODY_BYTES = 262144; // request size limit (RFC-0002 §3, unconstrained payload input)

const MAILBOX_TYPES = new Set(['ACTOR_NOTIFICATION', 'EVIDENCE_QUERY_REQUEST', 'CONTRIBUTION_RESULT', 'POH_CERTIFICATE']);

function nowIso(): string {
  return new Date().toISOString().replace(/\.\d{3}Z$/, 'Z');
}

function json(body: unknown, status: number): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json; charset=utf-8' },
  });
}

async function signedRejection(
  env: Env,
  reason: string,
  detail?: string,
): Promise<Record<string, unknown>> {
  const body: Record<string, unknown> = {
    type: 'DELIVERY_REJECTION',
    reason,
    received_at: nowIso(),
    receiver_id: env.KEEPER_TERMINAL_ID,
  };
  if (detail) body.detail = detail;
  const key = await importSigningKey(env.KEEPER_SIGNING_KEY);
  body.signature = await signBody(key, body);
  return body;
}

async function signedReceipt(
  env: Env,
  msgHash: string,
  response?: Record<string, unknown>,
): Promise<Record<string, unknown>> {
  const body: Record<string, unknown> = {
    type: 'DELIVERY_RECEIPT',
    received_at: nowIso(),
    message_hash: msgHash,
    receiver_id: env.KEEPER_TERMINAL_ID,
  };
  if (response) body.response = response;
  const key = await importSigningKey(env.KEEPER_SIGNING_KEY);
  body.signature = await signBody(key, body);
  return body;
}

/**
 * Persist the acknowledgment under the message hash and return what is
 * actually stored — on a concurrent duplicate the first writer wins and both
 * deliveries observe the identical acknowledgment (TRANSPORT-BINDING §4).
 */
async function storeAck(
  env: Env,
  msgHash: string,
  status: number,
  body: Record<string, unknown>,
): Promise<{ status: number; body: unknown }> {
  await env.DB.prepare(
    'INSERT OR IGNORE INTO delivery_acks (message_hash, http_status, body_json) VALUES (?, ?, ?)',
  )
    .bind(msgHash, status, JSON.stringify(body))
    .run();
  const stored = await env.DB.prepare(
    'SELECT http_status, body_json FROM delivery_acks WHERE message_hash = ?',
  )
    .bind(msgHash)
    .first<{ http_status: number; body_json: string }>();
  return stored
    ? { status: stored.http_status, body: JSON.parse(stored.body_json) }
    : { status, body };
}

async function dispatch(env: Env, msg: ProtocolMessage, msgHash: string): Promise<HandlerOutcome> {
  switch (msg.type) {
    case 'CLAIM_ANCHOR':
      return handleClaimAnchor(env, msg);
    case 'VERIFICATION_QUERY':
      return handleVerificationQuery(env, msg);
    case 'ANCHOR_CHAIN_QUERY':
      return handleAnchorChainQuery(env, msg);
    case 'REFEREE_STATS_QUERY':
      return handleRefereeStatsQuery(env, msg);
    case 'FEE_DEPOSIT':
      return handleFeeDeposit(env, msg);
    case 'FEE_STATUS_QUERY':
      return handleFeeStatusQuery(env, msg);
    case 'INCIDENT_NOTICE':
      return handleIncidentNotice(env, msg);
    case 'REFEREE_PROFILE':
      return handleRefereeProfile(env, msg);
    case 'REFEREE_DISCOVERY_REQUEST':
      return handleDiscoveryRequest(env, msg);
    case 'FEE_CLAIM':
      return handleFeeClaim(env, msg);
    case 'FEE_RECEIPT':
      return handleFeeReceipt(env, msg);
    case 'FEE_REFUND_CLAIM':
      return handleFeeRefundClaim(env, msg);
    case 'MAILBOX_QUERY':
      return handleMailboxQuery(env, msg);
    default:
      if (MAILBOX_TYPES.has(msg.type)) return handleMailboxDeliver(env, msg, msgHash);
      return {
        rejection: {
          status: 422,
          reason: 'PROTOCOL_REJECTED',
          detail: `unsupported message type: ${msg.type}`,
        },
      };
  }
}

async function handlePost(request: Request, env: Env): Promise<Response> {
  const text = await request.text();
  if (new TextEncoder().encode(text).length > MAX_BODY_BYTES) {
    return json(await signedRejection(env, 'TOO_LARGE', `body exceeds ${MAX_BODY_BYTES} bytes`), 400);
  }

  let msg: unknown;
  try {
    msg = JSON.parse(text);
  } catch {
    return json(await signedRejection(env, 'MALFORMED', 'body is not valid JSON'), 400);
  }
  if (typeof msg !== 'object' || msg === null || Array.isArray(msg) || typeof (msg as any).type !== 'string') {
    return json(await signedRejection(env, 'MALFORMED', 'body must be a JSON object with a string `type`'), 400);
  }
  const message = msg as ProtocolMessage;

  // Idempotency (TRANSPORT-BINDING §4): identical bytes -> original ack.
  const msgHash = await messageHash(message);
  const prior = await env.DB.prepare(
    'SELECT http_status, body_json FROM delivery_acks WHERE message_hash = ?',
  )
    .bind(msgHash)
    .first<{ http_status: number; body_json: string }>();
  if (prior) return json(JSON.parse(prior.body_json), prior.http_status);

  if (!isKnownType(message.type) && message.type !== 'MAILBOX_QUERY') {
    const rej = await signedRejection(env, 'PROTOCOL_REJECTED', `unsupported message type: ${message.type}`);
    const stored = await storeAck(env, msgHash, 422, rej);
    return json(stored.body, stored.status);
  }

  const schemaError = validateMessage(message.type, message);
  if (schemaError) {
    const rej = await signedRejection(env, 'SCHEMA_VIOLATION', schemaError);
    const stored = await storeAck(env, msgHash, 400, rej);
    return json(stored.body, stored.status);
  }

  const outcome = await dispatch(env, message, msgHash);

  if (outcome.rejection) {
    const { status, reason, detail } = outcome.rejection;
    const rej = await signedRejection(env, reason, detail);
    const stored = await storeAck(env, msgHash, status, rej);
    return json(stored.body, stored.status);
  }

  const receipt = await signedReceipt(env, msgHash, outcome.response);
  const stored = await storeAck(env, msgHash, 200, receipt);
  return json(stored.body, stored.status);
}

/**
 * Cron: push-based FEE_RELEASE (RFC-0001 §6.15). When the appeal window has
 * closed with no pending appeal, release the escrowed balance to the Referee
 * and deliver the FEE_RELEASE message to its endpoint. The referee identity
 * comes from its ASSESSMENT_ISSUED anchor (own-Keeper topology) and the
 * endpoint from its stored REFEREE_PROFILE; where neither is known the
 * escrow stays claimable via pull (FEE_CLAIM). Undelivered releases are
 * retried with identical bytes on later runs.
 */
async function runScheduled(env: Env): Promise<void> {
  const db = env.DB;
  const nowMs = Date.now();

  const due = await db.prepare(
    `SELECT incident_id, round, currency, release_at, referee_id FROM escrows
     WHERE state = 'ESCROWED' AND appeal_pending = 0 AND release_at IS NOT NULL`,
  ).all<{ incident_id: string; round: number; currency: string | null; release_at: string; referee_id: string | null }>();

  for (const esc of due.results) {
    const releaseMs = Date.parse(esc.release_at);
    if (Number.isNaN(releaseMs) || nowMs < releaseMs) continue;

    let refereeId = esc.referee_id;
    if (!refereeId) {
      const anchor = await db.prepare(
        "SELECT terminal_id FROM anchors WHERE incident_id = ? AND action_type = 'ASSESSMENT_ISSUED' ORDER BY id DESC LIMIT 1",
      )
        .bind(esc.incident_id)
        .first<{ terminal_id: string }>();
      refereeId = anchor?.terminal_id ?? null;
    }
    if (!refereeId) continue; // unresolvable here — the pull path (FEE_CLAIM) covers it

    const bal = await db.prepare(
      'SELECT COALESCE(SUM(amount), 0) AS total FROM deposits WHERE incident_id = ? AND round = ? AND refunded = 0',
    )
      .bind(esc.incident_id, esc.round)
      .first<{ total: number }>();

    const releaseMsg = {
      type: 'FEE_RELEASE',
      incident_id: esc.incident_id,
      referee_id: refereeId,
      released_amount: bal?.total ?? 0,
      currency: esc.currency ?? 'USD',
      timestamp: nowIso(),
    };

    // Atomic transition before dispatch (RFC-0001 §4.4): a concurrent
    // FEE_CLAIM now gets ALREADY_RELEASED; double payment cannot occur.
    const upd = await db.prepare(
      `UPDATE escrows SET state = 'RELEASED', released_amount = ?, released_via = 'FEE_RELEASE',
         referee_id = ?, release_json = ?, release_delivered = 0, updated_at = datetime('now')
       WHERE incident_id = ? AND state = 'ESCROWED' AND appeal_pending = 0`,
    )
      .bind(releaseMsg.released_amount, refereeId, JSON.stringify(releaseMsg), esc.incident_id)
      .run();
    if (!upd.meta.changes) continue;
  }

  // Deliver (and retry) pending FEE_RELEASE messages with identical bytes.
  const pending = await db.prepare(
    `SELECT e.incident_id, e.release_json, e.referee_id, p.profile_json
     FROM escrows e LEFT JOIN referee_profiles p ON p.referee_id = e.referee_id
     WHERE e.state = 'RELEASED' AND e.released_via = 'FEE_RELEASE'
       AND e.release_delivered = 0 AND e.release_json IS NOT NULL`,
  ).all<{ incident_id: string; release_json: string; referee_id: string; profile_json: string | null }>();

  for (const row of pending.results) {
    if (!row.profile_json) continue; // endpoint unknown; keep for pull/retry
    const endpoint = (JSON.parse(row.profile_json) as { endpoint?: string }).endpoint;
    if (!endpoint || !/^https?:\/\//.test(endpoint)) continue;
    try {
      const res = await fetch(endpoint, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json; charset=utf-8' },
        body: row.release_json,
      });
      if (res.ok) {
        await db.prepare(
          "UPDATE escrows SET release_delivered = 1, updated_at = datetime('now') WHERE incident_id = ?",
        )
          .bind(row.incident_id)
          .run();
      }
    } catch {
      // 5xx/timeout: not delivered — retried on the next run (binding §4).
    }
  }
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    if (request.method === 'GET') {
      // TRANSPORT-BINDING §1: GET {endpoint} MUST return a capability summary
      // carrying receiver_id and public_key (STD-034) — a Keeper has no
      // profile message of its own, so this is the only channel a verifier
      // has for the key that checks this Keeper's DELIVERY_RECEIPT signatures.
      return json(
        {
          service: 'rackp-keeper',
          role: 'KEEPER',
          receiver_id: env.KEEPER_TERMINAL_ID,
          public_key: publicKeyFromSigningKey(env.KEEPER_SIGNING_KEY),
          binding: 'https://github.com/rackp-io/rackp/blob/main/docs/TRANSPORT-BINDING.md',
          accepts: [
            'CLAIM_ANCHOR', 'VERIFICATION_QUERY', 'ANCHOR_CHAIN_QUERY', 'REFEREE_STATS_QUERY', 'FEE_DEPOSIT',
            'FEE_STATUS_QUERY', 'INCIDENT_NOTICE', 'REFEREE_PROFILE', 'REFEREE_DISCOVERY_REQUEST',
            'FEE_CLAIM', 'FEE_RECEIPT', 'FEE_REFUND_CLAIM',
            'ACTOR_NOTIFICATION', 'EVIDENCE_QUERY_REQUEST', 'CONTRIBUTION_RESULT', 'POH_CERTIFICATE',
            'MAILBOX_QUERY',
          ],
        },
        200,
      );
    }
    if (request.method !== 'POST') {
      return json({ error: 'method not allowed' }, 405);
    }
    return handlePost(request, env);
  },

  async scheduled(_event: ScheduledEvent, env: Env): Promise<void> {
    await runScheduled(env);
  },
};
