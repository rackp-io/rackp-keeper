/**
 * Per-type message handlers. Field shapes are guaranteed by the JSON Schema
 * validation in index.ts before dispatch; handlers implement protocol
 * semantics (RFC-0001 §4.4, §6) and the escrow state machine
 * (ESCROWED → RELEASED → SETTLED / WITHDRAWN / EXPIRED, STD-028).
 *
 * Outcome convention: `{}` = acknowledge with a bare DELIVERY_RECEIPT;
 * `{ response }` = embed the protocol response in the receipt
 * (TRANSPORT-BINDING §2); `{ rejection }` = DELIVERY_REJECTION.
 */
import { jcs, verifyEd25519 } from './crypto';
import type { Env, EscrowRow, HandlerOutcome, ProtocolMessage } from './types';

const DEFAULT_ASSESSMENT_DEADLINE_HOURS = 720; // STD-027 Standard Norm default

function nowIso(): string {
  return new Date().toISOString().replace(/\.\d{3}Z$/, 'Z');
}

function reject(status: 400 | 401 | 409 | 422, reason: string, detail?: string): HandlerOutcome {
  return { rejection: { status, reason, detail } };
}

function parseMs(iso: string | null | undefined): number | null {
  if (!iso) return null;
  const ms = Date.parse(iso);
  return Number.isNaN(ms) ? null : ms;
}

async function getPublicKey(env: Env, terminalId: string): Promise<string | null> {
  const row = await env.DB.prepare('SELECT public_key FROM public_keys WHERE terminal_id = ?')
    .bind(terminalId)
    .first<{ public_key: string }>();
  return row?.public_key ?? null;
}

/**
 * Verify the Ed25519 signature of a signed protocol message against the
 * signer's registered public key. Registration happens through anchoring
 * (CLAIM_ANCHOR seq 1) or, for a Referee in a split-Keeper topology, from
 * its REFEREE_PROFILE (G2, RFC-0001 §6.19). A signer with no registered key
 * is rejected as UNKNOWN_TERMINAL per TRANSPORT-BINDING §3.
 */
async function requireSignature(
  env: Env,
  msg: ProtocolMessage,
  signerId: string,
): Promise<HandlerOutcome | null> {
  const publicKey = await getPublicKey(env, signerId);
  if (!publicKey) {
    return reject(401, 'UNKNOWN_TERMINAL', `no public key registered for ${signerId}`);
  }
  const { signature, ...body } = msg;
  const ok = await verifyEd25519(publicKey, jcs(body), String(signature));
  if (!ok) return reject(401, 'SIGNATURE_INVALID');
  return null;
}

async function loadEscrow(env: Env, incidentId: string): Promise<EscrowRow | null> {
  return env.DB.prepare('SELECT * FROM escrows WHERE incident_id = ?')
    .bind(incidentId)
    .first<EscrowRow>();
}

async function createEscrow(env: Env, incidentId: string): Promise<void> {
  await env.DB.prepare(
    "INSERT OR IGNORE INTO escrows (incident_id, updated_at) VALUES (?, datetime('now'))",
  )
    .bind(incidentId)
    .run();
}

/** Sum of the current round's un-refunded deposits — what this Keeper holds (STD-029). */
async function escrowBalance(env: Env, incidentId: string, round: number): Promise<number> {
  const row = await env.DB.prepare(
    'SELECT COALESCE(SUM(amount), 0) AS total FROM deposits WHERE incident_id = ? AND round = ? AND refunded = 0',
  )
    .bind(incidentId, round)
    .first<{ total: number }>();
  return row?.total ?? 0;
}

async function verdictCerts(env: Env, incidentId: string): Promise<string[]> {
  const rows = await env.DB.prepare(
    'SELECT cert_id, MIN(issued_at) AS first_seen FROM verdict_records WHERE incident_id = ? GROUP BY cert_id ORDER BY first_seen ASC',
  )
    .bind(incidentId)
    .all<{ cert_id: string }>();
  return rows.results.map((r) => r.cert_id);
}

/**
 * STD-028: (re)arm the assessment-deadline timer to now + declared window.
 * Called on FEE_DEPOSIT, INCIDENT_OPEN and APPEAL_ACCEPTED; re-arming on each
 * event yields "the later of". Never re-arms a terminal escrow.
 */
async function armAssessmentTimer(env: Env, incidentId: string): Promise<void> {
  await env.DB.prepare(
    `UPDATE escrows
       SET deadline_at = datetime('now', '+' || CAST(COALESCE(deadline_hours, ?) * 3600 AS INTEGER) || ' seconds'),
           updated_at = datetime('now')
     WHERE incident_id = ? AND state = 'ESCROWED'`,
  )
    .bind(DEFAULT_ASSESSMENT_DEADLINE_HOURS, incidentId)
    .run();
}

// ---------------------------------------------------------------------------
// CLAIM_ANCHOR (RFC-0001 §6.1)
// ---------------------------------------------------------------------------
export async function handleClaimAnchor(env: Env, msg: ProtocolMessage): Promise<HandlerOutcome> {
  const db = env.DB;
  const terminalId = msg.terminal_id as string;
  const seq = msg.sequence_number as number;

  // Resolve the verification key. The schema already enforces that
  // sequence_number == 1 carries public_key.
  const registered = await getPublicKey(env, terminalId);
  let publicKey: string;
  let register = false;
  if (!registered) {
    if (!msg.public_key) {
      return reject(
        401,
        'UNKNOWN_TERMINAL',
        'terminal not registered: include public_key to register (required at sequence_number 1)',
      );
    }
    publicKey = msg.public_key as string;
    register = true;
  } else {
    if (msg.public_key && msg.public_key !== registered) {
      // Key rotation is out of scope; a differing key on a registered
      // terminal is a definitive protocol rejection, not a retry case.
      return reject(422, 'PROTOCOL_REJECTED', 'public_key does not match the registered key');
    }
    publicKey = registered;
  }

  const { signature, ...body } = msg;
  if (!(await verifyEd25519(publicKey, jcs(body), String(signature)))) {
    return reject(401, 'SIGNATURE_INVALID');
  }

  // Identical bytes were absorbed by the idempotency ledger before dispatch,
  // so any duplicate identity here is a conflicting message: 409.
  const dup = await db.prepare('SELECT 1 AS x FROM anchors WHERE claim_id = ?')
    .bind(msg.claim_id)
    .first();
  if (dup) return reject(409, 'SEQUENCE_CONFLICT', 'claim_id already exists');

  const maxRow = await db.prepare(
    'SELECT MAX(sequence_number) AS m FROM anchors WHERE terminal_id = ?',
  )
    .bind(terminalId)
    .first<{ m: number | null }>();
  if (maxRow?.m != null && seq <= maxRow.m) {
    return reject(
      409,
      'SEQUENCE_CONFLICT',
      `sequence_number ${seq} is not greater than the last anchored ${maxRow.m} (gaps are allowed; regressions are not)`,
    );
  }

  const stmts: D1PreparedStatement[] = [];
  if (register) {
    stmts.push(
      db.prepare('INSERT INTO public_keys (terminal_id, public_key, registered_at) VALUES (?, ?, ?)')
        .bind(terminalId, publicKey, msg.timestamp),
    );
  }
  stmts.push(
    db.prepare(
      `INSERT INTO anchors
         (claim_id, terminal_id, sequence_number, timestamp, data_hash, action_type, incident_id, cert_id, raw_json)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    ).bind(
      msg.claim_id,
      terminalId,
      seq,
      msg.timestamp,
      msg.data_hash,
      msg.action_type ?? null,
      msg.incident_id ?? null,
      msg.cert_id ?? null,
      JSON.stringify(msg),
    ),
  );
  if (msg.action_type === 'SESSION_START') {
    // norm_document_hash is optional (RFC-0001 §9.3): a terminal that cannot retrieve
    // its profile still declares, so store null rather than refusing the anchor.
    for (const np of msg.norm_profiles as Array<{
      norm_profile_id: string;
      norm_fetch_url: string;
      norm_document_hash?: string;
    }>) {
      stmts.push(
        db.prepare(
          `INSERT INTO terminal_norms (terminal_id, norm_profile_id, norm_fetch_url, norm_document_hash, declared_at)
           VALUES (?, ?, ?, ?, ?)
           ON CONFLICT (terminal_id, norm_profile_id)
           DO UPDATE SET norm_fetch_url = excluded.norm_fetch_url,
                         norm_document_hash = excluded.norm_document_hash,
                         declared_at = excluded.declared_at`,
        ).bind(terminalId, np.norm_profile_id, np.norm_fetch_url, np.norm_document_hash ?? null, msg.timestamp),
      );
    }
  }
  if (
    (msg.action_type === 'ASSESSMENT_ISSUED' || msg.action_type === 'POH_CERT_ISSUED') &&
    msg.incident_id &&
    msg.cert_id
  ) {
    stmts.push(
      db.prepare(
        "INSERT OR IGNORE INTO verdict_records (incident_id, cert_id, source) VALUES (?, ?, 'ANCHOR')",
      ).bind(msg.incident_id, msg.cert_id),
    );
  }
  await db.batch(stmts);
  return {};
}

// ---------------------------------------------------------------------------
// VERIFICATION_QUERY (RFC-0001 §6.12/§6.13)
// ---------------------------------------------------------------------------
export async function handleVerificationQuery(env: Env, msg: ProtocolMessage): Promise<HandlerOutcome> {
  const range = msg.original_timestamp_range as { start: string; end: string };
  const startMs = parseMs(range.start)!;
  const endMs = parseMs(range.end)!;
  const hashes = msg.target_hashes as string[];
  const target = msg.target_terminal_id as string;

  const placeholders = hashes.map(() => '?').join(', ');
  // Scoped to the target terminal: another terminal's anchored hash must not
  // verify as this party's evidence (RFC-0001 §6.12).
  const rows = await env.DB.prepare(
    `SELECT a.claim_id, a.terminal_id, a.timestamp, a.data_hash, pk.public_key
     FROM anchors a
     LEFT JOIN public_keys pk ON pk.terminal_id = a.terminal_id
     WHERE a.data_hash IN (${placeholders}) AND a.terminal_id = ?`,
  )
    .bind(...hashes, target)
    .all<{ claim_id: string; terminal_id: string; timestamp: string; data_hash: string; public_key: string | null }>();

  const results = hashes.map((hash) => {
    const inRange = rows.results.find((r) => {
      if (r.data_hash !== hash) return false;
      const ts = parseMs(r.timestamp);
      return ts !== null && ts >= startMs && ts <= endMs;
    });
    return {
      target_hash: hash,
      matched: !!inRange,
      matched_record: inRange
        ? {
            claim_id: inRange.claim_id,
            terminal_id: inRange.terminal_id,
            timestamp: inRange.timestamp,
            data_hash: inRange.data_hash,
            public_key: inRange.public_key,
          }
        : null,
    };
  });

  return {
    response: { type: 'VERIFICATION_RESULT', incident_id: msg.incident_id, results },
  };
}

// ---------------------------------------------------------------------------
// ANCHOR_CHAIN_QUERY (RFC-0001 §6.27/§6.28) — ledger disclosure
// ---------------------------------------------------------------------------
// Implementation-defined size cap (§6.28 truncation). `count` stays accurate;
// a requester needing more narrows the window and re-queries.
const ANCHOR_CHAIN_MAX_RETURNED = 500;

export async function handleAnchorChainQuery(env: Env, msg: ProtocolMessage): Promise<HandlerOutcome> {
  const requesterId = msg.requester_id as string;
  const target = msg.target_terminal_id as string;
  const incidentId = msg.incident_id as string;
  const range = msg.range as { start: string; end: string };

  const sigFail = await requireSignature(env, msg, requesterId);
  if (sigFail) return sigFail;

  // §6.27 authorization: anchor metadata reveals a terminal's activity
  // pattern, so the chain is readable only by the Referee bound to the
  // incident (G1 binding from the first authenticated INCIDENT_NOTICE) or by
  // the target terminal itself. In the standard flow INCIDENT_OPEN precedes
  // any chain query, so the binding always exists for a legitimate Referee.
  if (requesterId !== target) {
    const esc = await loadEscrow(env, incidentId);
    if (!esc?.referee_id || esc.referee_id !== requesterId) {
      return reject(
        422,
        'PROTOCOL_REJECTED',
        'requester is not the Referee bound to this incident (nor the target terminal itself)',
      );
    }
  }

  const startMs = parseMs(range.start)!;
  const endMs = parseMs(range.end)!;
  const rows = await env.DB.prepare(
    'SELECT raw_json, timestamp, action_type FROM anchors WHERE terminal_id = ? ORDER BY sequence_number ASC',
  )
    .bind(target)
    .all<{ raw_json: string; timestamp: string; action_type: string | null }>();

  // Timestamps are parsed in JS rather than compared as SQL strings: terminal
  // clocks emit ISO 8601 variants (ms, offsets) that do not collate reliably.
  const inWindow = rows.results.filter((r) => {
    const ts = parseMs(r.timestamp);
    return ts !== null && ts >= startMs && ts <= endMs;
  });

  // Governing SESSION_START (§6.28): the latest SESSION_START at or before
  // range.start, returned verbatim even when outside the window. Rows are in
  // ascending sequence order, so the last qualifying record wins.
  let sessionStart: unknown = null;
  for (const r of rows.results) {
    if (r.action_type !== 'SESSION_START') continue;
    const ts = parseMs(r.timestamp);
    if (ts !== null && ts <= startMs) sessionStart = JSON.parse(r.raw_json);
  }

  const count = inWindow.length;
  const truncated = count > ANCHOR_CHAIN_MAX_RETURNED;
  const anchors = (truncated ? inWindow.slice(0, ANCHOR_CHAIN_MAX_RETURNED) : inWindow).map(
    (r) => JSON.parse(r.raw_json) as unknown,
  );

  return {
    response: {
      type: 'ANCHOR_CHAIN_RESULT',
      incident_id: incidentId,
      target_terminal_id: target,
      count,
      truncated,
      anchors,
      session_start: sessionStart,
      timestamp: nowIso(),
    },
  };
}

// ---------------------------------------------------------------------------
// REFEREE_STATS_QUERY (RFC-0001 §6.20/§6.21)
// ---------------------------------------------------------------------------
export async function handleRefereeStatsQuery(env: Env, msg: ProtocolMessage): Promise<HandlerOutcome> {
  const db = env.DB;
  const terminalId = msg.terminal_id as string;
  const now = nowIso();

  const stats = await db.prepare(
    `SELECT
       COUNT(CASE WHEN action_type = 'ASSESSMENT_ISSUED' THEN 1 END) AS assessment_count,
       COUNT(CASE WHEN action_type = 'POH_CERT_ISSUED'   THEN 1 END) AS poh_cert_count,
       COUNT(CASE WHEN action_type = 'APPEAL_RECEIVED'   THEN 1 END) AS appeal_count,
       COUNT(CASE WHEN action_type = 'APPEAL_ACCEPTED'   THEN 1 END) AS appeal_accepted_count,
       COUNT(CASE WHEN action_type = 'APPEAL_REJECTED'   THEN 1 END) AS appeal_rejected_count,
       COUNT(CASE WHEN action_type = 'NAMED_AS_ACTOR'    THEN 1 END) AS named_as_actor_count,
       COUNT(DISTINCT CASE WHEN action_type = 'APPEAL_RECEIVED' THEN incident_id END) AS appealed_assessment_count,
       MIN(timestamp) AS active_since,
       MAX(timestamp) AS last_active,
       MIN(sequence_number) AS seq_min,
       MAX(sequence_number) AS seq_max,
       COUNT(*) AS total_count
     FROM anchors WHERE terminal_id = ?`,
  )
    .bind(terminalId)
    .first<{
      assessment_count: number; poh_cert_count: number; appeal_count: number;
      appeal_accepted_count: number; appeal_rejected_count: number;
      named_as_actor_count: number; appealed_assessment_count: number;
      active_since: string | null; last_active: string | null;
      seq_min: number | null; seq_max: number | null; total_count: number;
    }>();

  if (!stats || stats.total_count === 0) {
    return { response: { type: 'REFEREE_STATS_RESULT', terminal_id: terminalId, found: false, timestamp: now } };
  }

  // unreceived_count (RFC-0001 §6.21/§6.24, STD-032): FIXED-model incidents
  // with an ASSESSMENT_ISSUED / POH_CERT_ISSUED anchor and no FEE_RECEIPT
  // (copy) from this Referee. FREE-model referees are exempt; an unpublished
  // profile is counted conservatively (unknown is not exempt).
  let unreceived = 0;
  const profileRow = await db.prepare('SELECT profile_json FROM referee_profiles WHERE referee_id = ?')
    .bind(terminalId)
    .first<{ profile_json: string }>();
  const feeModel = profileRow
    ? (JSON.parse(profileRow.profile_json) as { fee?: { model?: string } }).fee?.model
    : undefined;
  if (feeModel !== 'FREE') {
    const u = await db.prepare(
      `SELECT COUNT(DISTINCT a.incident_id) AS u
       FROM anchors a
       WHERE a.terminal_id = ?1
         AND a.action_type IN ('ASSESSMENT_ISSUED', 'POH_CERT_ISSUED')
         AND a.incident_id IS NOT NULL
         AND NOT EXISTS (
           SELECT 1 FROM fee_receipts r
           WHERE r.incident_id = a.incident_id AND r.referee_id = ?1
         )`,
    )
      .bind(terminalId)
      .first<{ u: number }>();
    unreceived = u?.u ?? 0;
  }

  const vc = stats.assessment_count;
  const rate = (n: number) => (vc > 0 ? Math.round((n / vc) * 1000) / 1000 : 0);
  // Anchor continuity: with per-terminal unique sequence numbers, "no gaps"
  // is exactly (max - min + 1 == count).
  const continuity =
    stats.seq_min !== null && stats.seq_max !== null
      ? stats.seq_max - stats.seq_min + 1 === stats.total_count
      : true;

  return {
    response: {
      type: 'REFEREE_STATS_RESULT',
      terminal_id: terminalId,
      found: true,
      assessment_count: vc,
      poh_cert_count: stats.poh_cert_count,
      appeal_count: stats.appeal_count,
      appeal_rate: rate(stats.appeal_count),
      appealed_assessment_count: stats.appealed_assessment_count,
      appealed_assessment_rate: rate(stats.appealed_assessment_count),
      appeal_accepted_count: stats.appeal_accepted_count,
      appeal_rejected_count: stats.appeal_rejected_count,
      named_as_actor_count: stats.named_as_actor_count,
      named_as_actor_rate: rate(stats.named_as_actor_count),
      anchor_continuity: continuity,
      active_since: stats.active_since,
      last_active: stats.last_active,
      unreceived_count: unreceived,
      timestamp: now,
    },
  };
}

// ---------------------------------------------------------------------------
// FEE_DEPOSIT (RFC-0001 §6.4, STD-020/029)
// ---------------------------------------------------------------------------
export async function handleFeeDeposit(env: Env, msg: ProtocolMessage): Promise<HandlerOutcome> {
  const depositorId = msg.depositor_id as string;

  // STD-033: without this, any sender — not just depositor_id — could credit
  // or corrupt another party's escrow record at this public endpoint.
  const sigFail = await requireSignature(env, msg, depositorId);
  if (sigFail) return sigFail;

  const db = env.DB;
  const incidentId = msg.incident_id as string;
  const amount = msg.amount as number;
  const currency = msg.currency as string;

  const priorVerdicts = await verdictCerts(env, incidentId);
  const isReassessment = priorVerdicts.length > 0;

  let esc = await loadEscrow(env, incidentId);
  if (!esc) {
    await db.prepare(
      `INSERT INTO escrows (incident_id, currency, reassessment_initiator_id) VALUES (?, ?, ?)`,
    )
      .bind(incidentId, currency, isReassessment ? depositorId : null)
      .run();
    esc = (await loadEscrow(env, incidentId))!;
  } else if (esc.state !== 'ESCROWED') {
    // A deposit against a terminal escrow opens the next round (STD-020
    // re-assessment). The first depositor of the new round is the initiating
    // party and bears the full cost; transfer to the opponent is prohibited.
    await db.prepare(
      `UPDATE escrows SET
         round = round + 1, state = 'ESCROWED', currency = ?, appeal_pending = 0,
         deadline_at = NULL, release_at = NULL, referee_id = NULL,
         released_amount = NULL, released_via = NULL, release_json = NULL,
         release_delivered = 0, receipt_received = 0, cancellation_fee = NULL,
         reassessment_initiator_id = ?, updated_at = datetime('now')
       WHERE incident_id = ?`,
    )
      .bind(currency, isReassessment ? depositorId : null, incidentId)
      .run();
    esc = (await loadEscrow(env, incidentId))!;
  } else {
    const hasDeposits = (await escrowBalance(env, incidentId, esc.round)) > 0;
    if (!hasDeposits) {
      // Entry pre-created by INCIDENT_NOTICE: the round's first deposit fixes
      // the currency and, after a prior verdict, the initiating party (STD-020).
      await db.prepare(
        `UPDATE escrows SET currency = ?,
           reassessment_initiator_id = COALESCE(reassessment_initiator_id, ?),
           updated_at = datetime('now')
         WHERE incident_id = ?`,
      )
        .bind(currency, isReassessment ? depositorId : null, incidentId)
        .run();
    }
  }

  // Top-up semantics: a further (non-identical) deposit by the same party in
  // the same round adds to its amount.
  await db.prepare(
    `INSERT INTO deposits (incident_id, round, depositor_id, amount, currency)
     VALUES (?, ?, ?, ?, ?)
     ON CONFLICT (incident_id, round, depositor_id)
     DO UPDATE SET amount = amount + excluded.amount`,
  )
    .bind(incidentId, esc.round, depositorId, amount, currency)
    .run();

  await armAssessmentTimer(env, incidentId);
  return {};
}

// ---------------------------------------------------------------------------
// FEE_STATUS_QUERY (RFC-0001 §6.5/§6.6, STD-026)
// ---------------------------------------------------------------------------
export async function handleFeeStatusQuery(env: Env, msg: ProtocolMessage): Promise<HandlerOutcome> {
  const db = env.DB;
  const incidentId = msg.incident_id as string;
  const terminalId = msg.terminal_id as string;
  const now = nowIso();

  const esc = await loadEscrow(env, incidentId);
  const dep = esc
    ? await db.prepare(
        'SELECT created_at FROM deposits WHERE incident_id = ? AND round = ? AND depositor_id = ? AND refunded = 0',
      )
        .bind(incidentId, esc.round, terminalId)
        .first<{ created_at: string }>()
    : null;

  const priorVerdicts = await verdictCerts(env, incidentId);

  const result: Record<string, unknown> = {
    type: 'FEE_STATUS_RESULT',
    incident_id: incidentId,
    terminal_id: terminalId,
    deposited: !!dep,
    timestamp: now,
    prior_assessment_count: priorVerdicts.length,
  };
  if (dep) result.deposit_timestamp = dep.created_at.replace(' ', 'T') + 'Z';
  if (priorVerdicts.length > 0) result.prior_verdict_refs = priorVerdicts;

  const priorIncidentIds = msg.prior_incident_ids as string[] | undefined;
  if (priorIncidentIds && priorIncidentIds.length > 0) {
    const verified: Array<Record<string, unknown>> = [];
    for (const pid of priorIncidentIds) {
      const anchor = await db.prepare(
        "SELECT cert_id FROM anchors WHERE incident_id = ? AND action_type = 'ASSESSMENT_ISSUED' ORDER BY id ASC LIMIT 1",
      )
        .bind(pid)
        .first<{ cert_id: string | null }>();
      const entry: Record<string, unknown> = { incident_id: pid, verified: !!anchor };
      if (anchor?.cert_id) entry.cert_id = anchor.cert_id;
      verified.push(entry);
    }
    result.verified_prior_incidents = verified;
  }

  return { response: result };
}

// ---------------------------------------------------------------------------
// INCIDENT_NOTICE (RFC-0001 §6.3, §4.4; STD-027/028)
// NOTE (spec limitation, tracked for a future revision): INCIDENT_NOTICE
// carries neither a sender terminal_id nor a signature, so escrow lifecycle
// transitions triggered here are unauthenticated at the protocol level.
// ---------------------------------------------------------------------------
export async function handleIncidentNotice(env: Env, msg: ProtocolMessage): Promise<HandlerOutcome> {
  const db = env.DB;
  const incidentId = msg.incident_id as string;
  const eventType = msg.event_type as string;
  const refereeId = msg.referee_id as string;

  // G1: authenticate before acting. The notice drives escrow transitions (release,
  // appeal hold, withdrawal settlement), so an unverifiable or wrong-Referee notice
  // must not touch the escrow. (1) verify the signature against the referee's
  // registered key — a party Keeper holds it from the REFEREE_PROFILE published at
  // incident open (G2); (2) bind the incident to the referee_id of the first accepted
  // notice and reject any later notice from a different Referee.
  const sigFail = await requireSignature(env, msg, refereeId);
  if (sigFail) return sigFail;

  const existing = await loadEscrow(env, incidentId);
  const bound = existing?.referee_id ?? null;
  if (bound && bound !== refereeId) {
    return reject(422, 'PROTOCOL_REJECTED', 'incident is bound to a different Referee');
  }
  await createEscrow(env, incidentId);
  if (!bound) {
    await db
      .prepare("UPDATE escrows SET referee_id = ?, updated_at = datetime('now') WHERE incident_id = ? AND referee_id IS NULL")
      .bind(refereeId, incidentId)
      .run();
  }

  switch (eventType) {
    case 'INCIDENT_OPEN': {
      // STD-027/028: record the declared window; start (or refresh to the
      // later of) the assessment-deadline timer. The entry is created if the
      // notice precedes FEE_DEPOSIT so the declared window is not lost.
      await createEscrow(env, incidentId);
      if (typeof msg.assessment_deadline_hours === 'number') {
        await db.prepare(
          "UPDATE escrows SET deadline_hours = ?, updated_at = datetime('now') WHERE incident_id = ?",
        )
          .bind(msg.assessment_deadline_hours, incidentId)
          .run();
      }
      await armAssessmentTimer(env, incidentId);
      break;
    }
    case 'ASSESSMENT_COMPLETE': {
      await createEscrow(env, incidentId);
      if (msg.cert_id) {
        await db.prepare(
          "INSERT OR IGNORE INTO verdict_records (incident_id, cert_id, source) VALUES (?, ?, 'NOTICE')",
        )
          .bind(incidentId, msg.cert_id)
          .run();
      }
      // STD-028: assessment finished in time — stop the deadline timer and
      // start the FEE_RELEASE timer at the appeal deadline.
      const releaseAt = msg.additional_appeal_limit_datetime
        ? new Date(msg.additional_appeal_limit_datetime as string).toISOString()
        : null;
      await db.prepare(
        `UPDATE escrows SET deadline_at = NULL, release_at = ?, updated_at = datetime('now')
         WHERE incident_id = ? AND state = 'ESCROWED'`,
      )
        .bind(releaseAt, incidentId)
        .run();
      break;
    }
    case 'APPEAL_RECEIVED': {
      // Suspend the FEE_RELEASE timer.
      await db.prepare(
        "UPDATE escrows SET appeal_pending = 1, updated_at = datetime('now') WHERE incident_id = ?",
      )
        .bind(incidentId)
        .run();
      break;
    }
    case 'APPEAL_ACCEPTED': {
      // Reset: await a new ASSESSMENT_COMPLETE; restart the assessment timer.
      await db.prepare(
        `UPDATE escrows SET appeal_pending = 0, release_at = NULL, updated_at = datetime('now')
         WHERE incident_id = ?`,
      )
        .bind(incidentId)
        .run();
      await armAssessmentTimer(env, incidentId);
      break;
    }
    case 'APPEAL_REJECTED': {
      // Resume the FEE_RELEASE timer.
      await db.prepare(
        "UPDATE escrows SET appeal_pending = 0, updated_at = datetime('now') WHERE incident_id = ?",
      )
        .bind(incidentId)
        .run();
      break;
    }
    case 'ASSESSMENT_WITHDRAWN': {
      // RFC-0001 §6.17: deduct the Referee's declared cancellation_fee from
      // the balance this Keeper holds; the remainder returns to the
      // depositor. Actual fund movement is outside the reference scope; the
      // settlement is recorded on the escrow row.
      const esc = await loadEscrow(env, incidentId);
      if (esc && esc.state === 'ESCROWED') {
        const balance = await escrowBalance(env, incidentId, esc.round);
        const fee = Math.min((msg.cancellation_fee as number | undefined) ?? 0, balance);
        await db.prepare(
          `UPDATE escrows SET state = 'WITHDRAWN', cancellation_fee = ?,
             deadline_at = NULL, release_at = NULL, updated_at = datetime('now')
           WHERE incident_id = ? AND state = 'ESCROWED'`,
        )
          .bind(fee, incidentId)
          .run();
      }
      break;
    }
  }
  return {};
}

// ---------------------------------------------------------------------------
// REFEREE_PROFILE (RFC-0001 §6.19) / REFEREE_DISCOVERY_REQUEST (§6.18)
// ---------------------------------------------------------------------------
export async function handleRefereeProfile(env: Env, msg: ProtocolMessage): Promise<HandlerOutcome> {
  await env.DB.batch([
    env.DB.prepare(
      `INSERT INTO referee_profiles (referee_id, profile_json, updated_at)
       VALUES (?, ?, datetime('now'))
       ON CONFLICT (referee_id) DO UPDATE SET profile_json = excluded.profile_json, updated_at = excluded.updated_at`,
    ).bind(msg.referee_id, JSON.stringify(msg)),
    // G2 (RFC-0001 §4.4/§6.19): register referee_id -> public_key so this Keeper can
    // verify the Referee's signed FEE_CLAIM/FEE_RECEIPT. In a split-Keeper topology the
    // Referee never anchors here, so the profile is the only key channel. TOFU:
    // INSERT OR IGNORE keeps the first key seen (e.g. an anchor-registered one) authoritative.
    env.DB.prepare(
      'INSERT OR IGNORE INTO public_keys (terminal_id, public_key, registered_at) VALUES (?, ?, ?)',
    ).bind(msg.referee_id, msg.public_key, msg.profile_timestamp ?? new Date().toISOString()),
  ]);
  return {};
}

export async function handleDiscoveryRequest(env: Env, msg: ProtocolMessage): Promise<HandlerOutcome> {
  const filters = (msg.filters ?? {}) as Record<string, unknown>;
  const limit = (msg.limit as number | undefined) ?? 10;

  const rows = await env.DB.prepare('SELECT referee_id, profile_json FROM referee_profiles').all<{
    referee_id: string;
    profile_json: string;
  }>();

  const matched: Array<Record<string, unknown>> = [];
  for (const row of rows.results) {
    const p = JSON.parse(row.profile_json) as Record<string, any>;
    if (filters.availability_status && p.availability_status !== filters.availability_status) continue;
    if (filters.network && p.network !== filters.network) continue;
    if (filters.fee_model && p.fee?.model !== filters.fee_model) continue;
    if (filters.referee_id && p.referee_id !== filters.referee_id) continue;
    if (filters.jurisdiction_code) {
      const jc = filters.jurisdiction_code;
      if (!(p.conduct_norms as Array<any>).some((cn) => cn.jurisdiction_code === jc)) continue;
    }
    if (filters.domain) {
      const d = filters.domain;
      if (!(p.conduct_norms as Array<any>).some((cn) => cn.domain === d)) continue;
    }
    if (typeof filters.max_fee === 'number' && p.fee?.model !== 'FREE') {
      if (filters.fee_currency && p.fee?.currency !== filters.fee_currency) continue;
      if (p.fee?.amount > (filters.max_fee as number)) continue;
    }
    if (typeof filters.min_assessments === 'number') {
      const c = await env.DB.prepare(
        "SELECT COUNT(*) AS c FROM anchors WHERE terminal_id = ? AND action_type = 'ASSESSMENT_ISSUED'",
      )
        .bind(row.referee_id)
        .first<{ c: number }>();
      if ((c?.c ?? 0) < (filters.min_assessments as number)) continue;
    }
    matched.push(p);
    if (matched.length >= limit) break;
  }

  return {
    response: {
      type: 'REFEREE_DISCOVERY_RESULT',
      profiles: matched,
      count: matched.length,
      timestamp: nowIso(),
    },
  };
}

// ---------------------------------------------------------------------------
// FEE_CLAIM (RFC-0001 §6.22/§6.23) — pull-based payment
// ---------------------------------------------------------------------------
export async function handleFeeClaim(env: Env, msg: ProtocolMessage): Promise<HandlerOutcome> {
  const sigFail = await requireSignature(env, msg, msg.referee_id as string);
  if (sigFail) return sigFail;

  const db = env.DB;
  const incidentId = msg.incident_id as string;
  const now = nowIso();
  const esc = await loadEscrow(env, incidentId);

  // G1: only the Referee this incident is bound to (by the first INCIDENT_NOTICE)
  // may claim its escrow. Signature proves identity, not authorization: a different
  // registered terminal (even a party to the incident, who knows the cert_id) must
  // not be able to release or block the escrow. Authorization failure is a transport
  // rejection, not a FEE_CLAIM_RESULT. A claim can only reach ACCEPTED after an
  // ASSESSMENT_COMPLETE notice, which binds the Referee, so this never false-rejects.
  if (esc?.referee_id && esc.referee_id !== (msg.referee_id as string)) {
    return reject(422, 'PROTOCOL_REJECTED', 'incident is bound to a different Referee');
  }

  const rejected = (reason: string, extra?: Record<string, unknown>): HandlerOutcome => ({
    response: {
      type: 'FEE_CLAIM_RESULT',
      incident_id: incidentId,
      referee_id: msg.referee_id,
      cert_id: msg.cert_id,
      status: 'REJECTED',
      currency: esc?.currency ?? msg.currency,
      rejection_reason: reason,
      ...extra,
      timestamp: now,
    },
  });

  // STD-028: an EXPIRED escrow has been refunded — a late result confers no
  // payment right through the escrow.
  if (esc?.state === 'EXPIRED') return rejected('ESCROW_EXPIRED');
  if (esc && (esc.state === 'RELEASED' || esc.state === 'SETTLED' || esc.state === 'WITHDRAWN')) {
    return rejected('ALREADY_RELEASED');
  }
  const certs = await verdictCerts(env, incidentId);
  if (!certs.includes(msg.cert_id as string)) return rejected('CERT_NOT_FOUND');
  if (esc?.appeal_pending) return rejected('APPEAL_PENDING');
  const releaseMs = parseMs(esc?.release_at);
  if (!esc || releaseMs === null) return rejected('TIMER_NOT_ELAPSED');
  if (Date.now() < releaseMs) {
    return rejected('TIMER_NOT_ELAPSED', { timer_expires_at: esc.release_at });
  }

  const balance = await escrowBalance(env, incidentId, esc.round);
  // Atomic transition: whoever moves ESCROWED -> RELEASED first wins; a
  // concurrent push FEE_RELEASE makes this claim ALREADY_RELEASED (§6.22).
  const upd = await db.prepare(
    `UPDATE escrows SET state = 'RELEASED', released_amount = ?, released_via = 'FEE_CLAIM_RESULT',
       referee_id = ?, release_delivered = 1, updated_at = datetime('now')
     WHERE incident_id = ? AND state = 'ESCROWED'`,
  )
    .bind(balance, msg.referee_id, incidentId)
    .run();
  if (!upd.meta.changes) return rejected('ALREADY_RELEASED');

  return {
    response: {
      type: 'FEE_CLAIM_RESULT',
      incident_id: incidentId,
      referee_id: msg.referee_id,
      cert_id: msg.cert_id,
      status: 'ACCEPTED',
      released_amount: balance,
      currency: esc.currency ?? msg.currency,
      timestamp: now,
    },
  };
}

// ---------------------------------------------------------------------------
// FEE_RECEIPT (RFC-0001 §6.24, STD-032)
// ---------------------------------------------------------------------------
export async function handleFeeReceipt(env: Env, msg: ProtocolMessage): Promise<HandlerOutcome> {
  const sigFail = await requireSignature(env, msg, msg.referee_id as string);
  if (sigFail) return sigFail;

  const db = env.DB;
  const incidentId = msg.incident_id as string;

  // G1: same authorization boundary as FEE_CLAIM — only the bound Referee may settle
  // this incident's escrow. A bound escrow lives at a party Keeper; the own-Keeper
  // copy lands where no notice bound a Referee (referee_id NULL), so it passes.
  const esc = await loadEscrow(env, incidentId);
  if (esc?.referee_id && esc.referee_id !== (msg.referee_id as string)) {
    return reject(422, 'PROTOCOL_REJECTED', 'incident is bound to a different Referee');
  }

  // One receipt per incident per referee (§1.2.2 exactly-once); duplicates
  // and the own-Keeper copy share the same ledger row semantics.
  await db.prepare(
    `INSERT OR IGNORE INTO fee_receipts
       (incident_id, referee_id, cert_id, received_amount, currency, triggered_by, external_tx_ref, raw_json)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
  )
    .bind(
      incidentId,
      msg.referee_id,
      msg.cert_id,
      msg.received_amount,
      msg.currency,
      msg.triggered_by,
      msg.external_tx_ref ?? null,
      JSON.stringify(msg),
    )
    .run();

  // A releasing Keeper settles its escrow; a Keeper holding no released
  // escrow (the Referee's own Keeper receiving the copy) records only.
  await db.prepare(
    `UPDATE escrows SET state = 'SETTLED', receipt_received = 1, updated_at = datetime('now')
     WHERE incident_id = ? AND state = 'RELEASED'`,
  )
    .bind(incidentId)
    .run();

  return {};
}

// ---------------------------------------------------------------------------
// FEE_REFUND_CLAIM (RFC-0001 §6.25/§6.26, STD-028)
// ---------------------------------------------------------------------------
export async function handleFeeRefundClaim(env: Env, msg: ProtocolMessage): Promise<HandlerOutcome> {
  const sigFail = await requireSignature(env, msg, msg.depositor_id as string);
  if (sigFail) return sigFail;

  const db = env.DB;
  const incidentId = msg.incident_id as string;
  const depositorId = msg.depositor_id as string;
  const now = nowIso();
  const esc = await loadEscrow(env, incidentId);
  const dep = esc
    ? await db.prepare(
        'SELECT id, amount, currency, refunded FROM deposits WHERE incident_id = ? AND round = ? AND depositor_id = ?',
      )
        .bind(incidentId, esc.round, depositorId)
        .first<{ id: number; amount: number; currency: string; refunded: number }>()
    : null;

  const respond = (
    status: 'ACCEPTED' | 'REJECTED',
    fields: Record<string, unknown>,
  ): HandlerOutcome => ({
    response: {
      type: 'FEE_REFUND_RESULT',
      incident_id: incidentId,
      depositor_id: depositorId,
      status,
      currency: esc?.currency ?? dep?.currency ?? 'USD',
      ...fields,
      timestamp: now,
    },
  });
  const rejected = (reason: string, extra?: Record<string, unknown>) =>
    respond('REJECTED', { rejection_reason: reason, ...extra });

  if (!esc || !dep) return rejected('DEPOSIT_NOT_FOUND');
  if (esc.state === 'RELEASED' || esc.state === 'SETTLED') return rejected('ALREADY_RELEASED');
  // Returned via withdrawal settlement counts as already refunded (§6.26).
  if (esc.state === 'WITHDRAWN') return rejected('ALREADY_REFUNDED');
  if (dep.refunded) return rejected('ALREADY_REFUNDED');
  // ASSESSMENT_COMPLETE received for the current round: the escrow is in the
  // release flow, not the refund flow.
  if (esc.state === 'ESCROWED' && esc.release_at !== null) return rejected('ASSESSMENT_COMPLETED');
  const deadlineMs = parseMs(esc.deadline_at);
  if (deadlineMs === null) return rejected('DEADLINE_NOT_ELAPSED');
  if (Date.now() < deadlineMs) {
    return rejected('DEADLINE_NOT_ELAPSED', { deadline_expires_at: esc.deadline_at });
  }

  const upd = await db.prepare(
    "UPDATE deposits SET refunded = 1, refunded_at = datetime('now') WHERE id = ? AND refunded = 0",
  )
    .bind(dep.id)
    .run();
  if (!upd.meta.changes) return rejected('ALREADY_REFUNDED');
  // Full amount, no cancellation fee; the escrow record transitions to
  // EXPIRED (a further refund claim by the other depositor stays valid —
  // per-deposit refunded flags govern).
  await db.prepare(
    `UPDATE escrows SET state = 'EXPIRED', deadline_at = NULL, updated_at = datetime('now')
     WHERE incident_id = ? AND state IN ('ESCROWED', 'EXPIRED')`,
  )
    .bind(incidentId)
    .run();

  return respond('ACCEPTED', { refunded_amount: dep.amount });
}

// ---------------------------------------------------------------------------
// Party mailbox (RFC-0001 §4.4, §6 Message Delivery)
// ---------------------------------------------------------------------------
export async function handleMailboxDeliver(
  env: Env,
  msg: ProtocolMessage,
  msgHash: string,
): Promise<HandlerOutcome> {
  await env.DB.prepare(
    'INSERT INTO mailbox (message_type, incident_id, message_hash, message_json) VALUES (?, ?, ?, ?)',
  )
    .bind(msg.type, (msg.incident_id as string | undefined) ?? null, msgHash, JSON.stringify(msg))
    .run();
  return {};
}

/**
 * MAILBOX_QUERY — implementation-defined mailbox access (TRANSPORT-BINDING §5
 * places this outside the protocol). A party signs the query; held messages
 * are returned embedded in the receipt. This reference Keeper serves one
 * party, so all held messages are that party's; multi-tenant scoping is an
 * operator concern.
 */
export async function handleMailboxQuery(env: Env, msg: ProtocolMessage): Promise<HandlerOutcome> {
  if (typeof msg.terminal_id !== 'string' || typeof msg.signature !== 'string') {
    return reject(400, 'MALFORMED', 'MAILBOX_QUERY requires terminal_id and signature');
  }
  const sigFail = await requireSignature(env, msg, msg.terminal_id);
  if (sigFail) return sigFail;

  const conditions: string[] = [];
  const binds: unknown[] = [];
  if (typeof msg.incident_id === 'string') {
    conditions.push('incident_id = ?');
    binds.push(msg.incident_id);
  }
  if (typeof msg.since === 'string') {
    // The mailbox stores received_at in SQLite datetime form ("YYYY-MM-DD
    // HH:MM:SS") while clients echo back the ISO form this handler returns
    // ("...T...Z"); normalize the cursor to the stored form or the ' ' vs 'T'
    // byte difference silently empties every since-narrowed read.
    conditions.push('received_at >= ?');
    binds.push(msg.since.replace('T', ' ').replace(/(\.\d+)?Z?$/, ''));
  }
  const where = conditions.length ? `WHERE ${conditions.join(' AND ')}` : '';
  const rows = await env.DB.prepare(
    `SELECT message_json, received_at FROM mailbox ${where} ORDER BY id ASC LIMIT 200`,
  )
    .bind(...binds)
    .all<{ message_json: string; received_at: string }>();

  return {
    response: {
      type: 'MAILBOX_RESULT',
      messages: rows.results.map((r) => ({
        received_at: r.received_at.replace(' ', 'T') + 'Z',
        message: JSON.parse(r.message_json),
      })),
      count: rows.results.length,
      timestamp: nowIso(),
    },
  };
}
