-- rackp-keeper D1 schema v2
-- v2 is a breaking rebuild for the single-endpoint transport binding:
-- applying this file DROPS all v1 tables and their data (TESTNET data only;
-- production reset requires explicit operator approval).

DROP TABLE IF EXISTS anchors;
DROP TABLE IF EXISTS public_keys;
DROP TABLE IF EXISTS deposits;
DROP TABLE IF EXISTS verdict_records;
DROP TABLE IF EXISTS escrows;
DROP TABLE IF EXISTS terminal_norms;
DROP TABLE IF EXISTS delivery_acks;
DROP TABLE IF EXISTS mailbox;
DROP TABLE IF EXISTS referee_profiles;
DROP TABLE IF EXISTS fee_receipts;

-- Terminal public keys, registered from the first CLAIM_ANCHOR carrying
-- public_key (schema requires it at sequence_number == 1). RFC-0001 §4.4.
CREATE TABLE public_keys (
  terminal_id   TEXT PRIMARY KEY,
  public_key    TEXT NOT NULL,
  registered_at TEXT NOT NULL
);

-- CLAIM_ANCHOR store. UNIQUE(terminal_id, sequence_number) backs the
-- SEQUENCE_CONFLICT rejection (TRANSPORT-BINDING §3); gaps are allowed and
-- only lower provenance_score at assessment time.
CREATE TABLE anchors (
  id              INTEGER PRIMARY KEY AUTOINCREMENT,
  claim_id        TEXT NOT NULL UNIQUE,
  terminal_id     TEXT NOT NULL,
  sequence_number INTEGER NOT NULL,
  timestamp       TEXT NOT NULL,
  data_hash       TEXT NOT NULL,
  action_type     TEXT,
  incident_id     TEXT,
  cert_id         TEXT,
  raw_json        TEXT NOT NULL,
  created_at      TEXT NOT NULL DEFAULT (datetime('now')),
  UNIQUE (terminal_id, sequence_number)
);
CREATE INDEX idx_anchors_terminal  ON anchors(terminal_id);
CREATE INDEX idx_anchors_hash      ON anchors(data_hash);
CREATE INDEX idx_anchors_action    ON anchors(action_type);
CREATE INDEX idx_anchors_incident  ON anchors(incident_id);

-- Norm declarations from CLAIM_ANCHOR(SESSION_START).norm_profiles.
-- Redeclaration upserts (declared_at refreshed).
CREATE TABLE terminal_norms (
  terminal_id     TEXT NOT NULL,
  norm_profile_id TEXT NOT NULL,
  norm_fetch_url  TEXT NOT NULL,
  declared_at     TEXT NOT NULL,
  PRIMARY KEY (terminal_id, norm_profile_id)
);

-- Escrow state machine, one row per incident holding the CURRENT round
-- (STD-020 re-assessments bump `round`; superseded rounds keep their audit
-- trail in deposits/verdict_records/fee_receipts).
-- state: ESCROWED | RELEASED | SETTLED | WITHDRAWN | EXPIRED
-- deadline_at: STD-028 assessment-deadline timer (NULL = stopped)
-- release_at:  FEE_RELEASE timer = additional_appeal_limit_datetime (NULL = not started)
CREATE TABLE escrows (
  incident_id               TEXT PRIMARY KEY,
  round                     INTEGER NOT NULL DEFAULT 1,
  state                     TEXT NOT NULL DEFAULT 'ESCROWED',
  currency                  TEXT,
  appeal_pending            INTEGER NOT NULL DEFAULT 0,
  deadline_hours            REAL,
  deadline_at               TEXT,
  release_at                TEXT,
  referee_id                TEXT,
  released_amount           REAL,
  released_via              TEXT,     -- 'FEE_RELEASE' | 'FEE_CLAIM_RESULT'
  release_json              TEXT,     -- pending push FEE_RELEASE message (retried by cron)
  release_delivered         INTEGER NOT NULL DEFAULT 0,
  receipt_received          INTEGER NOT NULL DEFAULT 0,
  cancellation_fee          REAL,
  reassessment_initiator_id TEXT,     -- STD-020: first depositor after a prior verdict
  created_at                TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at                TEXT NOT NULL DEFAULT (datetime('now'))
);

-- FEE_DEPOSIT ledger. A second deposit by the same party in the same round
-- tops up the amount (idempotent redelivery of identical bytes is already
-- absorbed by delivery_acks and never reaches this table twice).
CREATE TABLE deposits (
  id           INTEGER PRIMARY KEY AUTOINCREMENT,
  incident_id  TEXT NOT NULL,
  round        INTEGER NOT NULL DEFAULT 1,
  depositor_id TEXT NOT NULL,
  amount       REAL NOT NULL,
  currency     TEXT NOT NULL,
  refunded     INTEGER NOT NULL DEFAULT 0,
  refunded_at  TEXT,
  created_at   TEXT NOT NULL DEFAULT (datetime('now')),
  UNIQUE (incident_id, round, depositor_id)
);
CREATE INDEX idx_deposits_incident ON deposits(incident_id);

-- incident_id -> cert_id, from ASSESSMENT_ISSUED / POH_CERT_ISSUED anchors
-- (Referee's own Keeper) and INCIDENT_NOTICE(ASSESSMENT_COMPLETE) (party
-- Keeper). Backs FEE_CLAIM cert validation and STD-020 re-assessment checks.
CREATE TABLE verdict_records (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  incident_id TEXT NOT NULL,
  cert_id     TEXT NOT NULL,
  source      TEXT NOT NULL,            -- 'ANCHOR' | 'NOTICE'
  issued_at   TEXT NOT NULL DEFAULT (datetime('now')),
  UNIQUE (incident_id, cert_id, source)
);
CREATE INDEX idx_verdicts_incident ON verdict_records(incident_id);

-- Idempotency ledger (TRANSPORT-BINDING §4): message_hash -> the original
-- acknowledgment (receipt or 4xx rejection), re-returned as issued.
CREATE TABLE delivery_acks (
  message_hash TEXT PRIMARY KEY,
  http_status  INTEGER NOT NULL,
  body_json    TEXT NOT NULL,
  created_at   TEXT NOT NULL DEFAULT (datetime('now'))
);

-- Party mailbox (RFC-0001 §4.4 / §6 Message Delivery): party-addressed
-- messages held for this Keeper's party. ACTOR_NOTIFICATION and
-- EVIDENCE_QUERY_REQUEST carry no recipient terminal_id — the party is
-- implied by which Keeper endpoint was posted to — so rows are keyed by
-- incident. Retrieval (MAILBOX_QUERY) is an implementation-defined
-- extension per TRANSPORT-BINDING §5.
CREATE TABLE mailbox (
  id           INTEGER PRIMARY KEY AUTOINCREMENT,
  message_type TEXT NOT NULL,
  incident_id  TEXT,
  message_hash TEXT NOT NULL,
  message_json TEXT NOT NULL,
  received_at  TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX idx_mailbox_incident ON mailbox(incident_id);

-- REFEREE_PROFILE store (discovery + fee.model lookup for unreceived_count).
CREATE TABLE referee_profiles (
  referee_id   TEXT PRIMARY KEY,
  profile_json TEXT NOT NULL,
  updated_at   TEXT NOT NULL DEFAULT (datetime('now'))
);

-- FEE_RECEIPT ledger (RFC-0001 §6.24, STD-032). One receipt per incident per
-- referee closes the unreceived_count obligation; duplicates are ignored.
CREATE TABLE fee_receipts (
  id              INTEGER PRIMARY KEY AUTOINCREMENT,
  incident_id     TEXT NOT NULL,
  referee_id      TEXT NOT NULL,
  cert_id         TEXT NOT NULL,
  received_amount REAL NOT NULL,
  currency        TEXT NOT NULL,
  triggered_by    TEXT NOT NULL,
  external_tx_ref TEXT,
  raw_json        TEXT NOT NULL,
  created_at      TEXT NOT NULL DEFAULT (datetime('now')),
  UNIQUE (incident_id, referee_id)
);
CREATE INDEX idx_receipts_referee ON fee_receipts(referee_id);
