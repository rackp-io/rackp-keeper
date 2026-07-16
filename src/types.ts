export interface Env {
  DB: D1Database;
  /** This Keeper's terminal_id (UUID v4), receiver_id on every acknowledgment. */
  KEEPER_TERMINAL_ID: string;
  /** Ed25519 private key as a JWK JSON string (secret; scripts/genkey.mjs).
   * The public half is derived from this at request time (crypto.ts
   * publicKeyFromSigningKey) rather than stored separately — see STD-034. */
  KEEPER_SIGNING_KEY: string;
}

/** A parsed inbound protocol message. Field-level shape is enforced by the JSON Schemas. */
export type ProtocolMessage = { type: string } & Record<string, unknown>;

export interface EscrowRow {
  incident_id: string;
  round: number;
  state: 'ESCROWED' | 'RELEASED' | 'SETTLED' | 'WITHDRAWN' | 'EXPIRED';
  currency: string | null;
  appeal_pending: number;
  deadline_hours: number | null;
  deadline_at: string | null;
  release_at: string | null;
  referee_id: string | null;
  released_amount: number | null;
  released_via: string | null;
  release_json: string | null;
  release_delivered: number;
  receipt_received: number;
  cancellation_fee: number | null;
  reassessment_initiator_id: string | null;
}

/** Result of a handler: the response message to embed (query types) or nothing (one-way). */
export interface HandlerOutcome {
  /** Embedded protocol response (TRANSPORT-BINDING §2, query messages). */
  response?: Record<string, unknown>;
  /** Definitive rejection instead of a receipt. */
  rejection?: { status: 400 | 401 | 409 | 422; reason: string; detail?: string };
}
