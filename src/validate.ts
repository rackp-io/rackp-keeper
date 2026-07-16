/**
 * Inbound message validation against the canonical protocol JSON Schemas
 * (schemas/, synced from the rackp repo by scripts/sync-schemas.mjs).
 * Using the published schemas directly — rather than a hand-written mirror —
 * makes spec drift a sync-script run instead of a code change.
 *
 * @cfworker/json-schema is used because it interprets schemas at runtime:
 * ajv-style code generation (new Function) is not available in Workers.
 */
import { Validator } from '@cfworker/json-schema';
import type { Schema } from '@cfworker/json-schema';

import common from '../schemas/common.json';
import claimAnchor from '../schemas/claim_anchor.json';
import verificationQuery from '../schemas/verification_query.json';
import anchorChainQuery from '../schemas/anchor_chain_query.json';
import refereeStatsQuery from '../schemas/referee_stats_query.json';
import feeDeposit from '../schemas/fee_deposit.json';
import feeStatusQuery from '../schemas/fee_status_query.json';
import incidentNotice from '../schemas/incident_notice.json';
import refereeProfile from '../schemas/referee_profile.json';
import refereeDiscoveryRequest from '../schemas/referee_discovery_request.json';
import feeClaim from '../schemas/fee_claim.json';
import feeReceipt from '../schemas/fee_receipt.json';
import feeRefundClaim from '../schemas/fee_refund_claim.json';
import actorNotification from '../schemas/actor_notification.json';
import evidenceQueryRequest from '../schemas/evidence_query_request.json';
import contributionResult from '../schemas/contribution_result.json';
import pohCertificate from '../schemas/poh_certificate.json';

// type -> schema for every protocol message this Keeper accepts.
const INBOUND_SCHEMAS: Record<string, unknown> = {
  CLAIM_ANCHOR: claimAnchor,
  VERIFICATION_QUERY: verificationQuery,
  ANCHOR_CHAIN_QUERY: anchorChainQuery,
  REFEREE_STATS_QUERY: refereeStatsQuery,
  FEE_DEPOSIT: feeDeposit,
  FEE_STATUS_QUERY: feeStatusQuery,
  INCIDENT_NOTICE: incidentNotice,
  REFEREE_PROFILE: refereeProfile,
  REFEREE_DISCOVERY_REQUEST: refereeDiscoveryRequest,
  FEE_CLAIM: feeClaim,
  FEE_RECEIPT: feeReceipt,
  FEE_REFUND_CLAIM: feeRefundClaim,
  // Party-addressed messages held in the mailbox (RFC-0001 §4.4).
  ACTOR_NOTIFICATION: actorNotification,
  EVIDENCE_QUERY_REQUEST: evidenceQueryRequest,
  CONTRIBUTION_RESULT: contributionResult,
  POH_CERTIFICATE: pohCertificate,
};

const validators = new Map<string, Validator>();

function validatorFor(type: string): Validator | null {
  const schema = INBOUND_SCHEMAS[type];
  if (!schema) return null;
  let v = validators.get(type);
  if (!v) {
    v = new Validator(schema as Schema, '2020-12', false);
    v.addSchema(common as Schema);
    validators.set(type, v);
  }
  return v;
}

export function isKnownType(type: string): boolean {
  return type in INBOUND_SCHEMAS;
}

/** null = valid; otherwise a human-readable detail for DELIVERY_REJECTION(SCHEMA_VIOLATION). */
export function validateMessage(type: string, message: unknown): string | null {
  const v = validatorFor(type);
  if (!v) return null; // no schema — caller decides (unknown types are rejected upstream)
  const result = v.validate(message);
  if (result.valid) return null;
  const first = result.errors[0];
  return first ? `${first.instanceLocation}: ${first.error}` : 'schema validation failed';
}
