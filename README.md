# rackp-keeper

A Cloudflare Workers + D1 implementation of the RACKP Keeper role: the
append-only anchor log, escrow custodian, and protocol mailbox that every
other terminal (Actor, Claimant, Referee) transacts through.

Implements [RFC-0001](https://github.com/rackp-io/rackp/blob/main/docs/RFC-0001.md) /
[RFC-0002](https://github.com/rackp-io/rackp/blob/main/docs/RFC-0002.md), spec version **0.2.0-alpha**.

> **Hosted instance**: the RACKP project runs a demo deployment of this
> Keeper at `keeper.rackp.io` so early adopters can verify the protocol
> end-to-end before standing up their own infrastructure. It carries no
> availability guarantee, may be reset or suspended without notice, and is
> intended to be retired (via an announced wind-down honoring outstanding
> escrow and evidence-retention obligations) once independent operators are
> established — see [Reference Implementations](https://github.com/rackp-io/rackp#-reference-implementations)
> in the main RACKP README for the operating policy.

## What it does

- **Anchoring**: accepts `CLAIM_ANCHOR` and stores it in a per-terminal hash
  chain (monotonic `sequence_number`), registering the terminal's public key
  at `sequence_number == 1` (trust-on-first-use).
- **Escrow**: runs the full lifecycle —
  `ESCROWED → RELEASED → SETTLED / WITHDRAWN / EXPIRED` — driven by
  `FEE_DEPOSIT` (signed, STD-033), `INCIDENT_NOTICE` from the bound Referee,
  `FEE_RELEASE` (pushed by this Keeper on cron) or `FEE_CLAIM` (pulled by the
  Referee), `FEE_RECEIPT`, `ASSESSMENT_WITHDRAWAL`, and the STD-028
  assessment-deadline timer (`FEE_REFUND_CLAIM`).
- **Mailbox**: holds party-addressed messages (`ACTOR_NOTIFICATION`,
  `EVIDENCE_QUERY_REQUEST`, `CONTRIBUTION_RESULT`, `POH_CERTIFICATE`) for
  non-destructive pickup via signed `MAILBOX_QUERY`.
- **Verification surface**: `VERIFICATION_QUERY` (hash lookup, public),
  `ANCHOR_CHAIN_QUERY` (authorized — Referee bound to the incident, or
  self-query only), `REFEREE_STATS_QUERY` / `REFEREE_DISCOVERY_REQUEST`
  (public Referee reputation and discovery).
- **Key publication**: `GET {endpoint}` returns a capability summary
  including `public_key` (STD-034), derived from the signing key rather than
  stored separately — the only channel a verifier has for checking this
  Keeper's `DELIVERY_RECEIPT` / `DELIVERY_REJECTION` signatures, since a
  Keeper has no profile message of its own.

All messages use the baseline single-endpoint HTTP binding
([TRANSPORT-BINDING.md](https://github.com/rackp-io/rackp/blob/main/docs/TRANSPORT-BINDING.md)):
every message is `POST {endpoint}`, acceptance is a signed `DELIVERY_RECEIPT`
(query-type responses embedded in it), rejections are 4xx
`DELIVERY_REJECTION`, and redelivery of identical bytes is idempotent.

## Architecture

| Module | Role |
|---|---|
| `index.ts` | HTTP entry point: idempotency-first dispatch, the `GET` capability summary, and the cron-driven push of `FEE_RELEASE` (`runScheduled`) |
| `handlers.ts` | Per-type handlers: escrow state machine, mailbox, anchor chain, discovery, stats |
| `crypto.ts` | JCS canonicalization (RFC 8785), Ed25519 sign/verify, public-key derivation from the signing JWK (STD-034) |
| `validate.ts` | JSON Schema validation per inbound message type, against `schemas/` (synced from the `rackp` repo) |
| `types.ts` | `Env` bindings and shared types |

## Setup

```
npm install
npm run genkey                    # prints KEEPER_SIGNING_KEY (JWK) + its public key
wrangler secret put KEEPER_SIGNING_KEY   # production; for local dev, put it in .dev.vars
npm run db:migrate:local          # or db:migrate:remote for production
npm run sync:schemas              # refresh schemas/ from the sibling ../rackp checkout
npm run dev                       # wrangler dev
npm run deploy                    # wrangler deploy
```

`schema.sql` drops and recreates every table on each migrate — safe for
TESTNET, but a production reset is a deliberate operator action.

## Tests

```
npm run typecheck
npm run test:unit          # JCS / Ed25519 known-answer checks, offline
npm run test:integration   # needs a running local instance:
                            #   npm run db:migrate:local && npx wrangler dev --port 8788
                            #   node test-integration.mjs
```

`test:integration` targets `http://127.0.0.1:8788` by default; set `BASE_URL`
to point at another instance.

## License

The source code in this repository is available under the
[RACKP Reference Implementation License](LICENSE) — free to use, modify,
and redistribute, with no patent license granted. Implementing, deploying,
or operating the RACK Protocol, whether with this software or any other
implementation, is governed by the
[RACK Protocol Source-Available License](https://github.com/rackp-io/rackp/blob/main/LICENSE).
Patent pending.
