# cross-impl

Results of running another project's conformance vectors against the
canonicalizer this Keeper deploys.

## What a receipt here claims

That `jcs()` in `src/crypto.ts` produced byte-identical output to the vectors
named in the receipt, at the fixture revision the receipt pins. Each receipt
records the fixture repository, the commit, and the SHA-256 of the fixture file
as it was read, so the claim is about a fixed input and cannot quietly become
false when either side moves on.

## What it does not claim

Nothing about the other project beyond those bytes. A receipt is not an
adoption, an endorsement, or a statement that the two systems interoperate at
any layer above the canonical form. RFC 8785 is a shared dependency, and
agreement on it is the narrowest useful fact two implementations can establish.

It is also not a claim about RACK Protocol as a specification. A specification
defines the byte contract; only an implementation can pass or fail a vector.
The normative vectors an implementation of this protocol must reproduce live in
[`schemas/test-vectors/`](../schemas/test-vectors) in the `rackp` repository —
those go outward. What is collected here comes inward.

## Re-running

```
npm install
node cross-impl/verify.mjs
```

The script fetches each fixture at its pinned commit, checks the SHA-256
against the receipt before using it, and exits non-zero on any mismatch — of a
vector or of the fixture itself.

## Receipts

| File | Fixture source | Result |
|---|---|---|
| `aps-jcs-receipt.json` | Agent Passport System conformance suite, RFC 8785 vectors | 8/8 |
