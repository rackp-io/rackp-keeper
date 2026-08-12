-- 0002 (0.2.0-alpha): record the Norm Profile document hash declared at SESSION_START.
--
-- RFC-0001 Section 9.3 adds an optional norm_document_hash to
-- CLAIM_ANCHOR.norm_profiles, so that a document replaced between declaration and
-- assessment is visible rather than silently changing an outcome. Nullable because
-- the field is optional: a terminal that could not retrieve its profile still
-- declares, and refusing the anchor would make a Norm publisher's availability a
-- precondition for anchoring at all.
--
-- Apply to a live database with:
--   wrangler d1 execute rackp-keeper --remote \
--     --file ./migrations/0002_terminal_norms_document_hash.sql
--
-- Do NOT apply schema.sql to a live database: it drops every table. Schema changes
-- after the initial release are differential, like this one. schema.sql carries the
-- same column so a fresh database matches.

ALTER TABLE terminal_norms ADD COLUMN norm_document_hash TEXT;
