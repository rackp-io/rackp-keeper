// Re-runs the cross-implementation check recorded in this directory: the APS
// conformance suite's RFC 8785 vectors, against the canonicalizer this worker
// deploys. Fixtures are fetched at the commit pinned in the receipt and their
// SHA-256 checked before use, so the run cannot silently drift to a later
// revision of someone else's repository.
//
//   node cross-impl/verify.mjs
//
// Exit code 0 on full agreement, 1 on any mismatch or fixture hash change.
import { readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { transformSync } from 'esbuild';

const receipt = JSON.parse(readFileSync(new URL('./aps-jcs-receipt.json', import.meta.url), 'utf8'));
const { jcs } = await import(
  'data:text/javascript;base64,' +
  Buffer.from(
    transformSync(readFileSync('./src/crypto.ts', 'utf8'), { loader: 'ts', format: 'esm' }).code,
  ).toString('base64')
);

const sha256 = (b) => createHash('sha256').update(b).digest('hex');
const raw = (repo, commit, path) =>
  `${repo.replace('github.com', 'raw.githubusercontent.com')}/${commit}/${path}`;

async function fetchPinned(path, commit, expected) {
  const res = await fetch(raw(receipt.fixture_repo, commit, path));
  if (!res.ok) throw new Error(`${path}: HTTP ${res.status}`);
  const body = Buffer.from(await res.arrayBuffer());
  const got = sha256(body);
  if (got !== expected) throw new Error(`${path}: fixture sha256 ${got}, receipt pins ${expected}`);
  return JSON.parse(body.toString('utf8'));
}

let failed = 0;
const fx = await fetchPinned(receipt.fixture, receipt.fixture_commit, receipt.fixture_sha256);
console.log(`${receipt.fixture} @ ${receipt.fixture_commit.slice(0, 12)}`);
for (const v of fx.vectors) {
  const out = jcs(v.input);
  const bytes = Buffer.from(out, 'utf8');
  const ok =
    out === v.canonical &&
    bytes.toString('hex') === v.canonical_bytes_hex &&
    sha256(bytes) === v.canonical_sha256;
  if (!ok) failed++;
  console.log(`  ${ok ? 'ok  ' : 'FAIL'} ${v.name}`);
}

// The diff fixture is a case study, not a vector set: its post-fix section
// publishes a canonical form we can reproduce, which is the part worth checking.
const m = /commit ([0-9a-f]{40})/.exec(receipt.note);
const h = /sha256 ([0-9a-f]{64})/.exec(receipt.note);
if (m && h) {
  const d = await fetchPinned('fixtures/canonical-bytes/canonical-bytes-diff-v032.json', m[1], h[1]);
  const out = jcs(d.components);
  const checks = [
    ['canonical_bytes_utf8', out === d.post_fix.canonical_bytes_utf8],
    ['canonical_bytes_hex', Buffer.from(out, 'utf8').toString('hex') === d.post_fix.canonical_bytes_hex],
    ['chain_hash', `sha256:${sha256(Buffer.from(out, 'utf8'))}` === d.divergence.post_fix_hash],
  ];
  console.log('canonical-bytes-diff-v032.json (post_fix, not counted)');
  for (const [n, ok] of checks) {
    if (!ok) failed++;
    console.log(`  ${ok ? 'ok  ' : 'FAIL'} ${n}`);
  }
}

console.log(failed === 0 ? '\nall checks agree' : `\n${failed} mismatch(es)`);
process.exit(failed === 0 ? 0 : 1);
