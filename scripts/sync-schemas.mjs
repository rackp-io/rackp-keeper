// sync-schemas.mjs — copy the canonical protocol schemas into ./schemas/.
// The keeper validates every inbound message against the published JSON
// Schemas (rackp repo, schemas/). This repo carries a checked-in copy so it
// builds standalone; run this script after any schema change in the rackp
// repo to refresh the copy. Test vectors are copied too (used by test-unit).
import { cpSync, mkdirSync, readdirSync, copyFileSync, existsSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const src = join(here, '..', '..', 'rackp', 'schemas');
const dst = join(here, '..', 'schemas');

if (!existsSync(src)) {
  console.error(`source not found: ${src} (expects the rackp repo checked out as a sibling)`);
  process.exit(1);
}

mkdirSync(dst, { recursive: true });
let n = 0;
for (const f of readdirSync(src)) {
  if (f.endsWith('.json')) {
    copyFileSync(join(src, f), join(dst, f));
    n++;
  }
}
cpSync(join(src, 'test-vectors'), join(dst, 'test-vectors'), { recursive: true });
console.log(`synced ${n} schemas + test-vectors from ${src}`);
