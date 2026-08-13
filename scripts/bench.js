/**
 * Tunes PBKDF2_ITERATIONS for this machine.
 *
 * The target is the slowest count that still keeps an unlock under ~1s, since
 * unlock cost is the only thing standing between a copied storage file and an
 * offline password grind. Run on the machine the extension will live on.
 *
 *   npm run bench
 */
import { PBKDF2_ITERATIONS, generateDataKey, unwrapWithPassword, wrapWithPassword } from '../src/crypto.js';

const BUDGET_MS = 1000;
const COUNTS = [100_000, 300_000, 600_000, 1_000_000, 2_000_000];
const REPS = 3;

async function timeUnwrap(iterations) {
  const dataKey = generateDataKey();
  const wrap = await wrapWithPassword('benchmark-password', dataKey, { iterations });
  const samples = [];
  for (let i = 0; i < REPS; i++) {
    const start = performance.now();
    await unwrapWithPassword('benchmark-password', wrap);
    samples.push(performance.now() - start);
  }
  return samples.reduce((a, b) => a + b) / samples.length;
}

console.log(`node ${process.version} — median of ${REPS} unwraps per count\n`);
console.log('  iterations     unlock cost');
console.log('  ----------     -----------');

let recommended = COUNTS[0];
for (const iterations of COUNTS) {
  const ms = await timeUnwrap(iterations);
  const flag = ms <= BUDGET_MS ? 'ok' : 'over budget';
  if (ms <= BUDGET_MS) recommended = iterations;
  console.log(`  ${String(iterations).padStart(10)}     ${ms.toFixed(0).padStart(5)} ms   ${flag}`);
}

console.log(`\n  budget:      ${BUDGET_MS} ms`);
console.log(`  configured:  ${PBKDF2_ITERATIONS.toLocaleString()}`);
console.log(`  recommended: ${recommended.toLocaleString()}`);

if (recommended < PBKDF2_ITERATIONS) {
  console.log('\n  Configured value exceeds the budget on this machine — consider lowering it.');
} else if (recommended > PBKDF2_ITERATIONS) {
  console.log('\n  Headroom available — consider raising PBKDF2_ITERATIONS.');
}
