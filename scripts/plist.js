/**
 * Write the macOS managed-preferences plist: the force-install entry and the
 * parent escrow bundle, which are the two things policy delivers.
 *
 * Usage:
 *   npm run plist -- --escrow escrow.json [--out dist/com.google.Chrome.plist]
 *                    [--update-url https://…/update.xml]
 *
 * The escrow bundle is the JSON shown in the extension's settings page under
 * the escrow key. It carries **no plaintext secret** — its private half is
 * sealed under the master password — which is why it is safe to put in a file
 * every profile on the machine can read (architecture.md §8).
 *
 * Installing the result is a separate, deliberate step, and a privileged one;
 * this script only writes a file. See INSTALL.md.
 */

import { readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { join, dirname, relative } from 'node:path';
import { fileURLToPath } from 'node:url';

import { extensionIdForKey } from './lib/crx.js';
import { ROOT, DIST, readConfig, readSigningKey } from './lib/release.js';

// --- plist serialisation -----------------------------------------------------

const ESCAPES = { '&': '&amp;', '<': '&lt;', '>': '&gt;' };
const escape = (text) => String(text).replace(/[&<>]/g, (c) => ESCAPES[c]);

/**
 * Serialise a value as an XML plist fragment.
 *
 * Only the four types a Chrome policy file can hold. Anything else throws
 * rather than being coerced: a policy that silently dropped a key would look
 * installed and deliver nothing, which is precisely the failure mode
 * `managed-schema.json` already exists to prevent.
 */
function plistValue(value, indent = '\t') {
  if (typeof value === 'string') return `${indent}<string>${escape(value)}</string>`;
  if (typeof value === 'boolean') return `${indent}<${value}/>`;
  if (Number.isInteger(value)) return `${indent}<integer>${value}</integer>`;

  if (Array.isArray(value)) {
    if (value.length === 0) return `${indent}<array/>`;
    const items = value.map((item) => plistValue(item, `${indent}\t`)).join('\n');
    return `${indent}<array>\n${items}\n${indent}</array>`;
  }

  // Plain objects only. A Date, a Map or a class instance has no plist form,
  // and `Object.entries` would quietly render most of them as an empty dict —
  // a policy key that looks present and delivers nothing.
  if (value && typeof value === 'object' && [Object.prototype, null].includes(Object.getPrototypeOf(value))) {
    const entries = Object.entries(value);
    if (entries.length === 0) return `${indent}<dict/>`;
    const body = entries
      .map(
        ([key, item]) =>
          `${indent}\t<key>${escape(key)}</key>\n${plistValue(item, `${indent}\t`)}`,
      )
      .join('\n');
    return `${indent}<dict>\n${body}\n${indent}</dict>`;
  }

  throw new Error(`Cannot express ${JSON.stringify(value)} in a plist`);
}

export function buildPlist(policies) {
  return `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
${plistValue(policies, '')}
</plist>
`;
}

// --- the policy itself -------------------------------------------------------

/**
 * Check the escrow bundle before it is written into a policy file.
 *
 * `storage.js` shape-checks it again on the way in, because storage is
 * untrusted input (architecture.md §6) — but a truncated paste caught here is a
 * one-line error, while the same paste caught there is silently *no escrow* on
 * every profile at once. Worth checking twice.
 */
export function checkEscrowBundle(bundle) {
  const problems = [];
  const has = (key, predicate) => {
    if (!predicate(bundle?.[key])) problems.push(key);
  };
  const isString = (v) => typeof v === 'string' && v.length > 0;

  has('v', Number.isInteger);
  has('keyId', isString);
  has('pub', isString);
  has('salt', isString);
  has('iterations', (v) => Number.isInteger(v) && v > 0);
  has('privWrapped', (v) => isString(v?.iv) && isString(v?.ct));

  if (problems.length > 0) {
    throw new Error(
      `That does not look like an escrow key: missing or malformed ${problems.join(', ')}.\n` +
        "Copy the whole JSON from the settings page's escrow key field.",
    );
  }
  return bundle;
}

/**
 * Assemble the Chrome policy dictionary.
 *
 * `ExtensionInstallForcelist` is the load-bearing one: a force-installed
 * extension cannot be disabled or removed from chrome://extensions, which is
 * the single property this whole phase exists to obtain (architecture.md §9).
 * It applies to every Chrome profile under the macOS user, and dormancy (§7)
 * is what makes that acceptable for the profiles that never asked for it.
 */
export function buildPolicies({ extensionId, updateUrl, escrowBundle }) {
  const policies = {};

  if (updateUrl) {
    policies.ExtensionInstallForcelist = [`${extensionId};${updateUrl}`];
  }

  if (escrowBundle) {
    // The `3rdparty` key is how a policy file reaches an individual extension's
    // managed storage. Chrome delivers nothing here that manifest.json's
    // `storage.managed_schema` has not declared.
    policies['3rdparty'] = {
      extensions: {
        [extensionId]: { escrowBundle },
      },
    };
  }

  return policies;
}

// --- CLI ---------------------------------------------------------------------

function parseArgs(argv) {
  const args = {};
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (!arg.startsWith('--')) throw new Error(`Unexpected argument: ${arg}`);
    const [flag, inline] = arg.slice(2).split('=');
    args[flag] = inline ?? argv[++i];
    if (args[flag] === undefined) throw new Error(`--${flag} needs a value`);
  }
  return args;
}

function main() {
  const args = parseArgs(process.argv.slice(2));
  const config = readConfig();
  const extensionId = extensionIdForKey(readSigningKey(config));

  const base = config.updateBaseUrl?.replace(/\/+$/, '');
  const updateUrl = args['update-url'] ?? (base ? `${base}/update.xml` : null);

  const escrowBundle = args.escrow
    ? checkEscrowBundle(JSON.parse(readFileSync(join(ROOT, args.escrow), 'utf8')))
    : null;

  const out = args.out ? join(ROOT, args.out) : join(DIST, 'com.google.Chrome.plist');
  mkdirSync(dirname(out), { recursive: true });
  writeFileSync(out, buildPlist(buildPolicies({ extensionId, updateUrl, escrowBundle })));

  const notes = [
    `Extension id: ${extensionId}`,
    `Wrote ${relative(ROOT, out)}`,
  ];
  if (!updateUrl) {
    notes.push(
      'No update URL, so no ExtensionInstallForcelist entry was written — without',
      'one the extension can still be disabled. Set updateBaseUrl in',
      'release.config.json, or pass --update-url.',
    );
  }
  if (!escrowBundle) {
    notes.push(
      'No --escrow, so this policy delivers no parent escrow key. Profiles will',
      'have no parent-unlock path unless one is installed locally per profile.',
    );
  }
  process.stdout.write(`${notes.join('\n')}\n`);
}

// Importable for tests; only the direct `npm run plist` invocation writes files.
if (process.argv[1] === fileURLToPath(import.meta.url)) {
  try {
    main();
  } catch (error) {
    process.stderr.write(`${error.message}\n`);
    process.exit(1);
  }
}
