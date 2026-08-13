/**
 * Generate the signing key, once.
 *
 * The key is the extension's identity: Chrome derives the extension id from its
 * public half, and the id is what the force-install policy names. Regenerating
 * it after the policy is in place produces a *different* extension — a new,
 * empty profile store, and the old one stranded with its encrypted snapshot
 * unreachable. So this refuses to overwrite an existing key, and the key is
 * gitignored and belongs in a password manager alongside the master password.
 *
 * Usage: npm run keygen
 */

import { generateKeyPairSync } from 'node:crypto';
import { writeFileSync, readFileSync, existsSync, mkdirSync } from 'node:fs';
import { dirname, relative } from 'node:path';

import { extensionIdForKey } from './lib/crx.js';
import { ROOT, readConfig, signingKeyPath } from './lib/release.js';

const config = readConfig();
const path = signingKeyPath(config);

if (existsSync(path)) {
  process.stderr.write(
    `A signing key already exists at ${config.signingKey}.\n` +
      `Extension id: ${extensionIdForKey(readFileSync(path, 'utf8'))}\n\n` +
      'Refusing to overwrite it: a new key means a new extension id, which means\n' +
      'the force-install policy points at nothing and any locked profile keeps an\n' +
      'encrypted snapshot no installed extension can open.\n',
  );
  process.exit(1);
}

// 2048-bit RSA: what Chrome's own packer produces, and what the CRX3 header
// format assumes. This key signs the package; it has nothing to do with the
// RSA-3072 key bundles in src/crypto.js that protect tab sessions.
const { privateKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
const pem = privateKey.export({ type: 'pkcs8', format: 'pem' });

mkdirSync(dirname(path), { recursive: true });
writeFileSync(path, pem, { mode: 0o600 });

process.stdout.write(
  `Wrote ${relative(ROOT, path)} (keep this; back it up; never commit it)\n` +
    `Extension id: ${extensionIdForKey(pem)}\n`,
);
