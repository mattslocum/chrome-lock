/**
 * What "the extension" means to the build, and where the release settings live.
 *
 * The file list here is deliberately explicit rather than a directory walk.
 * A walk ships whatever happens to be lying in `src/` — a scratch file, an
 * editor backup, a half-finished page — and the whole point of this project is
 * that the packed artifact is something I can read in one sitting and freeze
 * (architecture.md §10.7-8). Adding a file to the extension should be a visible
 * line in a diff. `test/packaging.test.js` fails if `src/` and this list ever
 * disagree, so the explicitness cannot silently rot.
 */

import { readFileSync, existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

// scripts/lib/release.js → scripts/lib → scripts → the repo root.
export const ROOT = dirname(dirname(dirname(fileURLToPath(import.meta.url))));

/** Everything that goes in the crx, as archive-relative paths. */
export const PACKAGED_FILES = [
  'manifest.json',
  'managed-schema.json',
  'src/crypto.js',
  'src/lock-engine.js',
  'src/lock.html',
  'src/lock.js',
  'src/messages.js',
  'src/options.html',
  'src/options.js',
  'src/popup.html',
  'src/popup.js',
  'src/service_worker.js',
  'src/settings.js',
  'src/storage.js',
  'src/ui.css',
];

export const CONFIG_PATH = join(ROOT, 'release.config.json');
export const DIST = join(ROOT, 'dist');

export function readManifest() {
  return JSON.parse(readFileSync(join(ROOT, 'manifest.json'), 'utf8'));
}

/**
 * Release settings: the signing key's location and, optionally, the base URL
 * the crx and `update.xml` will be served from.
 *
 * `updateBaseUrl` is null until whoever is releasing fills it in, and the
 * scripts stay useful without it — a force-installed extension takes its update
 * URL from the policy, so a crx alone is enough to install. See INSTALL.md.
 */
export function readConfig() {
  const config = existsSync(CONFIG_PATH)
    ? JSON.parse(readFileSync(CONFIG_PATH, 'utf8'))
    : {};
  return {
    signingKey: config.signingKey ?? 'keys/chrome-lock.pem',
    updateBaseUrl: config.updateBaseUrl ?? null,
  };
}

export function signingKeyPath(config = readConfig()) {
  return join(ROOT, config.signingKey);
}

export function readSigningKey(config = readConfig()) {
  const path = signingKeyPath(config);
  if (!existsSync(path)) {
    throw new Error(
      `No signing key at ${config.signingKey}. Run \`npm run keygen\` first.\n` +
        'The key fixes the extension id, so it must be kept and never regenerated ' +
        'for an extension already installed by policy.',
    );
  }
  return readFileSync(path, 'utf8');
}
