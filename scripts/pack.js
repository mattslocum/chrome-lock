/**
 * Pack the extension into a signed crx, and write the update manifest beside it.
 *
 * Usage: npm run pack
 *
 * Output lands in dist/:
 *   chrome-lock-<version>.crx   the signed package the policy installs
 *   update.xml                  what Chrome polls for updates, when a
 *                               `updateBaseUrl` is configured
 *
 * The crx is reproducible — same sources, same key, same bytes — so a build can
 * be compared against the one that was actually shipped. That is what makes
 * "tag it, keep the CRX, never auto-update from anything I don't control"
 * (architecture.md §10.8) a thing you can check.
 */

import { readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { join, relative } from 'node:path';
import { fileURLToPath } from 'node:url';

import { makeZip } from './lib/zip.js';
import { makeCrx, extensionIdForKey } from './lib/crx.js';
import { ROOT, DIST, PACKAGED_FILES, readManifest, readConfig, readSigningKey } from './lib/release.js';

/** Build the crx bytes. Separated from the writing so tests can call it. */
export function buildCrx(privateKeyPem) {
  const files = PACKAGED_FILES.map((name) => ({
    name,
    data: readFileSync(join(ROOT, name)),
  }));
  return makeCrx(makeZip(files), privateKeyPem);
}

/**
 * The Omaha update manifest Chrome polls.
 *
 * `codebase` must be an absolute https URL, and Chrome checks the `version`
 * here against the installed one before it downloads anything — so this file,
 * not the crx, is what actually triggers an update.
 */
export function buildUpdateXml({ appId, version, codebase }) {
  return `<?xml version="1.0" encoding="UTF-8"?>
<gupdate xmlns="http://www.google.com/update2/response" protocol="2.0">
  <app appid="${appId}">
    <updatecheck codebase="${codebase}" version="${version}" />
  </app>
</gupdate>
`;
}

function main() {
  const config = readConfig();
  const manifest = readManifest();
  const privateKeyPem = readSigningKey(config);
  const appId = extensionIdForKey(privateKeyPem);

  const crx = buildCrx(privateKeyPem);
  const crxName = `chrome-lock-${manifest.version}.crx`;

  mkdirSync(DIST, { recursive: true });
  writeFileSync(join(DIST, crxName), crx);

  const lines = [
    `Extension id: ${appId}`,
    `Version:      ${manifest.version}`,
    `Files:        ${PACKAGED_FILES.length}`,
    `SHA-256:      ${createHash('sha256').update(crx).digest('hex')}`,
    `Wrote ${relative(ROOT, join(DIST, crxName))} (${crx.length} bytes)`,
  ];

  if (config.updateBaseUrl) {
    const base = config.updateBaseUrl.replace(/\/+$/, '');
    const xml = buildUpdateXml({
      appId,
      version: manifest.version,
      codebase: `${base}/${crxName}`,
    });
    writeFileSync(join(DIST, 'update.xml'), xml);
    lines.push(`Wrote ${relative(ROOT, join(DIST, 'update.xml'))} → ${base}/${crxName}`);
  } else {
    // Not an error: a force-installed extension takes its update URL from the
    // policy, so the crx alone is enough to install and to test. Auto-update is
    // the part that needs somewhere to host.
    lines.push(
      'No updateBaseUrl in release.config.json, so no update.xml was written.',
      'Set it to where dist/ will be served from to enable auto-update.',
    );
  }

  process.stdout.write(`${lines.join('\n')}\n`);
}

// Importable for tests; only the direct `npm run pack` invocation writes files.
if (process.argv[1] === fileURLToPath(import.meta.url)) {
  try {
    main();
  } catch (error) {
    // These are setup mistakes with actionable messages — a stack trace above
    // them just buries the sentence that says what to do.
    process.stderr.write(`${error.message}\n`);
    process.exit(1);
  }
}
