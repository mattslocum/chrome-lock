/**
 * The packaged artifact is the thing that actually gets installed, and it is
 * the one part of the project nobody reads before trusting: a crx is a signed
 * binary blob. So the checks here are about *what went into it* — that the
 * archive holds exactly the declared files and nothing stray, that the
 * signature verifies against the key that fixes the extension id, and that the
 * policy file names that same id.
 *
 * The invariant sweeps over the shipped source live here too, for the same
 * reason: architecture.md §10 lists rules a reader is otherwise expected to
 * check by eye, on the files that are about to be frozen and force-installed.
 */

import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, writeFileSync, readdirSync, existsSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { createVerify, createPublicKey, generateKeyPairSync, createHash } from 'node:crypto';
import { join } from 'node:path';
import { inflateRawSync } from 'node:zlib';
import { tmpdir } from 'node:os';

import { makeZip } from '../scripts/lib/zip.js';
import { makeCrx, parseCrx, extensionIdForKey, publicKeyDer, crxId } from '../scripts/lib/crx.js';
import { buildCrx, buildUpdateXml } from '../scripts/pack.js';
import { buildPlist, buildPolicies, checkEscrowBundle } from '../scripts/plist.js';
import { ROOT, PACKAGED_FILES, readManifest } from '../scripts/lib/release.js';

// One throwaway key for the whole file: generating RSA keys is the slowest
// thing here and nothing below depends on a *particular* key.
const { privateKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
const KEY = privateKey.export({ type: 'pkcs8', format: 'pem' });

/** Read a zip back with only the central directory, the way Chrome would. */
function readZip(zip) {
  const end = zip.lastIndexOf(Buffer.from([0x50, 0x4b, 0x05, 0x06]));
  assert.notEqual(end, -1, 'no end-of-central-directory record');

  const count = zip.readUInt16LE(end + 10);
  let cursor = zip.readUInt32LE(end + 16);
  const entries = [];

  for (let i = 0; i < count; i += 1) {
    assert.equal(zip.readUInt32LE(cursor), 0x02014b50, 'bad central directory entry');
    const method = zip.readUInt16LE(cursor + 10);
    const crc = zip.readUInt32LE(cursor + 16);
    const compressedSize = zip.readUInt32LE(cursor + 20);
    const uncompressedSize = zip.readUInt32LE(cursor + 24);
    const nameLength = zip.readUInt16LE(cursor + 28);
    const extraLength = zip.readUInt16LE(cursor + 30);
    const commentLength = zip.readUInt16LE(cursor + 32);
    const offset = zip.readUInt32LE(cursor + 42);
    const name = zip.subarray(cursor + 46, cursor + 46 + nameLength).toString('utf8');

    // Walk into the local header to find where the body actually starts.
    assert.equal(zip.readUInt32LE(offset), 0x04034b50, `bad local header for ${name}`);
    const localNameLength = zip.readUInt16LE(offset + 26);
    const localExtraLength = zip.readUInt16LE(offset + 28);
    const bodyStart = offset + 30 + localNameLength + localExtraLength;
    const body = zip.subarray(bodyStart, bodyStart + compressedSize);

    entries.push({
      name,
      crc,
      uncompressedSize,
      data: method === 8 ? inflateRawSync(body) : Buffer.from(body),
    });

    cursor += 46 + nameLength + extraLength + commentLength;
  }

  return entries;
}

describe('the zip inside the crx', () => {
  test('round-trips contents, including data that does not compress', () => {
    const incompressible = createHash('sha512').update('seed').digest();
    const zip = makeZip([
      { name: 'b.txt', data: Buffer.from('hello '.repeat(200)) },
      { name: 'src/a.js', data: Buffer.from('const x = 1;\n') },
      { name: 'random.bin', data: incompressible },
    ]);

    const byName = Object.fromEntries(readZip(zip).map((e) => [e.name, e]));
    assert.equal(byName['b.txt'].data.toString(), 'hello '.repeat(200));
    assert.equal(byName['src/a.js'].data.toString(), 'const x = 1;\n');
    assert.deepEqual(byName['random.bin'].data, incompressible);
    assert.equal(byName['random.bin'].uncompressedSize, incompressible.length);
  });

  test('is byte-identical across builds, so a shipped crx can be re-derived', () => {
    // Input order deliberately differs: entries are sorted, and timestamps are
    // fixed, so nothing about *when* or *how* it was built leaks into the bytes.
    const files = [
      { name: 'manifest.json', data: Buffer.from('{}') },
      { name: 'src/a.js', data: Buffer.from('a') },
    ];
    assert.deepEqual(makeZip(files), makeZip([...files].reverse()));
  });
});

/**
 * Read length-delimited protobuf fields into `{fieldNumber: [bytes, …]}`.
 *
 * Deliberately a separate implementation from the packer's writer — a shared
 * one would agree with itself about a wrong encoding, and the whole question
 * here is whether Chrome's parser will agree.
 */
function readFields(buffer) {
  const fields = {};
  let cursor = 0;
  while (cursor < buffer.length) {
    let tag = 0;
    let shift = 1;
    while (buffer[cursor] & 0x80) {
      tag += (buffer[cursor++] & 0x7f) * shift;
      shift *= 128;
    }
    tag += buffer[cursor++] * shift;

    assert.equal(tag % 8, 2, 'only length-delimited fields are expected');

    let length = 0;
    shift = 1;
    while (buffer[cursor] & 0x80) {
      length += (buffer[cursor++] & 0x7f) * shift;
      shift *= 128;
    }
    length += buffer[cursor++] * shift;

    const number = (tag - 2) / 8;
    (fields[number] ??= []).push(buffer.subarray(cursor, cursor + length));
    cursor += length;
  }
  return fields;
}

/** Everything Chrome signs, in order, for a given payload. */
function signedBytes(signedHeaderData, zip) {
  const length = Buffer.alloc(4);
  length.writeUInt32LE(signedHeaderData.length, 0);
  return Buffer.concat([
    Buffer.from('CRX3 SignedData\x00', 'latin1'),
    length,
    signedHeaderData,
    zip,
  ]);
}

describe('crx signing', () => {
  test('the signature verifies over the exact bytes Chrome will check', () => {
    const zip = makeZip([{ name: 'manifest.json', data: Buffer.from('{}') }]);
    const crx = makeCrx(zip, KEY);
    const parsed = parseCrx(crx);

    assert.deepEqual(parsed.zip, zip, 'payload must survive packing untouched');

    const header = readFields(parsed.header);
    const signedHeaderData = header[10000][0];
    const proof = readFields(header[2][0]);

    assert.deepEqual(proof[1][0], publicKeyDer(KEY), 'the packed public key must be ours');

    // The signed header carries the crx id, which is what binds a signature to
    // this extension and stops one being replayed onto another's payload.
    assert.deepEqual(readFields(signedHeaderData)[1][0], crxId(publicKeyDer(KEY)));

    const verified = createVerify('sha256')
      .update(signedBytes(signedHeaderData, parsed.zip))
      .verify(createPublicKey(KEY), proof[2][0]);

    assert.equal(verified, true, 'Chrome would reject a crx this check fails');
  });

  test('a tampered payload breaks the signature', () => {
    const zip = makeZip([{ name: 'manifest.json', data: Buffer.from('{"a":1}') }]);
    const crx = makeCrx(zip, KEY);

    const tampered = Buffer.from(crx);
    tampered[tampered.length - 40] ^= 0xff;

    const parsed = parseCrx(tampered);
    const header = readFields(parsed.header);
    const verified = createVerify('sha256')
      .update(signedBytes(header[10000][0], parsed.zip))
      .verify(createPublicKey(KEY), readFields(header[2][0])[2][0]);

    assert.equal(verified, false, 'an edited crx must not verify');
  });

  test('the extension id is 32 characters of a-p, derived from the key alone', () => {
    const id = extensionIdForKey(KEY);
    assert.match(id, /^[a-p]{32}$/);
    assert.equal(id, extensionIdForKey(KEY), 'the same key must always give the same id');

    const { privateKey: other } = generateKeyPairSync('rsa', { modulusLength: 2048 });
    assert.notEqual(
      id,
      extensionIdForKey(other.export({ type: 'pkcs8', format: 'pem' })),
      'a different key must be a different extension',
    );
  });
});

describe('what actually ships', () => {
  // Packed lazily and inside the tests: work in a `describe` body that throws
  // is reported as a suite that ran and passed, so the assertions below would
  // silently stop existing.
  let cached;
  const packed = () => (cached ??= readZip(parseCrx(buildCrx(KEY)).zip));
  const packedNames = () => packed().map((e) => e.name).sort();

  test('the archive holds exactly the declared file list', () => {
    assert.deepEqual(packedNames(), [...PACKAGED_FILES].sort());
  });

  test('every file in src/ is declared — nothing ships or is dropped by accident', () => {
    const onDisk = readdirSync(join(ROOT, 'src'))
      .map((name) => `src/${name}`)
      .sort();
    assert.deepEqual(
      onDisk,
      PACKAGED_FILES.filter((name) => name.startsWith('src/')).sort(),
      'src/ and PACKAGED_FILES disagree; update scripts/lib/release.js',
    );
  });

  test('the packed manifest is the manifest in the repo', () => {
    const packedManifest = packed().find((e) => e.name === 'manifest.json');
    assert.deepEqual(JSON.parse(packedManifest.data.toString()), readManifest());
  });

  test('the manifest names a managed schema, and the schema declares the escrow key', () => {
    // Without both halves the plist delivers nothing and parent unlock silently
    // never appears on any child profile.
    const manifest = readManifest();
    assert.equal(manifest.storage?.managed_schema, 'managed-schema.json');
    assert.ok(packedNames().includes('managed-schema.json'), 'the schema must ship in the crx');

    const schema = JSON.parse(
      packed().find((e) => e.name === 'managed-schema.json').data.toString(),
    );
    assert.ok(schema.properties?.escrowBundle, 'schema must declare escrowBundle');
  });

  test('no key material, source control, or OS clutter is packed', () => {
    for (const name of packedNames()) {
      assert.ok(!name.includes('..'), `path traversal in archive: ${name}`);
      assert.doesNotMatch(name, /(^|\/)\.|\.pem$|\.crx$|node_modules|test\//, name);
    }
  });
});

describe('invariants over the shipped source', () => {
  const sources = PACKAGED_FILES.filter((name) => /\.(js|html)$/.test(name)).map((name) => ({
    name,
    text: readFileSync(join(ROOT, name), 'utf8'),
  }));

  test('no innerHTML anywhere (§10.2)', () => {
    for (const { name, text } of sources) {
      assert.ok(!text.includes('innerHTML'), `${name} uses innerHTML`);
    }
  });

  test('no console.* in shipped code (§10.4)', () => {
    for (const { name, text } of sources) {
      assert.doesNotMatch(text, /\bconsole\.(log|warn|error|info|debug)\s*\(/, `${name} logs`);
    }
  });

  test('nothing sensitive can reach storage.sync, because nothing touches it (§10.3)', () => {
    // `chrome.storage.sync` rather than `storage.sync`: the rule is about calls,
    // and storage.js quite rightly explains in a comment why it never makes one.
    for (const { name, text } of sources) {
      assert.doesNotMatch(text, /chrome\.storage\.sync/, `${name} touches storage.sync`);
    }
  });

  test('no network calls, and no inline script for the CSP to have to refuse (§10.6)', () => {
    for (const { name, text } of sources) {
      assert.doesNotMatch(text, /\b(fetch|XMLHttpRequest|WebSocket|EventSource)\s*\(/, name);
      assert.doesNotMatch(text, /\bimportScripts\s*\(/, name);
    }
    for (const { name, text } of sources.filter((s) => s.name.endsWith('.html'))) {
      // A <script> with a body rather than a src would be inline script.
      assert.doesNotMatch(text, /<script(?![^>]*\bsrc=)/, `${name} has an inline script`);
    }
  });

  test('the CSP pins script-src and forbids connections', () => {
    const csp = readManifest().content_security_policy?.extension_pages ?? '';
    assert.match(csp, /script-src 'self'/);
    assert.match(csp, /connect-src 'none'/);
  });

  test('no host permissions and no content scripts (§3)', () => {
    const manifest = readManifest();
    assert.equal(manifest.host_permissions, undefined);
    assert.equal(manifest.content_scripts, undefined);
    assert.deepEqual(manifest.permissions, ['storage', 'tabs', 'tabGroups', 'idle', 'alarms']);
  });
});

describe('the update manifest', () => {
  test('names the extension, the version, and an absolute https crx URL', () => {
    const xml = buildUpdateXml({
      appId: extensionIdForKey(KEY),
      version: '0.6.0',
      codebase: 'https://example.invalid/chrome-lock/chrome-lock-0.6.0.crx',
    });

    assert.match(xml, new RegExp(`appid="${extensionIdForKey(KEY)}"`));
    assert.match(xml, /version="0\.6\.0"/);
    assert.match(xml, /codebase="https:\/\/[^"]+\.crx"/);
    assert.match(xml, /xmlns="http:\/\/www\.google\.com\/update2\/response"/);
  });
});

describe('the managed-preferences plist', () => {
  const escrowBundle = {
    v: 1,
    keyId: 'abc123',
    pub: 'BASE64PUB',
    privWrapped: { iv: 'BASE64IV', ct: 'BASE64CT' },
    salt: 'BASE64SALT',
    iterations: 600000,
  };

  test('force-installs this extension id and delivers the escrow bundle under 3rdparty', () => {
    const id = extensionIdForKey(KEY);
    const policies = buildPolicies({
      extensionId: id,
      updateUrl: 'https://example.invalid/chrome-lock/update.xml',
      escrowBundle,
    });

    assert.deepEqual(policies.ExtensionInstallForcelist, [
      `${id};https://example.invalid/chrome-lock/update.xml`,
    ]);
    // The nesting is the part that is easy to get wrong and impossible to
    // notice: a bundle one level out is simply never delivered.
    assert.deepEqual(policies['3rdparty'].extensions[id].escrowBundle, escrowBundle);
  });

  test('the escrow bundle survives the round trip through XML intact', () => {
    const id = extensionIdForKey(KEY);
    const xml = buildPlist(buildPolicies({ extensionId: id, updateUrl: null, escrowBundle }));

    assert.match(xml, /<!DOCTYPE plist/);
    assert.match(xml, /<key>escrowBundle<\/key>/);
    assert.match(xml, /<integer>600000<\/integer>/);
    assert.ok(xml.includes('BASE64CT'));
    assert.ok(!xml.includes('ExtensionInstallForcelist'), 'no update URL, no forcelist entry');
  });

  test('markup in a value cannot break out of the plist', () => {
    const xml = buildPlist({ Note: 'a & b <key>injected</key>' });
    assert.ok(xml.includes('a &amp; b &lt;key&gt;injected&lt;/key&gt;'));
    assert.equal(xml.match(/<key>/g).length, 1, 'only the real key element');
  });

  test('a value type Chrome policy cannot express is refused rather than dropped', () => {
    assert.throws(() => buildPlist({ When: new Date() }), /Cannot express/);
    assert.throws(() => buildPlist({ Ratio: 1.5 }), /Cannot express/);
  });

  test('a truncated escrow paste is caught here, not silently as "no escrow" everywhere', () => {
    assert.throws(() => checkEscrowBundle({ ...escrowBundle, pub: '' }), /pub/);
    assert.throws(() => checkEscrowBundle({ ...escrowBundle, privWrapped: { iv: 'x' } }), /privWrapped/);
    assert.throws(() => checkEscrowBundle(JSON.parse('{}')), /keyId/);
    assert.doesNotThrow(() => checkEscrowBundle(escrowBundle));
  });

  test('macOS parses it, and the escrow bundle survives byte for byte', (t) => {
    // plutil is the parser that will actually read this file on the target
    // machine, so where it is available its opinion beats ours. Linting alone
    // would only prove the XML is well-formed; the bundle is base64 inside
    // nested dictionaries, and it is delivering *that* intact that decides
    // whether parent unlock works on a child profile.
    if (process.platform !== 'darwin' || !existsSync('/usr/bin/plutil')) {
      t.skip('plutil is only available on macOS');
      return;
    }

    const id = extensionIdForKey(KEY);
    const path = join(tmpdir(), `chrome-lock-policy-${process.pid}.plist`);
    writeFileSync(
      path,
      buildPlist(
        buildPolicies({
          extensionId: id,
          updateUrl: 'https://example.invalid/chrome-lock/update.xml',
          escrowBundle,
        }),
      ),
    );

    assert.match(execFileSync('/usr/bin/plutil', ['-lint', path], { encoding: 'utf8' }), /OK/);

    const parsed = JSON.parse(
      execFileSync('/usr/bin/plutil', ['-convert', 'json', '-o', '-', path], { encoding: 'utf8' }),
    );
    assert.deepEqual(parsed.ExtensionInstallForcelist, [
      `${id};https://example.invalid/chrome-lock/update.xml`,
    ]);
    assert.deepEqual(parsed['3rdparty'].extensions[id].escrowBundle, escrowBundle);
  });
});
