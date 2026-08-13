import { test, describe, before } from 'node:test';
import assert from 'node:assert/strict';

import {
  DecryptError,
  changeBundlePassword,
  createKeyBundle,
  decryptSnapshot,
  encryptSnapshot,
  fromB64,
  generateDataKey,
  toB64,
  unwrapWithBundle,
  verifyBundlePassword,
  wrapToBundle,
} from '../src/crypto.js';

// Real iteration counts make the suite unbearably slow; correctness is
// independent of the count. The tuned production value is asserted separately
// in bench.js.
const FAST = { iterations: 1000 };

// RSA-3072 keygen costs about a second, so the bundles are made once and shared.
// Tests that need a *distinct* keypair say so explicitly.
let profile; // stands in for a profile's own bundle, password 'kid-pw'
let escrow; // stands in for the parent escrow bundle, password 'master-pw'

before(async () => {
  [profile, escrow] = await Promise.all([
    createKeyBundle('kid-pw', FAST),
    createKeyBundle('master-pw', FAST),
  ]);
});

const SNAPSHOT = {
  windows: [
    {
      left: 0,
      top: 25,
      width: 1440,
      height: 900,
      state: 'normal',
      tabs: [
        { url: 'https://example.com/', pinned: true, active: false },
        { url: 'https://example.org/x?y=1#z', pinned: false, active: true },
      ],
    },
  ],
};

describe('base64 helpers', () => {
  test('round-trips arbitrary bytes including 0x00 and 0xff', () => {
    const bytes = new Uint8Array(256).map((_, i) => i);
    assert.deepEqual(fromB64(toB64(bytes)), bytes);
  });

  test('handles buffers larger than the call-argument limit', () => {
    // A snapshot with many tabs encrypts to well over the ~64k spread limit that
    // String.fromCharCode(...bytes) would hit. Filled in 64k chunks because
    // getRandomValues itself refuses more than 65,536 bytes per call.
    const big = new Uint8Array(200_000);
    for (let off = 0; off < big.length; off += 65_536) {
      crypto.getRandomValues(big.subarray(off, Math.min(off + 65_536, big.length)));
    }
    assert.deepEqual(fromB64(toB64(big)), big);
  });
});

describe('key bundles', () => {
  test('round-trips a data key wrapped with only the public half', async () => {
    const dataKey = generateDataKey();
    // Exactly what a lock does: no password in sight, public key only.
    const wrap = await wrapToBundle({ v: profile.v, keyId: profile.keyId, pub: profile.pub }, dataKey);
    assert.deepEqual(await unwrapWithBundle('kid-pw', profile, wrap), dataKey);
  });

  test('carries no plaintext private key', async () => {
    // A PKCS#8 RSA private key base64-encodes with this prefix; the sealed form
    // must not, and the bundle must not open without the password.
    assert.doesNotMatch(profile.privWrapped.ct, /^MII/);
    assert.equal(await verifyBundlePassword('wrong-pw', profile), false);
    assert.equal(await verifyBundlePassword('kid-pw', profile), true);
  });

  test('rejects a wrong password with DecryptError, not a crash', async () => {
    const wrap = await wrapToBundle(profile, generateDataKey());
    await assert.rejects(() => unwrapWithBundle('wrong', profile, wrap), DecryptError);
  });

  test('rejects a wrap made for a different keypair', async () => {
    const wrap = await wrapToBundle(escrow, generateDataKey());
    await assert.rejects(() => unwrapWithBundle('kid-pw', profile, wrap), DecryptError);
  });

  test('rejects tampered ciphertext', async () => {
    const wrap = await wrapToBundle(profile, generateDataKey());
    const ct = fromB64(wrap.ct);
    ct[0] ^= 0xff;
    await assert.rejects(
      () => unwrapWithBundle('kid-pw', profile, { ...wrap, ct: toB64(ct) }),
      DecryptError,
    );
  });

  test('rejects an unknown record version', async () => {
    const wrap = await wrapToBundle(profile, generateDataKey());
    await assert.rejects(
      () => unwrapWithBundle('kid-pw', profile, { ...wrap, v: 99 }),
      DecryptError,
    );
  });

  test('uses a fresh salt and IV per seal', async () => {
    const resealed = await changeBundlePassword('kid-pw', 'kid-pw', profile, FAST);
    assert.notEqual(resealed.salt, profile.salt);
    assert.notEqual(resealed.privWrapped.iv, profile.privWrapped.iv);
  });

  test('survives a JSON round-trip through storage', async () => {
    const dataKey = generateDataKey();
    const wrap = JSON.parse(JSON.stringify(await wrapToBundle(profile, dataKey)));
    const stored = JSON.parse(JSON.stringify(profile));
    assert.deepEqual(await unwrapWithBundle('kid-pw', stored, wrap), dataKey);
  });

  test('handles unicode and long passwords', async () => {
    const password = '🔐 correct-horse-battery-staple ünïcodé '.repeat(10);
    const bundle = await changeBundlePassword('kid-pw', password, profile, FAST);
    const dataKey = generateDataKey();
    const wrap = await wrapToBundle(bundle, dataKey);
    assert.deepEqual(await unwrapWithBundle(password, bundle, wrap), dataKey);
  });
});

describe('snapshot encryption', () => {
  test('round-trips a realistic snapshot', async () => {
    const dataKey = generateDataKey();
    const blob = await encryptSnapshot(dataKey, SNAPSHOT);
    assert.deepEqual(await decryptSnapshot(dataKey, blob), SNAPSHOT);
  });

  test('leaks no plaintext URL into the stored blob', async () => {
    const blob = await encryptSnapshot(generateDataKey(), SNAPSHOT);
    assert.doesNotMatch(JSON.stringify(blob), /example\.(com|org)/);
  });

  test('a different data key cannot decrypt', async () => {
    const blob = await encryptSnapshot(generateDataKey(), SNAPSHOT);
    await assert.rejects(() => decryptSnapshot(generateDataKey(), blob), DecryptError);
  });

  test('uses a fresh IV per encryption', async () => {
    const dataKey = generateDataKey();
    const a = await encryptSnapshot(dataKey, SNAPSHOT);
    const b = await encryptSnapshot(dataKey, SNAPSHOT);
    assert.notEqual(a.iv, b.iv);
    assert.notEqual(a.ct, b.ct);
  });
});

describe('password change', () => {
  test('keeps the keypair, so existing wraps and the snapshot are untouched', async () => {
    const dataKey = generateDataKey();
    const blob = await encryptSnapshot(dataKey, SNAPSHOT);
    const before = JSON.stringify(blob);
    const wrap = await wrapToBundle(profile, dataKey);

    const changed = await changeBundlePassword('kid-pw', 'new-pw', profile, FAST);

    assert.equal(changed.keyId, profile.keyId, 'keypair must not change');
    assert.equal(changed.pub, profile.pub);
    assert.equal(JSON.stringify(blob), before, 'snapshot must not be re-encrypted');

    const recovered = await unwrapWithBundle('new-pw', changed, wrap);
    assert.deepEqual(await decryptSnapshot(recovered, blob), SNAPSHOT);
    await assert.rejects(() => unwrapWithBundle('kid-pw', changed, wrap), DecryptError);
  });

  test('rejects a wrong current password', async () => {
    await assert.rejects(
      () => changeBundlePassword('wrong', 'new', profile, FAST),
      DecryptError,
    );
  });
});

describe('parent escrow', () => {
  test('both unlock paths recover the same key independently', async () => {
    const dataKey = generateDataKey();
    const blob = await encryptSnapshot(dataKey, SNAPSHOT);

    // One lock writes both wraps, using only public keys.
    const pwWrap = await wrapToBundle(profile, dataKey);
    const masterWrap = await wrapToBundle(escrow, dataKey);

    assert.deepEqual(
      await decryptSnapshot(await unwrapWithBundle('kid-pw', profile, pwWrap), blob),
      SNAPSHOT,
    );
    assert.deepEqual(
      await decryptSnapshot(await unwrapWithBundle('master-pw', escrow, masterWrap), blob),
      SNAPSHOT,
    );
  });

  test('a master unlock does not invalidate the profile password', async () => {
    const dataKey = generateDataKey();
    const pwWrap = await wrapToBundle(profile, dataKey);
    const masterWrap = await wrapToBundle(escrow, dataKey);

    await unwrapWithBundle('master-pw', escrow, masterWrap);
    assert.deepEqual(await unwrapWithBundle('kid-pw', profile, pwWrap), dataKey);
  });

  test('rotating the master password keeps existing wraps valid', async () => {
    const dataKey = generateDataKey();
    const wrap = await wrapToBundle(escrow, dataKey);

    const rotated = await changeBundlePassword('master-pw', 'new-master', escrow, FAST);

    assert.equal(rotated.keyId, escrow.keyId);
    assert.deepEqual(await unwrapWithBundle('new-master', rotated, wrap), dataKey);
    await assert.rejects(() => unwrapWithBundle('master-pw', rotated, wrap), DecryptError);
  });
});

describe('profile isolation', () => {
  test("one profile's password cannot open another's bundle", async () => {
    const other = await createKeyBundle('other-pw', FAST);
    const wrap = await wrapToBundle(other, generateDataKey());

    await assert.rejects(() => unwrapWithBundle('kid-pw', other, wrap), DecryptError);
    await assert.rejects(() => unwrapWithBundle('other-pw', profile, wrap), DecryptError);
  });
});
