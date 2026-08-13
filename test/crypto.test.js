import { test, describe } from 'node:test';
import assert from 'node:assert/strict';

import {
  DecryptError,
  createEscrowBundle,
  decryptSnapshot,
  encryptSnapshot,
  fromB64,
  generateDataKey,
  rotateMasterPassword,
  toB64,
  unwrapWithMaster,
  unwrapWithPassword,
  verifyMasterPassword,
  wrapForMaster,
  wrapWithPassword,
} from '../src/crypto.js';

// Real iteration counts make the suite unbearably slow; correctness is
// independent of the count. The tuned production value is asserted separately
// in bench.js.
const FAST = { iterations: 1000 };

const SNAPSHOT = {
  windows: [
    {
      left: 0,
      top: 25,
      width: 1440,
      height: 900,
      focused: true,
      tabs: [
        { url: 'https://example.com/', pinned: true, index: 0, active: false },
        { url: 'https://example.org/x?y=1#z', pinned: false, index: 1, active: true },
      ],
    },
  ],
  groups: [{ id: 7, title: 'work', color: 'blue', tabIndexes: [1] }],
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

describe('password wrapping', () => {
  test('round-trips the data key', async () => {
    const dataKey = generateDataKey();
    const wrap = await wrapWithPassword('correct horse', dataKey, FAST);
    assert.deepEqual(await unwrapWithPassword('correct horse', wrap), dataKey);
  });

  test('rejects a wrong password with DecryptError, not a crash', async () => {
    const wrap = await wrapWithPassword('right', generateDataKey(), FAST);
    await assert.rejects(() => unwrapWithPassword('wrong', wrap), DecryptError);
  });

  test('rejects tampered ciphertext (GCM authentication)', async () => {
    const wrap = await wrapWithPassword('pw', generateDataKey(), FAST);
    const ct = fromB64(wrap.ct);
    ct[0] ^= 0xff;
    await assert.rejects(
      () => unwrapWithPassword('pw', { ...wrap, ct: toB64(ct) }),
      DecryptError,
    );
  });

  test('rejects an unknown record version', async () => {
    const wrap = await wrapWithPassword('pw', generateDataKey(), FAST);
    await assert.rejects(() => unwrapWithPassword('pw', { ...wrap, v: 99 }), DecryptError);
  });

  test('uses a fresh salt and IV per wrap', async () => {
    const dataKey = generateDataKey();
    const a = await wrapWithPassword('same', dataKey, FAST);
    const b = await wrapWithPassword('same', dataKey, FAST);
    assert.notEqual(a.salt, b.salt);
    assert.notEqual(a.iv, b.iv);
    assert.notEqual(a.ct, b.ct);
  });

  test('survives a JSON round-trip through storage', async () => {
    const dataKey = generateDataKey();
    const wrap = JSON.parse(JSON.stringify(await wrapWithPassword('pw', dataKey, FAST)));
    assert.deepEqual(await unwrapWithPassword('pw', wrap), dataKey);
  });

  test('handles unicode and long passwords', async () => {
    const password = '🔐 correct-horse-battery-staple ünïcodé '.repeat(10);
    const dataKey = generateDataKey();
    const wrap = await wrapWithPassword(password, dataKey, FAST);
    assert.deepEqual(await unwrapWithPassword(password, wrap), dataKey);
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
  test('rewraps the data key without touching the ciphertext', async () => {
    const dataKey = generateDataKey();
    const blob = await encryptSnapshot(dataKey, SNAPSHOT);
    const before = JSON.stringify(blob);

    // A password change is exactly: unwrap with the old, wrap under the new.
    const oldWrap = await wrapWithPassword('old-pw', dataKey, FAST);
    const recovered = await unwrapWithPassword('old-pw', oldWrap);
    const newWrap = await wrapWithPassword('new-pw', recovered, FAST);

    assert.equal(JSON.stringify(blob), before, 'snapshot must not be re-encrypted');
    assert.deepEqual(await decryptSnapshot(await unwrapWithPassword('new-pw', newWrap), blob), SNAPSHOT);
    await assert.rejects(() => unwrapWithPassword('old-pw', newWrap), DecryptError);
  });
});

describe('parent escrow', () => {
  test('master password unwraps a data key wrapped with only the public key', async () => {
    const bundle = await createEscrowBundle('master-pw', FAST);
    const dataKey = generateDataKey();

    // What a child profile does at lock time — public half only.
    const wrap = await wrapForMaster({ keyId: bundle.keyId, pub: bundle.pub, v: bundle.v }, dataKey);

    assert.deepEqual(await unwrapWithMaster('master-pw', bundle, wrap), dataKey);
  });

  test('the distributed bundle carries no plaintext private key', async () => {
    const bundle = await createEscrowBundle('master-pw', FAST);
    // A PKCS#8 RSA private key begins with this byte sequence; the wrapped form
    // must not expose it, nor should the bundle be decryptable without the password.
    assert.doesNotMatch(bundle.privWrapped.ct, /^MII/);
    assert.equal(await verifyMasterPassword('wrong-pw', bundle), false);
    assert.equal(await verifyMasterPassword('master-pw', bundle), true);
  });

  test('rejects a wrong master password', async () => {
    const bundle = await createEscrowBundle('master-pw', FAST);
    const wrap = await wrapForMaster(bundle, generateDataKey());
    await assert.rejects(() => unwrapWithMaster('nope', bundle, wrap), DecryptError);
  });

  test('rejects a wrap made for a different keypair', async () => {
    const mine = await createEscrowBundle('pw', FAST);
    const other = await createEscrowBundle('pw', FAST);
    const wrap = await wrapForMaster(other, generateDataKey());
    await assert.rejects(() => unwrapWithMaster('pw', mine, wrap), DecryptError);
  });

  test('both unlock paths recover the same key independently', async () => {
    const bundle = await createEscrowBundle('master-pw', FAST);
    const dataKey = generateDataKey();
    const blob = await encryptSnapshot(dataKey, SNAPSHOT);

    const pwWrap = await wrapWithPassword('kid-pw', dataKey, FAST);
    const masterWrap = await wrapForMaster(bundle, dataKey);

    assert.deepEqual(await decryptSnapshot(await unwrapWithPassword('kid-pw', pwWrap), blob), SNAPSHOT);
    assert.deepEqual(await decryptSnapshot(await unwrapWithMaster('master-pw', bundle, masterWrap), blob), SNAPSHOT);
  });

  test('a master unlock does not invalidate the profile password', async () => {
    const bundle = await createEscrowBundle('master-pw', FAST);
    const dataKey = generateDataKey();
    const pwWrap = await wrapWithPassword('kid-pw', dataKey, FAST);
    const masterWrap = await wrapForMaster(bundle, dataKey);

    await unwrapWithMaster('master-pw', bundle, masterWrap);
    assert.deepEqual(await unwrapWithPassword('kid-pw', pwWrap), dataKey);
  });

  test('rotating the master password keeps existing wraps valid', async () => {
    const bundle = await createEscrowBundle('old-master', FAST);
    const dataKey = generateDataKey();
    const wrap = await wrapForMaster(bundle, dataKey);

    const rotated = await rotateMasterPassword('old-master', 'new-master', bundle, FAST);

    assert.equal(rotated.keyId, bundle.keyId, 'keypair must not change');
    assert.equal(rotated.pub, bundle.pub);
    assert.deepEqual(await unwrapWithMaster('new-master', rotated, wrap), dataKey);
    await assert.rejects(() => unwrapWithMaster('old-master', rotated, wrap), DecryptError);
  });

  test('rotation rejects a wrong current password', async () => {
    const bundle = await createEscrowBundle('right', FAST);
    await assert.rejects(
      () => rotateMasterPassword('wrong', 'new', bundle, FAST),
      DecryptError,
    );
  });
});

describe('profile isolation', () => {
  test("one profile's password cannot unwrap another's key", async () => {
    const alice = generateDataKey();
    const aliceWrap = await wrapWithPassword('alice-pw', alice, FAST);
    const bobWrap = await wrapWithPassword('bob-pw', generateDataKey(), FAST);

    await assert.rejects(() => unwrapWithPassword('bob-pw', aliceWrap), DecryptError);
    await assert.rejects(() => unwrapWithPassword('alice-pw', bobWrap), DecryptError);
  });
});
