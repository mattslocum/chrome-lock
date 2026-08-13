/**
 * Phase 5: the properties that are easy to believe and hard to notice breaking.
 *
 * Four things are pinned down here:
 *
 *   1. Authorization. Every message is gated on the sender being us, and on the
 *      type naming a handler we actually wrote. Both are one-line checks whose
 *      absence is invisible until something exploits them, which is exactly the
 *      shape of the bug two of the three reference extensions shipped.
 *   2. Tampered storage. `chrome.storage.local` can be edited by hand from
 *      devtools, so every record read back is untrusted input. None of it should
 *      be able to throw from somewhere unrelated, arm a trigger on a profile
 *      that cannot use it, or hold someone out of their own tabs.
 *   3. A worker that died while locked. It comes back to a locked profile with
 *      no in-memory state at all, and has to re-establish the lock from disk.
 *   4. Profile independence. Two configured profiles, one dormant, and no path
 *      between them.
 */

import { test, describe, before, beforeEach } from 'node:test';
import assert from 'node:assert/strict';

import { createFakeChrome } from './fake-chrome.js';

let fake = createFakeChrome();
globalThis.chrome = fake.chrome;

const engine = await import('../src/lock-engine.js');
const storage = await import('../src/storage.js');
const { HANDLERS, isTrustedSender, routeMessage } = await import('../src/messages.js');
/** Named to stay clear of the WebCrypto global that crypto.js itself uses. */
const crypto2 = await import('../src/crypto.js');

const PASSWORD = 'correct-horse-battery';
const TABS = [{ url: 'https://example.com/one' }, { url: 'https://example.org/two' }];

/** The sender Chrome supplies for one of our own pages. */
const OURS = {
  id: 'fake-extension-id',
  url: 'chrome-extension://fake-extension-id/src/popup.html',
};

/** Setting up a password is an RSA keygen plus a 600k PBKDF2, so it is done once. */
let configuredDisk;

before(async () => {
  await engine.setUpPassword(PASSWORD);
  configuredDisk = fake.dumpStorage();
});

beforeEach(() => {
  fake = createFakeChrome();
  globalThis.chrome = fake.chrome;
  fake.loadStorage(configuredDisk);
});

/**
 * Replace the locked session's plaintext with `snapshot`, keeping every step the
 * engine would take: a fresh dataKey, the snapshot encrypted under it, and the
 * key wrapped to this profile's public key. Lets a test put an arbitrary
 * *plaintext* through the real unlock path, which tampering with the ciphertext
 * cannot do — it is authenticated.
 */
async function writeSnapshot(snapshot) {
  const dataKey = crypto2.generateDataKey();
  const bundle = await storage.getProfileBundle();
  await storage.setSnapshot(await crypto2.encryptSnapshot(dataKey, snapshot));
  await storage.setPasswordSnapshotWrap(await crypto2.wrapToBundle(bundle, dataKey));
  crypto2.wipe(dataKey);
}

/** Send a message the way Chrome would, and resolve what the page would receive. */
function send(message, sender = OURS) {
  // Note for the caller: pass `null`, not `undefined`, to test a missing
  // sender — `undefined` takes the default above and tests nothing.
  return new Promise((resolve) => {
    const willRespond = routeMessage(message, sender, resolve);
    // `false` means the channel closed with nobody answering — which is what a
    // refused message looks like from the page's side.
    if (!willRespond) resolve(undefined);
  });
}

describe('message router: only our own pages are answered', () => {
  test('a message from another extension is refused, and its handler never runs', async () => {
    await engine.lock('manual');

    const response = await send({ type: 'unlock', password: PASSWORD }, {
      id: 'some-other-extension',
      url: 'chrome-extension://some-other-extension/attack.html',
    });

    assert.equal(response, undefined);
    assert.equal((await storage.getLockState()).isLocked, true, 'still locked');
  });

  test('a message with no sender at all is refused', async () => {
    assert.equal(await send({ type: 'status' }, null), undefined);
    assert.equal(await send({ type: 'status' }, {}), undefined);
    assert.equal(isTrustedSender(undefined), false);
  });

  test('our id with a url from somewhere else is refused', () => {
    // Belt and braces: Chrome sets sender.id, so this should be unreachable.
    // The url check costs nothing and makes the trusted set explicit.
    assert.equal(isTrustedSender({ id: 'fake-extension-id', url: 'https://evil.example/' }), false);
    assert.equal(isTrustedSender(OURS), true);
    // The service worker carries no url; that must not be read as untrusted.
    assert.equal(isTrustedSender({ id: 'fake-extension-id' }), true);
  });

  test('a type that is only a property of Object.prototype resolves to no handler', async () => {
    // HANDLERS is looked up with a caller-supplied string. With an ordinary
    // object literal, `constructor` and `toString` would both find a function
    // here and be invoked as handlers.
    for (const type of ['constructor', 'toString', '__proto__', 'hasOwnProperty']) {
      assert.equal(await send({ type }), undefined, `${type} must not route`);
    }
    assert.equal(await send({}), undefined);
    assert.equal(await send(undefined), undefined);
    assert.equal(await send({ type: 42 }), undefined);
  });

  test('an unknown type is refused rather than answered with an error', async () => {
    // An untrusted sender learns nothing from us — not even which types exist.
    assert.equal(await send({ type: 'unlockPlease' }), undefined);
  });

  test('a handler that throws comes back as a failure, not an unhandled rejection', async () => {
    // A second setup on a configured profile is the easiest handler to make throw.
    const response = await send({ type: 'setUpPassword', password: 'another-password' });
    assert.equal(response.ok, false);
    assert.match(response.error, /already has a password/);
  });

  test('every handler is reachable only through the router', () => {
    // Guards against a handler being added straight onto the object in a way
    // that skips the gate — there is only one entry point, and this is it.
    assert.equal(Object.getPrototypeOf(HANDLERS), null);
    for (const name of Object.keys(HANDLERS)) {
      assert.equal(typeof HANDLERS[name], 'function', name);
    }
  });

  test('a legitimate page gets its answer', async () => {
    const status = await send({ type: 'status' });
    assert.equal(status.configured, true);
    assert.equal(status.lockState.isLocked, false);

    const settings = await send({ type: 'updateSettings', patch: { idleDelaySeconds: 900 } });
    assert.equal(settings.settings.idleDelaySeconds, 900);
    // The idle threshold is per worker lifetime, so a change has to reach
    // chrome.idle now rather than at the next worker start.
    assert.equal(fake.chrome.idle.detectionIntervalSeconds, 900);
  });
});

describe('tampered storage degrades rather than misbehaves', () => {
  test('a damaged profile bundle makes the profile dormant, not half-configured', async () => {
    fake.loadStorage({ ...configuredDisk, profileBundle: { v: 1, pub: 'not-a-bundle' } });

    assert.equal(await storage.isConfigured(), false);
    // Dormant means dormant: the trigger refuses rather than closing the tabs
    // and then discovering it cannot encrypt them.
    fake.openWindow({ tabs: TABS });
    await assert.rejects(() => engine.lock('manual'), /No password is set/);
    assert.equal(fake.listWindows().length, 1, 'the window is untouched');
  });

  test('a lock state of the wrong type reads as unlocked', async () => {
    for (const junk of ['locked', 42, ['isLocked'], null]) {
      fake.loadStorage({ ...configuredDisk, lockState: junk });
      const state = await storage.getLockState();
      assert.equal(state.isLocked, false, JSON.stringify(junk));
      assert.equal(state.lockWindowId, null);
    }
  });

  test('a lock window id that is not a number reads as absent', async () => {
    fake.loadStorage({
      ...configuredDisk,
      lockState: { isLocked: true, lockWindowId: 'all', lockedAt: Date.now(), reason: 'manual' },
    });
    const state = await storage.getLockState();
    assert.equal(state.isLocked, true);
    // The reaper spares exactly one window id. A string matches none of them, so
    // it must not be carried around as though it identified something.
    assert.equal(state.lockWindowId, null);

    // The sweep repairs it: no lock window is present, so one is made.
    fake.openWindow({ tabs: TABS });
    await engine.sweep();
    const windows = fake.listWindows();
    assert.equal(windows.length, 1);
    assert.equal(windows[0].type, 'popup');
    assert.equal((await storage.getLockState()).lockWindowId, windows[0].id);
  });

  test('a nonsense backoff does not block an attempt', async () => {
    for (const junk of [{ nextAttemptAt: NaN }, { nextAttemptAt: 'soon' }, 'backoff', 7]) {
      fake.loadStorage({ ...configuredDisk, backoff: junk });
      assert.equal(await engine.backoffRemainingMs(), 0, JSON.stringify(junk));
    }
  });

  test('an absurd backoff deadline is clamped to the policy maximum', async () => {
    const FIVE_MINUTES = 5 * 60 * 1000;
    fake.loadStorage({
      ...configuredDisk,
      backoff: { failures: 9e9, nextAttemptAt: Date.now() + 365 * 24 * 60 * 60 * 1000 },
    });
    // Nothing this code writes can exceed five minutes, so a year on the clock
    // is an edited record or a clock jump. Neither may lock someone out of their
    // own tabs for longer than the policy ever intends.
    assert.equal(await engine.backoffRemainingMs(), FIVE_MINUTES);
  });

  test('a malformed escrow bundle is not offered as a recovery path', async () => {
    fake.loadStorage({ ...configuredDisk, escrowBundleLocal: { v: 1, pub: 'truncated' } });
    const status = await engine.getEscrowStatus();
    assert.equal(status.available, false);
    assert.equal(status.source, null);
    assert.equal(status.canUnlockNow, false);
  });

  test('a malformed managed bundle does not shadow a working local one', async () => {
    // The precedence rule exists so a child cannot shadow the parent's key. It
    // must not fire on a bundle that is not a key at all — a truncated paste in
    // the plist would otherwise silently remove escrow from every profile.
    const master = 'a-very-long-master-password';
    await engine.createEscrow(master);
    const good = fake.dumpStorage();

    fake.setManaged('escrowBundle', { v: 1, pub: 'truncated' });
    const status = await engine.getEscrowStatus();
    assert.equal(status.source, 'local');
    assert.equal(status.keyId, good.escrowBundleLocal.keyId);
  });

  test('a corrupted ciphertext is a failed attempt, not a crash', async () => {
    fake.openWindow({ tabs: TABS });
    await engine.lock('manual');

    const disk = fake.dumpStorage();
    fake.loadStorage({ ...disk, snapshot: { ...disk.snapshot, ct: 'not base64 at all!!' } });

    const result = await engine.unlock(PASSWORD);
    assert.equal(result.ok, false);
    // And the lock holds: a session that cannot be decrypted must not be a way
    // to get the windows back.
    assert.equal((await storage.getLockState()).isLocked, true);
    assert.equal(fake.listWindows().filter((w) => w.type !== 'popup').length, 0);
  });

  test('a snapshot of the wrong shape still ends the lock and restores what it can', async () => {
    fake.openWindow({ tabs: TABS });
    await engine.lock('manual');

    // Written the way the engine writes one — a fresh dataKey, wrapped to this
    // profile's public key — so this goes through the real unlock path. Only the
    // plaintext is nonsense, which is the case a version change could produce.
    await writeSnapshot({
      windows: [
        'nope',
        null,
        { tabs: 'not-an-array' },
        { tabs: [{ url: null }, { url: 'https://ok.example/' }] },
      ],
    });

    const result = await engine.unlock(PASSWORD);
    assert.equal(result.ok, true);
    assert.equal((await storage.getLockState()).isLocked, false, 'the lock ended');

    // A restore that threw halfway would leave neither tabs nor a lock window.
    const windows = fake.listWindows();
    assert.equal(windows.length, 1);
    assert.deepEqual(windows[0].tabs.map((tab) => tab.url), ['https://ok.example/']);
  });
});

describe('a worker that died while locked comes back locked', () => {
  test('the lock is re-established from disk alone', async () => {
    fake.openWindow({ tabs: TABS });
    await engine.lock('manual');
    const disk = fake.dumpStorage();

    // Chrome restarts: the worker is gone, every in-memory guard with it, and
    // Chrome restores the previous session's windows on its own.
    const restarted = createFakeChrome();
    globalThis.chrome = restarted.chrome;
    restarted.loadStorage(disk);
    restarted.openWindow({ tabs: TABS });
    restarted.openWindow({ tabs: [{ url: 'https://example.net/three' }] });

    assert.equal((await storage.getLockState()).isLocked, true, 'still locked on cold start');

    // Not a bare sweep: window ids restart with the browser, so the recorded
    // lock window id may well name one of the windows Chrome just restored.
    await engine.resumeLock();

    const windows = restarted.listWindows();
    assert.equal(windows.length, 1);
    assert.equal(windows[0].type, 'popup', 'only the lock window survives');
    assert.equal((await storage.getLockState()).lockWindowId, windows[0].id);

    // And the session is still there for the password that owns it.
    const result = await engine.unlock(PASSWORD);
    assert.equal(result.ok, true);
    assert.deepEqual(
      restarted.listWindows().flatMap((win) => win.tabs.map((tab) => tab.url)),
      TABS.map((tab) => tab.url),
    );
  });
});

describe('profiles are independent', () => {
  const OTHER_PASSWORD = 'a-different-password-entirely';

  /** Three profiles: two configured with different passwords, one never touched. */
  let alice;
  let bob;
  let dormant;

  before(async () => {
    alice = createFakeChrome();
    bob = createFakeChrome();
    dormant = createFakeChrome();

    globalThis.chrome = alice.chrome;
    alice.loadStorage(configuredDisk); // set up with PASSWORD

    globalThis.chrome = bob.chrome;
    await engine.setUpPassword(OTHER_PASSWORD);
  });

  const inProfile = (profile, work) => {
    globalThis.chrome = profile.chrome;
    return work();
  };

  test('each profile locks and unlocks with its own password only', async () => {
    alice.openWindow({ tabs: [{ url: 'https://alice.example/' }] });
    bob.openWindow({ tabs: [{ url: 'https://bob.example/' }] });

    await inProfile(alice, () => engine.lock('manual'));
    await inProfile(bob, () => engine.lock('manual'));

    // Neither password opens the other's session, and failing in one profile
    // leaves the other exactly where it was.
    assert.equal((await inProfile(alice, () => engine.unlock(OTHER_PASSWORD))).ok, false);
    assert.equal((await inProfile(bob, () => engine.unlock(PASSWORD))).ok, false);

    assert.equal(await inProfile(alice, () => storage.getLockState()).then((s) => s.isLocked), true);
    assert.equal(await inProfile(bob, () => storage.getLockState()).then((s) => s.isLocked), true);

    assert.equal((await inProfile(alice, () => engine.unlock(PASSWORD))).ok, true);
    assert.deepEqual(
      alice.listWindows().flatMap((win) => win.tabs.map((tab) => tab.url)),
      ['https://alice.example/'],
    );
    // Bob is untouched by any of it: still locked, still holding his own tabs.
    assert.equal(await inProfile(bob, () => storage.getLockState()).then((s) => s.isLocked), true);
    assert.equal((await inProfile(bob, () => engine.unlock(OTHER_PASSWORD))).ok, true);
    assert.deepEqual(
      bob.listWindows().flatMap((win) => win.tabs.map((tab) => tab.url)),
      ['https://bob.example/'],
    );
  });

  test('a failed attempt in one profile does not slow another down', async () => {
    // The backoff is per profile because the storage it lives in is.
    await inProfile(alice, async () => {
      alice.openWindow({ tabs: TABS });
      await engine.lock('manual'); // unlock() refuses to count attempts otherwise
      for (let i = 0; i < 5; i++) await engine.unlock('wrong-password-here');
    });
    assert.ok(await inProfile(alice, () => engine.backoffRemainingMs()) > 0);
    assert.equal(await inProfile(bob, () => engine.backoffRemainingMs()), 0);
    assert.equal(await inProfile(dormant, () => engine.backoffRemainingMs()), 0);
  });

  test('the third profile stays completely silent', async () => {
    await inProfile(dormant, async () => {
      assert.equal(await storage.isConfigured(), false);
      dormant.openWindow({ tabs: TABS });

      // No lock, from any trigger — the worker checks dormancy before all three,
      // and the engine refuses even if one somehow got through.
      await assert.rejects(() => engine.lock('idle'), /No password is set/);
      await assert.rejects(() => engine.lock('startup'), /No password is set/);

      // Nothing written, either. A profile that never asked for this should look
      // exactly as it did before the extension arrived.
      assert.deepEqual(dormant.dumpStorage(), {});
      assert.equal(dormant.listWindows().length, 1);
      assert.equal(dormant.listWindows()[0].type, 'normal');
    });
  });
});
