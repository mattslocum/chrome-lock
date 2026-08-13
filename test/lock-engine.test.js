import { test, describe, before, beforeEach } from 'node:test';
import assert from 'node:assert/strict';

import { createFakeChrome } from './fake-chrome.js';

// The engine resolves the `chrome` global at call time, so a test can swap in a
// fresh fake between cases. It must exist before the module is imported, though,
// because storage.js touches it at load.
let fake = createFakeChrome();
globalThis.chrome = fake.chrome;

const engine = await import('../src/lock-engine.js');
const storage = await import('../src/storage.js');

const PASSWORD = 'correct-horse-battery';

const TABS = [
  { url: 'https://example.com/one', pinned: true },
  { url: 'https://example.org/two?q=1', active: true },
];

/**
 * Setting up a password costs an RSA keygen plus a full 600k-iteration PBKDF2,
 * so it is done once and the resulting on-disk state is replayed into a fresh
 * fake for each test. That also exercises the thing we care about: the engine
 * holds nothing across a restart beyond what is written here.
 */
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

/** A window matching TABS, plus a chrome:// tab that must not be captured. */
function openTypicalWindow() {
  return fake.openWindow({
    left: 120,
    top: 60,
    width: 1280,
    height: 800,
    tabs: [...TABS, { url: 'chrome://settings/' }],
  });
}

function lockWindows() {
  return fake.listWindows().filter((win) => win.type === 'popup');
}

describe('setup and dormancy', () => {
  test('an unconfigured profile refuses to lock and reports itself dormant', async () => {
    const blank = createFakeChrome();
    globalThis.chrome = blank.chrome;
    blank.openWindow({ tabs: TABS });

    assert.equal(await storage.isConfigured(), false);
    await assert.rejects(() => engine.lock('manual'), engine.LockError);
    assert.equal(blank.listWindows().length, 1, 'nothing may be closed');
  });

  test('a configured profile reports itself configured', async () => {
    assert.equal(await storage.isConfigured(), true);
  });

  test('rejects a password that is too short', async () => {
    const blank = createFakeChrome();
    globalThis.chrome = blank.chrome;
    await assert.rejects(() => engine.setUpPassword('short'), engine.LockError);
  });
});

describe('lock', () => {
  test('closes every window and leaves only the lock window', async () => {
    openTypicalWindow();
    fake.openWindow({ tabs: [{ url: 'https://third.example/' }] });

    await engine.lock('manual');

    const open = fake.listWindows();
    assert.equal(open.length, 1);
    assert.equal(open[0].type, 'popup');
    assert.match(open[0].tabs[0].url, /lock\.html$/);
  });

  test('records the lock state so a cold-started worker knows to enforce it', async () => {
    openTypicalWindow();
    await engine.lock('idle');

    const state = await storage.getLockState();
    assert.equal(state.isLocked, true);
    assert.equal(state.reason, 'idle');
    assert.equal(state.lockWindowId, lockWindows()[0].id);
  });

  test('is idempotent — locking while locked does not overwrite the snapshot', async () => {
    openTypicalWindow();
    await engine.lock('manual');
    const first = fake.dumpStorage();

    await engine.lock('manual');
    assert.deepEqual(fake.dumpStorage().snapshot, first.snapshot);
  });

  test('writes an escrow wrap when a bundle is published to managed storage', async () => {
    const { createKeyBundle } = await import('../src/crypto.js');
    fake.setManaged('escrowBundle', await createKeyBundle('master-pw', { iterations: 1000 }));
    openTypicalWindow();

    await engine.lock('manual');
    assert.notEqual(await storage.getMasterSnapshotWrap(), null);
  });

  test('writes no escrow wrap when no bundle is available', async () => {
    openTypicalWindow();
    await engine.lock('manual');
    assert.equal(await storage.getMasterSnapshotWrap(), null);
  });
});

describe('unlock', () => {
  test('restores windows, tabs, order, pinning and geometry', async () => {
    const original = openTypicalWindow();
    await engine.lock('manual');

    assert.deepEqual(await engine.unlock(PASSWORD), { ok: true });

    const restored = fake.listWindows();
    assert.equal(restored.length, 1, 'the lock window must be gone');
    const win = restored[0];
    assert.deepEqual(
      win.tabs.map((tab) => tab.url),
      TABS.map((tab) => tab.url),
      'chrome:// tabs are not captured, everything else is, in order',
    );
    assert.equal(win.tabs[0].pinned, true);
    assert.equal(win.tabs[1].active, true);
    assert.deepEqual(
      { left: win.left, top: win.top, width: win.width, height: win.height },
      { left: original.left, top: original.top, width: original.width, height: original.height },
    );
  });

  test('consumes the snapshot, so an old session cannot be restored twice', async () => {
    openTypicalWindow();
    await engine.lock('manual');
    await engine.unlock(PASSWORD);

    const disk = fake.dumpStorage();
    assert.equal(disk.snapshot, undefined);
    assert.equal(disk.wrap_pw, undefined);
    assert.equal(disk.wrap_master, undefined);
    assert.equal((await storage.getLockState()).isLocked, false);
  });

  test('a wrong password leaves the lock and the snapshot intact', async () => {
    openTypicalWindow();
    await engine.lock('manual');

    const result = await engine.unlock('not-the-password');
    assert.equal(result.ok, false);
    assert.equal((await storage.getLockState()).isLocked, true);
    assert.notEqual(await storage.getSnapshot(), null);
    assert.equal(lockWindows().length, 1, 'the lock window stays up');
  });

  test('never wipes anything after repeated failures — it only delays', async () => {
    openTypicalWindow();
    await engine.lock('manual');
    const before = fake.dumpStorage();

    for (let i = 0; i < 4; i++) await engine.unlock('wrong');

    const after = fake.dumpStorage();
    assert.deepEqual(after.snapshot, before.snapshot);
    assert.deepEqual(after.profileBundle, before.profileBundle);
  });

  test('backs off only after the free attempts are used up', async () => {
    openTypicalWindow();
    await engine.lock('manual');

    for (let i = 0; i < 3; i++) {
      const result = await engine.unlock('wrong');
      assert.ok(!result.retryAfterMs, `attempt ${i + 1} should be free`);
    }
    const throttled = await engine.unlock('wrong');
    assert.ok(throttled.retryAfterMs > 0, 'the fourth attempt starts the backoff');

    // And the delay is enforced, not merely reported: the correct password is
    // refused while the timer runs.
    const blocked = await engine.unlock(PASSWORD);
    assert.equal(blocked.ok, false);
    assert.ok(blocked.retryAfterMs > 0);
  });

  test('a successful unlock clears the failure count', async () => {
    openTypicalWindow();
    await engine.lock('manual');
    await engine.unlock('wrong');

    assert.deepEqual(await engine.unlock(PASSWORD), { ok: true });
    assert.deepEqual(await storage.getBackoff(), { failures: 0, nextAttemptAt: 0 });
  });
});

/**
 * Phase 3's bar: the restored session should be indistinguishable from the
 * original. These cases each pin one dimension of that — geometry and window
 * state, tab groups with their metadata, which window ends up focused, and the
 * interaction between pinning and grouping that Chrome's API forces on us.
 */
describe('restore fidelity', () => {
  test('restores tab groups with their titles, colors and collapsed state', async () => {
    fake.openWindow({
      tabs: [
        { url: 'https://a.example/', group: 'work' },
        { url: 'https://b.example/', group: 'work' },
        { url: 'https://c.example/' },
        { url: 'https://d.example/', group: 'reading' },
      ],
      groupSpecs: {
        work: { color: 'blue', collapsed: false },
        reading: { color: 'red', collapsed: true },
      },
    });

    await engine.lock('manual');
    await engine.unlock(PASSWORD);

    const win = fake.listWindows()[0];
    const groupOf = (url) => {
      const tab = win.tabs.find((t) => t.url === url);
      return fake.listGroups().find((g) => g.id === tab.groupId) ?? null;
    };

    const work = groupOf('https://a.example/');
    assert.deepEqual(
      { title: work.title, color: work.color, collapsed: work.collapsed },
      { title: 'work', color: 'blue', collapsed: false },
    );
    assert.equal(groupOf('https://b.example/').id, work.id, 'both work tabs share one group');
    assert.equal(groupOf('https://c.example/'), null, 'an ungrouped tab stays ungrouped');

    const reading = groupOf('https://d.example/');
    assert.notEqual(reading.id, work.id, 'separate groups stay separate');
    assert.deepEqual(
      { title: reading.title, color: reading.color, collapsed: reading.collapsed },
      { title: 'reading', color: 'red', collapsed: true },
    );
  });

  test('a group spanning two windows is rebuilt per window, not merged', async () => {
    fake.openWindow({ tabs: [{ url: 'https://a.example/', group: 'left' }] });
    fake.openWindow({ tabs: [{ url: 'https://b.example/', group: 'right' }] });

    await engine.lock('manual');
    await engine.unlock(PASSWORD);

    const wins = fake.listWindows();
    assert.equal(wins.length, 2);
    const groupIds = wins.map((win) => win.tabs[0].groupId);
    assert.notEqual(groupIds[0], groupIds[1]);
    for (const [i, id] of groupIds.entries()) {
      const group = fake.listGroups().find((g) => g.id === id);
      assert.equal(group.windowId, wins[i].id, 'each group belongs to its own window');
    }
  });

  test('pinned tabs are restored pinned and never grouped', async () => {
    fake.openWindow({
      tabs: [
        { url: 'https://pinned.example/', pinned: true },
        { url: 'https://grouped.example/', group: 'work' },
      ],
    });

    await engine.lock('manual');
    await engine.unlock(PASSWORD);

    const win = fake.listWindows()[0];
    const pinned = win.tabs.find((t) => t.url === 'https://pinned.example/');
    assert.equal(pinned.pinned, true);
    assert.equal(pinned.groupId, -1, 'Chrome forbids a pinned tab in a group');
    assert.notEqual(win.tabs.find((t) => t.url === 'https://grouped.example/').groupId, -1);
  });

  test('restores the window that was focused, not merely the last one rebuilt', async () => {
    fake.openWindow({ tabs: [{ url: 'https://focused.example/' }], focused: true });
    fake.openWindow({ tabs: [{ url: 'https://background.example/' }] });

    await engine.lock('manual');
    await engine.unlock(PASSWORD);

    const focused = fake.listWindows().filter((win) => win.focused);
    assert.equal(focused.length, 1, 'exactly one window has focus');
    assert.equal(focused[0].tabs[0].url, 'https://focused.example/');
  });

  test('restores a maximized window as maximized rather than at stale geometry', async () => {
    fake.openWindow({ tabs: [{ url: 'https://a.example/' }], state: 'maximized' });

    await engine.lock('manual');
    await engine.unlock(PASSWORD);

    assert.equal(fake.listWindows()[0].state, 'maximized');
  });

  test('locks and restores normally on a Chrome build with no tabGroups API', async () => {
    fake.openWindow({ tabs: [{ url: 'https://a.example/', group: 'work' }] });
    const tabGroups = fake.chrome.tabGroups;
    delete fake.chrome.tabGroups;

    try {
      await engine.lock('manual');
      assert.deepEqual(await engine.unlock(PASSWORD), { ok: true });
    } finally {
      fake.chrome.tabGroups = tabGroups;
    }

    const win = fake.listWindows()[0];
    assert.equal(win.tabs[0].url, 'https://a.example/', 'tabs matter, groups are a bonus');
  });
});

describe('protection mode', () => {
  test('closes any window that appears while locked', async () => {
    openTypicalWindow();
    await engine.lock('manual');

    const intruder = fake.openWindow({ tabs: [{ url: 'https://sneaky.example/' }] });
    await engine.onWindowCreated(intruder);

    assert.deepEqual(fake.listWindows().map((w) => w.type), ['popup']);
  });

  test('leaves the lock window alone', async () => {
    openTypicalWindow();
    await engine.lock('manual');

    await engine.onWindowCreated(lockWindows()[0]);
    assert.equal(lockWindows().length, 1);
  });

  test('recreates the lock window if it is closed', async () => {
    openTypicalWindow();
    await engine.lock('manual');
    const original = lockWindows()[0];

    await chrome.windows.remove(original.id);
    await engine.onWindowRemoved(original.id);

    const replacement = lockWindows();
    assert.equal(replacement.length, 1);
    assert.notEqual(replacement[0].id, original.id);
    assert.equal((await storage.getLockState()).lockWindowId, replacement[0].id);
  });

  test('the sweep repairs a lock that drifted while the worker was down', async () => {
    openTypicalWindow();
    await engine.lock('manual');

    // What a terminated service worker would miss: the lock window closed and
    // ordinary windows opened, with no listener awake to react.
    fake.closeAllWindows();
    fake.openWindow({ tabs: [{ url: 'https://while-you-were-out.example/' }] });

    await engine.sweep();

    const open = fake.listWindows();
    assert.equal(open.length, 1);
    assert.equal(open[0].type, 'popup');
  });

  test('does nothing at all when unlocked', async () => {
    const win = fake.openWindow({ tabs: TABS });
    await engine.onWindowCreated(win);
    await engine.sweep();
    assert.equal(fake.listWindows().length, 1);
  });
});

describe('disabling the extension must not restore tabs', () => {
  test('nothing readable on disk reveals a captured URL', async () => {
    openTypicalWindow();
    await engine.lock('manual');

    // Everything a person could read after disabling the extension: the whole of
    // this profile's storage, exactly as persisted.
    const disk = JSON.stringify(fake.dumpStorage());

    assert.doesNotMatch(disk, /example\.com/);
    assert.doesNotMatch(disk, /example\.org/);
    assert.doesNotMatch(disk, /https:\/\//);
    assert.match(disk, /"snapshot"/, 'the ciphertext really is there to be searched');
  });

  test('re-enabling the extension does not restore the session', async () => {
    openTypicalWindow();
    await engine.lock('manual');
    const disk = fake.dumpStorage();

    // Disable: the worker and every in-memory value are gone. Re-enable: a fresh
    // runtime comes back to exactly what was on disk, and nothing else.
    const reenabled = createFakeChrome();
    globalThis.chrome = reenabled.chrome;
    reenabled.loadStorage(disk);

    // The lock survives the cycle...
    assert.equal((await storage.getLockState()).isLocked, true);
    await engine.sweep();
    assert.deepEqual(reenabled.listWindows().map((w) => w.type), ['popup']);

    // ...and the restored runtime has no key, so it cannot open the snapshot.
    assert.equal((await engine.unlock('guess')).ok, false);
    assert.equal((await engine.unlock('')).ok, false);
    assert.notEqual(await storage.getSnapshot(), null, 'and it destroys nothing trying');
  });

  test('only the password recovers the session, and it still does', async () => {
    openTypicalWindow();
    await engine.lock('manual');
    const disk = fake.dumpStorage();

    const reenabled = createFakeChrome();
    globalThis.chrome = reenabled.chrome;
    reenabled.loadStorage(disk);

    assert.deepEqual(await engine.unlock(PASSWORD), { ok: true });
    assert.deepEqual(
      reenabled.listWindows()[0].tabs.map((tab) => tab.url),
      TABS.map((tab) => tab.url),
    );
  });
});

/**
 * The point of changing a password is that it reseals the private key and
 * nothing else: the keypair, and therefore every wrap and the ciphertext, must
 * survive untouched. A change that re-encrypted the snapshot would be a change
 * that could lose it.
 */
describe('changing the password', () => {
  const NEW_PASSWORD = 'a-different-long-password';

  test('the new password opens a session locked under the old one', async () => {
    openTypicalWindow();
    await engine.lock('manual');
    const wrapBefore = await storage.getPasswordSnapshotWrap();
    const snapshotBefore = await storage.getSnapshot();

    await engine.changePassword(PASSWORD, NEW_PASSWORD);

    assert.deepEqual(await storage.getPasswordSnapshotWrap(), wrapBefore, 'wrap untouched');
    assert.deepEqual(await storage.getSnapshot(), snapshotBefore, 'ciphertext untouched');
    assert.deepEqual(await engine.unlock(NEW_PASSWORD), { ok: true });
    assert.deepEqual(
      fake.listWindows()[0].tabs.map((tab) => tab.url),
      TABS.map((tab) => tab.url),
    );
  });

  test('the old password stops working once it is changed', async () => {
    await engine.changePassword(PASSWORD, NEW_PASSWORD);
    openTypicalWindow();
    await engine.lock('manual');

    assert.equal((await engine.unlock(PASSWORD)).ok, false);
    assert.notEqual(await storage.getSnapshot(), null, 'and a wrong guess destroys nothing');
  });

  test('a wrong current password changes nothing', async () => {
    const before = await storage.getProfileBundle();
    await assert.rejects(() => engine.changePassword('not-the-password', NEW_PASSWORD));
    assert.deepEqual(await storage.getProfileBundle(), before);
  });

  test('rejects a new password that is too short, without checking the old one', async () => {
    const before = await storage.getProfileBundle();
    await assert.rejects(() => engine.changePassword(PASSWORD, 'short'), engine.LockError);
    assert.deepEqual(await storage.getProfileBundle(), before);
  });

  test('a dormant profile has no password to change', async () => {
    globalThis.chrome = createFakeChrome().chrome;
    await assert.rejects(() => engine.changePassword(PASSWORD, NEW_PASSWORD), engine.LockError);
  });
});

/**
 * The lock window is recreated whenever it is closed and the worker is torn down
 * constantly, so a backoff has to be readable from storage rather than held by
 * whichever page happened to trigger it.
 */
describe('backoff is visible to a freshly opened lock window', () => {
  test('reports no wait before any failure', async () => {
    assert.equal(await engine.backoffRemainingMs(), 0);
  });

  test('reports the remaining wait after the free attempts are spent', async () => {
    openTypicalWindow();
    await engine.lock('manual');
    for (let i = 0; i < 4; i++) await engine.unlock('wrong');

    const remaining = await engine.backoffRemainingMs();
    assert.ok(remaining > 0 && remaining <= 2000, `expected a short wait, got ${remaining}`);
  });

  test('survives a worker restart, because it is a timestamp on disk', async () => {
    openTypicalWindow();
    await engine.lock('manual');
    for (let i = 0; i < 4; i++) await engine.unlock('wrong');
    const disk = fake.dumpStorage();

    const restarted = createFakeChrome();
    globalThis.chrome = restarted.chrome;
    restarted.loadStorage(disk);

    assert.ok(await engine.backoffRemainingMs() > 0);
  });
});

/**
 * Parent escrow: the second and last unlock path.
 *
 * The properties worth pinning down are the ones a family depends on rather than
 * the ones a cryptographer would list. A parent can open a kid's session; doing
 * so changes nothing about the kid's own password; a profile under policy cannot
 * quietly swap the escrow key for one it chose; and every one of these paths
 * fails without destroying a session.
 */
describe('parent escrow', () => {
  const MASTER = 'a-long-generated-master-passphrase';
  const FAST = { iterations: 1000 };

  /** A cheap escrow bundle. Real ones cost 600k iterations; the mechanism is identical. */
  async function escrowBundle(password = MASTER) {
    const { createKeyBundle } = await import('../src/crypto.js');
    return createKeyBundle(password, FAST);
  }

  describe('installing a key', () => {
    test('rejects a master password short enough to be memorable', async () => {
      await assert.rejects(() => engine.createEscrow('short-one'), engine.LockError);
      assert.equal((await engine.getEscrowStatus()).available, false);
    });

    test('rejects anything that is not a working key bundle', async () => {
      const real = await escrowBundle();
      const cases = {
        'not an object': 'nonsense',
        'missing the public half': { ...real, pub: undefined },
        // Structurally perfect and still useless: the check is whether it encrypts.
        'a corrupted public key': { ...real, pub: real.privWrapped.ct },
      };
      for (const [name, bundle] of Object.entries(cases)) {
        await assert.rejects(() => engine.importEscrow(bundle), engine.LockError, name);
      }
      assert.equal((await engine.getEscrowStatus()).available, false);
    });

    test('accepts a bundle exported from another profile', async () => {
      const bundle = await escrowBundle();
      await engine.importEscrow(bundle);

      const status = await engine.getEscrowStatus();
      assert.equal(status.available, true);
      assert.equal(status.source, 'local');
      assert.equal(status.keyId, bundle.keyId);
      assert.equal(status.editable, true);
    });
  });

  describe('unlocking as a parent', () => {
    test('opens the session, and the profile password still works afterwards', async () => {
      await engine.importEscrow(await escrowBundle());
      openTypicalWindow();
      await engine.lock('manual');
      const profileBundleBefore = await storage.getProfileBundle();

      assert.deepEqual(await engine.unlock(MASTER, 'master'), { ok: true });
      assert.deepEqual(
        fake.listWindows()[0].tabs.map((tab) => tab.url),
        TABS.map((tab) => tab.url),
      );

      // The whole point of "it restores and stops": nothing is reset.
      assert.deepEqual(await storage.getProfileBundle(), profileBundleBefore);
      openTypicalWindow();
      await engine.lock('manual');
      assert.deepEqual(await engine.unlock(PASSWORD), { ok: true });
    });

    test('a wrong master password leaves the lock and the snapshot intact', async () => {
      await engine.importEscrow(await escrowBundle());
      openTypicalWindow();
      await engine.lock('manual');

      const result = await engine.unlock('a-long-but-wrong-passphrase', 'master');
      assert.equal(result.ok, false);
      assert.equal((await storage.getLockState()).isLocked, true);
      assert.notEqual(await storage.getSnapshot(), null);
    });

    test('the profile password is not accepted on the parent path, or vice versa', async () => {
      await engine.importEscrow(await escrowBundle());
      openTypicalWindow();
      await engine.lock('manual');

      assert.equal((await engine.unlock(PASSWORD, 'master')).ok, false);
      assert.equal((await engine.unlock(MASTER, 'password')).ok, false);
      assert.deepEqual(await engine.unlock(PASSWORD), { ok: true }, 'and neither guess broke it');
    });

    test('backoff covers the parent path too, so it is not a way around a wait', async () => {
      await engine.importEscrow(await escrowBundle());
      openTypicalWindow();
      await engine.lock('manual');

      for (let i = 0; i < 4; i++) await engine.unlock('wrong', 'password');
      const result = await engine.unlock(MASTER, 'master');

      assert.equal(result.ok, false, 'the correct master password waits its turn');
      assert.ok(result.retryAfterMs > 0);
      assert.equal((await storage.getLockState()).isLocked, true);
    });

    test('is offered only when it could actually work', async () => {
      // Locked before escrow existed: there is no wrap to open, so the lock
      // screen must not advertise a path that cannot succeed.
      openTypicalWindow();
      await engine.lock('manual');
      await engine.importEscrow(await escrowBundle());

      assert.equal((await engine.getEscrowStatus()).canUnlockNow, false);
      assert.equal((await engine.unlock(MASTER, 'master')).ok, false);
      assert.deepEqual(await engine.unlock(PASSWORD), { ok: true }, 'the owner is unaffected');

      openTypicalWindow();
      await engine.lock('manual');
      assert.equal((await engine.getEscrowStatus()).canUnlockNow, true);
    });
  });

  describe('under policy', () => {
    test('a managed bundle wins over anything the profile installed itself', async () => {
      const managed = await escrowBundle('the-managed-master-passphrase');
      await engine.importEscrow(await escrowBundle());
      fake.setManaged('escrowBundle', managed);

      const status = await engine.getEscrowStatus();
      assert.equal(status.source, 'managed');
      assert.equal(status.keyId, managed.keyId);
      assert.equal(status.editable, false);

      // And the wrap follows the managed key, so a child cannot shadow the
      // parent's escrow with one whose password they chose.
      openTypicalWindow();
      await engine.lock('manual');
      assert.equal((await engine.unlock(MASTER, 'master')).ok, false);
      assert.deepEqual(
        await engine.unlock('the-managed-master-passphrase', 'master'),
        { ok: true },
      );
    });

    test('the profile cannot change or remove a key set by policy', async () => {
      fake.setManaged('escrowBundle', await escrowBundle());

      for (const attempt of [
        () => engine.createEscrow('another-long-master-passphrase'),
        () => engine.importEscrow(escrowBundle()),
        () => engine.removeEscrow(),
        () => engine.changeMasterPassword(MASTER, 'another-long-master-passphrase'),
      ]) {
        await assert.rejects(attempt, engine.LockError);
      }
      assert.equal((await engine.getEscrowStatus()).source, 'managed');
    });
  });

  describe('rotating and removing', () => {
    test('a new master password opens a session locked under the old one', async () => {
      await engine.importEscrow(await escrowBundle());
      openTypicalWindow();
      await engine.lock('manual');
      const wrapBefore = await storage.getMasterSnapshotWrap();

      const rotated = await engine.changeMasterPassword(MASTER, 'the-next-master-passphrase');

      // The keypair is untouched, so no profile anywhere is stranded by a rotation.
      assert.equal(rotated.keyId, (await storage.getEscrowBundle()).keyId);
      assert.deepEqual(await storage.getMasterSnapshotWrap(), wrapBefore);
      assert.equal((await engine.unlock(MASTER, 'master')).ok, false);
      assert.deepEqual(
        await engine.unlock('the-next-master-passphrase', 'master'),
        { ok: true },
      );
    });

    test('a wrong current master password changes nothing', async () => {
      await engine.importEscrow(await escrowBundle());
      const before = await storage.getEscrowBundle();

      await assert.rejects(() =>
        engine.changeMasterPassword('not-the-master-passphrase', 'a-long-new-passphrase'),
      );
      assert.deepEqual(await storage.getEscrowBundle(), before);
    });

    test('removing escrow ends parent unlock without stranding the owner', async () => {
      await engine.importEscrow(await escrowBundle());
      openTypicalWindow();
      await engine.lock('manual');

      await engine.removeEscrow();

      // The private key that could open wrap_master went with the bundle, so the
      // wrap is unreadable by anyone — it must not linger looking like a path.
      assert.equal((await engine.getEscrowStatus()).available, false);
      assert.equal(await storage.getMasterSnapshotWrap(), null);
      assert.equal((await engine.unlock(MASTER, 'master')).ok, false);

      // And the thing that must never break: the owner's own session.
      assert.deepEqual(await engine.unlock(PASSWORD), { ok: true });
      assert.deepEqual(
        fake.listWindows()[0].tabs.map((tab) => tab.url),
        TABS.map((tab) => tab.url),
      );
    });
  });
});
