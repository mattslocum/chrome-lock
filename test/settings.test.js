/**
 * Settings come from chrome.storage.local, which is locally editable, and from
 * an options page whose controls a user can be handed by an older build. Both
 * are untrusted input, so what matters here is that anything readable produces a
 * usable settings object rather than a trigger that misfires or never fires.
 */

import { test, describe, beforeEach } from 'node:test';
import assert from 'node:assert/strict';

import { createFakeChrome } from './fake-chrome.js';

let fake = createFakeChrome();
globalThis.chrome = fake.chrome;

const { DEFAULTS, getSettings, updateSettings } = await import('../src/settings.js');
const storage = await import('../src/storage.js');

beforeEach(() => {
  fake = createFakeChrome();
  globalThis.chrome = fake.chrome;
});

describe('defaults', () => {
  test('a profile that has never opened the settings page gets the conservative set', async () => {
    assert.deepEqual(await getSettings(), DEFAULTS);
  });

  // Setting a password is a deliberate act, and the walk-away case is the one
  // this extension exists for — so idle locking is on for anyone who configured
  // the profile at all. Startup locking is not: it can fire before you have done
  // anything, which is a worse surprise than a lock you asked for.
  test('idle locking is on by default at ten minutes; startup locking is not', async () => {
    assert.equal(DEFAULTS.lockOnIdle, true);
    assert.equal(DEFAULTS.idleDelaySeconds, 600);
    assert.equal(DEFAULTS.lockOnStartup, false);
  });

  // The defaults are irrelevant to a profile nobody configured — the trigger
  // sites check that first, so a default-on idle lock does not wake a dormant
  // profile. This is the guard that makes an on-by-default trigger safe.
  test('a dormant profile is unaffected by an on-by-default trigger', async () => {
    assert.equal(await storage.isConfigured(), false);
  });
});

describe('updating', () => {
  test('a partial patch leaves the other settings alone', async () => {
    await updateSettings({ lockOnIdle: true });
    await updateSettings({ idleDelaySeconds: 300 });

    assert.deepEqual(await getSettings(), {
      lockOnStartup: false,
      lockOnIdle: true,
      idleDelaySeconds: 300,
    });
  });

  test('returns what was stored, which is what the options page renders', async () => {
    const returned = await updateSettings({ idleDelaySeconds: 300 });
    assert.deepEqual(returned, await getSettings());
  });

  test('an empty patch is a no-op rather than a reset', async () => {
    await updateSettings({ lockOnStartup: true, idleDelaySeconds: 900 });
    await updateSettings({});

    const settings = await getSettings();
    assert.equal(settings.lockOnStartup, true);
    assert.equal(settings.idleDelaySeconds, 900);
  });
});

describe('untrusted input', () => {
  test('a delay below Chrome’s minimum is raised to it, not passed through', async () => {
    // chrome.idle.setDetectionInterval throws below 15s, which would break the
    // idle trigger on every worker start rather than at the moment it was set.
    assert.equal((await updateSettings({ idleDelaySeconds: 1 })).idleDelaySeconds, 15);
  });

  test('an absurd delay is clamped rather than accepted', async () => {
    assert.equal((await updateSettings({ idleDelaySeconds: 1e9 })).idleDelaySeconds, 4 * 60 * 60);
  });

  test('a non-numeric delay falls back to the default', async () => {
    assert.equal(
      (await updateSettings({ idleDelaySeconds: 'soon' })).idleDelaySeconds,
      DEFAULTS.idleDelaySeconds,
    );
  });

  test('the toggles are strictly booleans, so a truthy string does not arm a trigger', async () => {
    const settings = await updateSettings({ lockOnStartup: 'yes', lockOnIdle: 1 });
    assert.equal(settings.lockOnStartup, false);
    assert.equal(settings.lockOnIdle, false);
  });

  test('garbage written directly to storage still yields usable settings', async () => {
    await storage.setStoredSettings({ lockOnIdle: true, idleDelaySeconds: null, junk: 'x' });

    assert.deepEqual(await getSettings(), {
      lockOnStartup: false,
      lockOnIdle: true,
      idleDelaySeconds: DEFAULTS.idleDelaySeconds,
    });
  });
});
