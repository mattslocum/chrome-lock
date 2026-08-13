/**
 * Orchestration, message router, lifecycle.
 *
 * Every listener is registered here at top level, unconditionally, because an
 * MV3 service worker is terminated after ~30s idle and only a top-level
 * registration survives to wake it again. The handlers themselves decide whether
 * to act, by reading the persisted lock state — which is why protection mode can
 * outlive any number of worker restarts.
 *
 * Dormancy: a profile that has never set a password does nothing at all. Every
 * trigger below checks that first. No badge, no notification, no page opened on
 * install or update, ever.
 */

import * as engine from './lock-engine.js';
import { getSettings } from './settings.js';
import * as storage from './storage.js';

const SWEEP_ALARM = 'lock-sweep';
const SWEEP_PERIOD_MINUTES = 1; // the MV3 minimum
const LOCK_COMMAND = 'lock-now';

// --- protection mode listeners ----------------------------------------------

chrome.windows.onCreated.addListener((win) => {
  engine.onWindowCreated(win);
});

chrome.tabs.onCreated.addListener((tab) => {
  engine.onTabCreated(tab);
});

chrome.windows.onRemoved.addListener((windowId) => {
  engine.onWindowRemoved(windowId);
});

chrome.windows.onFocusChanged.addListener((windowId) => {
  engine.onFocusChanged(windowId);
});

chrome.alarms.onAlarm.addListener((alarm) => {
  if (alarm.name === SWEEP_ALARM) engine.sweep();
});

// --- lifecycle --------------------------------------------------------------

// Every worker start, not just install: the idle threshold is per worker
// lifetime and reverts to Chrome's default when the worker is torn down.
applyIdleDetectionInterval();

chrome.runtime.onInstalled.addListener(() => {
  ensureSweepAlarm();
});

chrome.runtime.onStartup.addListener(async () => {
  await ensureSweepAlarm();
  if (!(await storage.isConfigured())) return;

  // A lock that was in effect when Chrome closed is still in effect now: Chrome
  // restores the previous session on its own, so without this the tabs would
  // simply come back.
  if ((await storage.getLockState()).isLocked) {
    await engine.sweep();
    return;
  }
  if ((await getSettings()).lockOnStartup) await engine.lock('startup');
});

chrome.idle.onStateChanged.addListener(async (state) => {
  // 'locked' is the macOS screen lock, which is exactly the walk-away case.
  if (state !== 'idle' && state !== 'locked') return;
  if (!(await storage.isConfigured())) return;
  if ((await storage.getLockState()).isLocked) return;

  const settings = await getSettings();
  if (settings.lockOnIdle) await engine.lock('idle');
});

// The keyboard shortcut. Dormancy applies: on a profile with no password this
// does nothing, silently — no error, no prompt to set one up.
chrome.commands.onCommand.addListener(async (command) => {
  if (command !== LOCK_COMMAND) return;
  if (!(await storage.isConfigured())) return;
  await engine.lock('manual');
});

async function ensureSweepAlarm() {
  const existing = await chrome.alarms.get(SWEEP_ALARM);
  if (!existing) {
    await chrome.alarms.create(SWEEP_ALARM, { periodInMinutes: SWEEP_PERIOD_MINUTES });
  }
}

/**
 * `chrome.idle` fires `idle` after a threshold that is scoped to the worker's
 * lifetime and reverts to Chrome's 60s default when the worker is torn down — so
 * the configured delay is reapplied on every start, not set once at install.
 * Doing it unconditionally is safe:
 * the threshold only decides when `onStateChanged` fires, and that handler still
 * checks dormancy and the trigger setting before locking anything.
 */
async function applyIdleDetectionInterval() {
  const { idleDelaySeconds } = await getSettings();
  chrome.idle.setDetectionInterval(idleDelaySeconds);
}

// --- message router ---------------------------------------------------------

/**
 * Handlers for messages from our own pages. Each returns a plain object that is
 * sent back to the caller.
 */
const HANDLERS = {
  async status() {
    return {
      configured: await storage.isConfigured(),
      lockState: await storage.getLockState(),
      escrowAvailable: (await storage.getEscrowBundle()) !== null,
    };
  },

  async setUpPassword({ password }) {
    await engine.setUpPassword(password);
    return { ok: true };
  },

  async lock() {
    await engine.lock('manual');
    return { ok: true };
  },

  async unlock({ password, via }) {
    return engine.unlock(password, via === 'master' ? 'master' : 'password');
  },
};

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  // The one check that all three reference extensions omitted, twice over:
  // without it, any web page could post {type:"unlock"} at us.
  if (sender.id !== chrome.runtime.id) return false;

  const handler = HANDLERS[message?.type];
  if (!handler) return false;

  handler(message ?? {})
    .then(sendResponse)
    .catch((error) => sendResponse({ ok: false, error: error.message }));
  return true; // response is async
});
