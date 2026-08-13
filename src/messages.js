/**
 * The message router: every request from our own pages arrives here.
 *
 * It lives in its own module rather than inside service_worker.js because it is
 * the one place authorization is decided (invariant §9.1), and a rule that
 * cannot be tested is a rule that is believed rather than known. The worker
 * registers `routeMessage` and does nothing else with messages.
 *
 * Two gates, both of which have to hold before a handler runs:
 *
 *   1. The sender is us. `sender.id` is set by Chrome, not by the sender, and a
 *      page that is not part of this extension cannot forge it. Without this
 *      check any web page could post `{type:"unlock"}` at the worker — which is
 *      exactly the bug GoogleChromeProfileLock and BrowserLock both shipped.
 *   2. The type names a handler we actually defined. `HANDLERS` is given a null
 *      prototype so that `{type:"constructor"}` or `{type:"__proto__"}` finds
 *      nothing instead of finding a function off Object.prototype.
 */

import * as engine from './lock-engine.js';
import { getSettings, updateSettings } from './settings.js';
import * as storage from './storage.js';

/**
 * Handlers for messages from our own pages. Each returns a plain object that is
 * sent straight back to the caller.
 *
 * Null-prototype: see gate 2 above. This object is looked up with an
 * attacker-influenced string, so it must contain nothing it was not given.
 */
export const HANDLERS = Object.assign(Object.create(null), {
  async status() {
    return {
      configured: await storage.isConfigured(),
      lockState: await storage.getLockState(),
      escrow: await engine.getEscrowStatus(),
    };
  },

  /** Mint an escrow key. The bundle comes back so it can be copied to the plist. */
  async createEscrow({ masterPassword }) {
    return { ok: true, bundle: await engine.createEscrow(masterPassword) };
  },

  async importEscrow({ bundle }) {
    return { ok: true, bundle: await engine.importEscrow(bundle) };
  },

  async removeEscrow() {
    await engine.removeEscrow();
    return { ok: true };
  },

  async changeMasterPassword({ oldPassword, newPassword }) {
    return { ok: true, bundle: await engine.changeMasterPassword(oldPassword, newPassword) };
  },

  async setUpPassword({ password }) {
    await engine.setUpPassword(password);
    return { ok: true };
  },

  async changePassword({ oldPassword, newPassword }) {
    await engine.changePassword(oldPassword, newPassword);
    return { ok: true };
  },

  async getSettings() {
    return { ok: true, settings: await getSettings() };
  },

  /**
   * Returns what was actually stored, not what was asked for: settings.js clamps
   * and coerces, so the options page renders the response rather than its own
   * controls.
   */
  async updateSettings({ patch }) {
    const settings = await updateSettings(patch ?? {});
    // The idle threshold is per worker lifetime, so a changed delay has to be
    // pushed to chrome.idle now — the next worker start reapplies it from here.
    chrome.idle.setDetectionInterval(settings.idleDelaySeconds);
    return { ok: true, settings };
  },

  /** Lets the lock window resume a countdown it did not start. */
  async backoffStatus() {
    return { ok: true, retryAfterMs: await engine.backoffRemainingMs() };
  },

  async lock() {
    await engine.lock('manual');
    return { ok: true };
  },

  async unlock({ password, via }) {
    return engine.unlock(password, via === 'master' ? 'master' : 'password');
  },
});

/**
 * Gate 1. `sender.id` is enough on its own — Chrome sets it and nothing else
 * can — but the URL is checked too where one is present, so that only pages
 * shipped inside this extension are ever answered. The service worker itself
 * sends no messages and carries no `sender.url`, hence the conditional.
 *
 * @param {chrome.runtime.MessageSender|undefined} sender
 */
export function isTrustedSender(sender) {
  if (!sender || sender.id !== chrome.runtime.id) return false;
  const prefix = `chrome-extension://${chrome.runtime.id}/`;
  if (typeof sender.url === 'string' && !sender.url.startsWith(prefix)) return false;
  return true;
}

/**
 * The `chrome.runtime.onMessage` listener.
 *
 * Returns `true` only when a response is coming, which is what keeps the message
 * channel open; anything rejected by either gate returns `false` and is answered
 * by nobody. A refused message gets no error back on purpose — an untrusted
 * sender learns nothing from us, not even which types exist.
 *
 * @returns {boolean}
 */
export function routeMessage(message, sender, sendResponse) {
  if (!isTrustedSender(sender)) return false;

  const type = message?.type;
  const handler = typeof type === 'string' ? HANDLERS[type] : undefined;
  if (typeof handler !== 'function') return false;

  handler(message)
    .then(sendResponse)
    .catch((error) => sendResponse({ ok: false, error: error.message }));
  return true; // the response is async
}
