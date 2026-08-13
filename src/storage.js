/**
 * Typed accessors over chrome.storage.local.
 *
 * Everything here is per-profile: chrome.storage.local is scoped to the Chrome
 * profile, which is what lets one shared extension binary serve N independent
 * locks. Nothing in this project writes to storage.sync — it is keyed to the
 * Google account, which several profiles on this machine could share.
 *
 * What is stored, and why it is safe to store in the clear:
 *
 *   profileBundle  this profile's RSA keypair, private half sealed under the
 *                  profile password. No plaintext secret.
 *   snapshot       the encrypted tab session {v, iv, ct}. Useless without a dataKey.
 *   wrap_pw        the snapshot's dataKey, wrapped to profileBundle's public key.
 *   wrap_master    the same dataKey, wrapped to the parent escrow public key.
 *   lockState      {isLocked, lockedAt, reason, lockWindowId} — plaintext on
 *                  purpose: not sensitive, and the service worker needs it on a
 *                  cold start to know it must keep enforcing the lock.
 *   backoff        failed-attempt count and the time attempts resume.
 *   settings       triggers and delays.
 *
 *   escrowBundleLocal  a parent escrow bundle installed by this profile, for
 *                  development and for machines with no policy. Also no plaintext
 *                  secret. A bundle from chrome.storage.managed, which the profile
 *                  cannot write to, takes precedence — see getEscrowRecord.
 */

import { looksLikeKeyBundle } from './crypto.js';

const KEYS = {
  profileBundle: 'profileBundle',
  snapshot: 'snapshot',
  wrapPw: 'wrap_pw',
  wrapMaster: 'wrap_master',
  lockState: 'lockState',
  backoff: 'backoff',
  settings: 'settings',
  /** Development-only escrow bundle, pasted into the options page. */
  escrowFallback: 'escrowBundleLocal',
};

const UNLOCKED = Object.freeze({
  isLocked: false,
  lockedAt: null,
  reason: null,
  lockWindowId: null,
});

async function get(key, fallback = null) {
  const result = await chrome.storage.local.get(key);
  return result[key] ?? fallback;
}

/**
 * Everything below treats what comes back from storage as untrusted input.
 *
 * Not because an attacker is expected — the threat model says otherwise — but
 * because `chrome://extensions` and devtools can edit this store by hand, and a
 * record that has been edited into the wrong *shape* should degrade to the
 * default rather than throw somewhere far from here. Spreading a string over a
 * defaults object, in particular, yields character-indexed keys rather than an
 * error, which is the kind of thing that fails much later and looks like a bug
 * in something else.
 */
function asObject(value) {
  return value && typeof value === 'object' && !Array.isArray(value) ? value : {};
}

/** A finite number, or `fallback` for anything else — NaN and Infinity included. */
function asNumber(value, fallback) {
  return typeof value === 'number' && Number.isFinite(value) ? value : fallback;
}

function set(key, value) {
  return chrome.storage.local.set({ [key]: value });
}

// --- this profile's key bundle ----------------------------------------------

/** @returns {Promise<object|null>} */
export const getProfileBundle = () => get(KEYS.profileBundle);
export const setProfileBundle = (bundle) => set(KEYS.profileBundle, bundle);

/**
 * Whether this profile has been configured at all. A profile that returns false
 * must behave as though the extension is not installed — the dormancy rule.
 */
export async function isConfigured() {
  // Shape-checked, not merely present: a profile whose bundle has been damaged
  // can neither lock nor unlock, so reporting it as configured would leave it
  // half-alive — arming triggers that can only fail — where dormancy leaves it
  // exactly as it was before the extension arrived, and able to set a password
  // again.
  return looksLikeKeyBundle(await getProfileBundle());
}

// --- the parent escrow bundle -----------------------------------------------

/**
 * Managed storage is populated from the macOS managed-preferences plist and is
 * read-only to the extension — the kids cannot edit or remove it, which is the
 * whole reason escrow is distributed this way. The local fallback exists so
 * escrow can be exercised during development without a plist.
 *
 * Managed wins when both exist. A profile that is under policy should behave the
 * same whatever it happens to have in its own storage: otherwise a child could
 * shadow the parent's escrow key with one whose password they chose, which would
 * silently disable the recovery path while the options page still claimed it was
 * there.
 *
 * @returns {Promise<{bundle: object, source: 'managed'|'local'}|{bundle: null, source: null}>}
 */
export async function getEscrowRecord() {
  try {
    const managed = await chrome.storage.managed.get('escrowBundle');
    // Shape-checked like everything else here. A malformed bundle in the plist —
    // a truncated paste, most likely — must not shadow a working local one and
    // must not be reported as an available recovery path.
    if (looksLikeKeyBundle(managed?.escrowBundle)) {
      return { bundle: managed.escrowBundle, source: 'managed' };
    }
  } catch {
    // No managed policy is configured for this profile. Expected, not an error.
  }
  const local = await get(KEYS.escrowFallback);
  return looksLikeKeyBundle(local)
    ? { bundle: local, source: 'local' }
    : { bundle: null, source: null };
}

/** @returns {Promise<object|null>} */
export const getEscrowBundle = async () => (await getEscrowRecord()).bundle;

export const setLocalEscrowBundle = (bundle) => set(KEYS.escrowFallback, bundle);
export const clearLocalEscrowBundle = () => chrome.storage.local.remove(KEYS.escrowFallback);

// --- the locked session -----------------------------------------------------

export const getSnapshot = () => get(KEYS.snapshot);
export const setSnapshot = (blob) => set(KEYS.snapshot, blob);

export const getPasswordSnapshotWrap = () => get(KEYS.wrapPw);
export const setPasswordSnapshotWrap = (wrap) => set(KEYS.wrapPw, wrap);

export const getMasterSnapshotWrap = () => get(KEYS.wrapMaster);
export const setMasterSnapshotWrap = (wrap) =>
  wrap === null ? chrome.storage.local.remove(KEYS.wrapMaster) : set(KEYS.wrapMaster, wrap);

/** Consume the locked session: ciphertext and both wraps go together or not at all. */
export const clearSnapshotRecords = () =>
  chrome.storage.local.remove([KEYS.snapshot, KEYS.wrapPw, KEYS.wrapMaster]);

// --- lock state -------------------------------------------------------------

/** @returns {Promise<{isLocked: boolean, lockedAt: number|null, reason: string|null, lockWindowId: number|null}>} */
export async function getLockState() {
  const stored = asObject(await get(KEYS.lockState, {}));
  return {
    ...UNLOCKED,
    ...stored,
    // Coerced rather than trusted: `isLocked` gates protection mode, and
    // `lockWindowId` decides which window the reaper spares. A non-number there
    // matches no window, so the reaper would close the lock window and the
    // handler that recreates it would not recognise it either.
    isLocked: stored.isLocked === true,
    lockWindowId: asNumber(stored.lockWindowId, null),
  };
}

export const setLockState = (state) => set(KEYS.lockState, state);
export const clearLockState = () => set(KEYS.lockState, { ...UNLOCKED });

// --- failed-attempt backoff -------------------------------------------------

/** @returns {Promise<{failures: number, nextAttemptAt: number}>} */
export async function getBackoff() {
  const stored = asObject(await get(KEYS.backoff, {}));
  return {
    failures: Math.max(0, asNumber(stored.failures, 0)),
    nextAttemptAt: asNumber(stored.nextAttemptAt, 0),
  };
}

export const setBackoff = (state) => set(KEYS.backoff, state);
export const clearBackoff = () => chrome.storage.local.remove(KEYS.backoff);

// --- settings ---------------------------------------------------------------

export const getStoredSettings = async () => asObject(await get(KEYS.settings, {}));
export const setStoredSettings = (settings) => set(KEYS.settings, settings);
