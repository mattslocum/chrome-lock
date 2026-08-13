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
 * The escrow bundle is *not* in this list: it arrives via chrome.storage.managed,
 * which the profile cannot write to. See getEscrowBundle.
 */

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
  return (await getProfileBundle()) !== null;
}

// --- the parent escrow bundle -----------------------------------------------

/**
 * Managed storage is populated from the macOS managed-preferences plist and is
 * read-only to the extension — the kids cannot edit or remove it, which is the
 * whole reason escrow is distributed this way. The local fallback exists so
 * escrow can be exercised during development without a plist.
 *
 * @returns {Promise<object|null>}
 */
export async function getEscrowBundle() {
  try {
    const managed = await chrome.storage.managed.get('escrowBundle');
    if (managed?.escrowBundle) return managed.escrowBundle;
  } catch {
    // No managed policy is configured for this profile. Expected, not an error.
  }
  return get(KEYS.escrowFallback);
}

export const setLocalEscrowBundle = (bundle) => set(KEYS.escrowFallback, bundle);

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
  return { ...UNLOCKED, ...(await get(KEYS.lockState, {})) };
}

export const setLockState = (state) => set(KEYS.lockState, state);
export const clearLockState = () => set(KEYS.lockState, { ...UNLOCKED });

// --- failed-attempt backoff -------------------------------------------------

/** @returns {Promise<{failures: number, nextAttemptAt: number}>} */
export async function getBackoff() {
  return { failures: 0, nextAttemptAt: 0, ...(await get(KEYS.backoff, {})) };
}

export const setBackoff = (state) => set(KEYS.backoff, state);
export const clearBackoff = () => chrome.storage.local.remove(KEYS.backoff);

// --- settings ---------------------------------------------------------------

export const getStoredSettings = () => get(KEYS.settings, {});
export const setStoredSettings = (settings) => set(KEYS.settings, settings);
