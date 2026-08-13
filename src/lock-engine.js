/**
 * Snapshot, close, protect, restore.
 *
 * The property this file exists to preserve: **while locked, the extension holds
 * no secret.** Locking needs only public keys; the dataKey is generated, used
 * once, wrapped, and wiped inside a single call. Only an unlock derives a
 * private key, and only for as long as that unlock takes. So a service worker
 * that is terminated, restarted, or disabled outright has no key and no
 * plaintext — there is nothing to restore and nothing to leak.
 *
 * Consequently protection mode is *persisted state*, not listeners attached at
 * lock time. An MV3 worker is torn down after ~30s idle; anything registered at
 * lock time would die with it. service_worker.js registers the listeners once at
 * top level, and they consult the stored lock state on every wake.
 */

import {
  DecryptError,
  changeBundlePassword,
  createKeyBundle,
  decryptSnapshot,
  encryptSnapshot,
  generateDataKey,
  looksLikeKeyBundle,
  unwrapWithBundle,
  validateKeyBundle,
  wipe,
  wrapToBundle,
} from './crypto.js';
import * as storage from './storage.js';

export const LOCK_WINDOW_PAGE = 'src/lock.html';
const LOCK_WINDOW_SIZE = { width: 440, height: 300 };

/** Schemes Chrome will not restore anyway, so there is no point capturing them. */
const UNRESTORABLE = ['chrome://', 'chrome-extension://', 'about:', 'devtools://'];

/** Failed attempts: 3 free, then min(2^(n-3) s, 5 min). Never anything destructive. */
const FREE_ATTEMPTS = 3;
const MAX_BACKOFF_MS = 5 * 60 * 1000;

/** Pause after leaving protection mode, so in-flight window events settle first. */
const RESTORE_SETTLE_MS = 200;

/**
 * In-memory guards that suppress the reaper during legitimate transitions. They
 * do not survive a worker restart and do not need to: each spans a single
 * uninterrupted async operation.
 */
let isRestoring = false;
let isCreatingLockWindow = false;

export class LockError extends Error {
  constructor(message) {
    super(message);
    this.name = 'LockError';
  }
}

// --- setup ------------------------------------------------------------------

/**
 * First-run: mint this profile's key bundle. The private half is sealed under
 * the password and never held afterwards.
 * @param {string} password
 */
export async function setUpPassword(password) {
  if (await storage.isConfigured()) {
    throw new LockError('This profile already has a password');
  }
  if (typeof password !== 'string' || password.length < 8) {
    throw new LockError('Password must be at least 8 characters');
  }
  await storage.setProfileBundle(await createKeyBundle(password));
}

/**
 * Change the password by resealing the private key under a new one. The keypair,
 * and therefore every existing snapshot wrap, is untouched.
 */
export async function changePassword(oldPassword, newPassword) {
  const bundle = await storage.getProfileBundle();
  if (!looksLikeKeyBundle(bundle)) throw new LockError('No password is set for this profile');
  if (typeof newPassword !== 'string' || newPassword.length < 8) {
    throw new LockError('Password must be at least 8 characters');
  }
  await storage.setProfileBundle(
    await changeBundlePassword(oldPassword, newPassword, bundle),
  );
}

// --- parent escrow ----------------------------------------------------------
// The escrow bundle is the same key bundle as a profile's own (crypto.js), made
// with the master password instead. Nothing here is secret: the private half is
// sealed under a password this machine never holds, so the bundle is safe to
// hand to every profile.

/**
 * The master password is the one credential where the "accidental and snoopy"
 * threat model does not apply: `privWrapped` is readable by every profile on the
 * machine, so it can be copied and ground offline where the backoff cannot see
 * it — and it unlocks *everything*. Hence a longer floor than a profile password,
 * and a nudge towards a generated passphrase rather than a memorable one.
 */
export const MIN_MASTER_PASSWORD_LENGTH = 16;

/**
 * What this profile knows about parent unlock, for the options and lock pages.
 *
 * `canUnlockNow` is the narrower question the lock screen has to ask: a bundle
 * being present is not enough, because a session locked before escrow was set up
 * has no `wrap_master` and cannot be opened by the master password however
 * correct it is. Offering the option then would be a lie.
 */
export async function getEscrowStatus() {
  const { bundle, source } = await storage.getEscrowRecord();
  return {
    available: bundle !== null,
    source,
    keyId: bundle?.keyId ?? null,
    // The bundle itself, so the options page can offer it for copying into the
    // plist. It holds no plaintext secret — that is the property that lets it be
    // distributed to every profile in the first place.
    bundle,
    /** Managed bundles come from policy; the profile cannot edit or remove them. */
    editable: source !== 'managed',
    canUnlockNow: bundle !== null && (await storage.getMasterSnapshotWrap()) !== null,
  };
}

/**
 * Mint an escrow bundle from a master password and install it on this profile.
 *
 * Returns the bundle so the options page can show it for copying into the
 * managed-preferences plist — which is where it belongs on a real install. This
 * local copy is the development path, and any profile under policy ignores it.
 *
 * @param {string} masterPassword
 * @returns {Promise<object>} the bundle, containing no plaintext secret
 */
export async function createEscrow(masterPassword) {
  await assertEscrowEditable();
  if (
    typeof masterPassword !== 'string' ||
    masterPassword.length < MIN_MASTER_PASSWORD_LENGTH
  ) {
    throw new LockError(
      `The master password must be at least ${MIN_MASTER_PASSWORD_LENGTH} characters`,
    );
  }
  const bundle = await createKeyBundle(masterPassword);
  await storage.setLocalEscrowBundle(bundle);
  return bundle;
}

/**
 * Install a bundle the parent made elsewhere — the other half of createEscrow,
 * for putting the same escrow key on a second profile without retyping the
 * master password into it.
 *
 * Validated by actually wrapping to its public key, because this input is pasted
 * by hand: a bundle that only looks right would fail at lock time, silently
 * costing the recovery path exactly when it was needed.
 */
export async function importEscrow(bundle) {
  await assertEscrowEditable();
  if (!(await validateKeyBundle(bundle))) {
    throw new LockError('That is not a valid escrow bundle');
  }
  await storage.setLocalEscrowBundle(bundle);
  return bundle;
}

/**
 * Forget the escrow bundle, ending parent unlock on this profile.
 *
 * This takes the currently locked session with it, and it has to: unwrapping
 * `wrap_master` needs the private key that lives, sealed, in the bundle being
 * removed. Without the bundle that wrap is unopenable by anyone — so it is
 * cleared too rather than left on disk as a record nothing can read (an escrow
 * that no longer works must not keep looking like one).
 *
 * Not destructive in the sense that matters: `wrap_pw` and the ciphertext are
 * untouched, so the profile's own password still opens the session. The only
 * thing lost is the recovery path, which is exactly what was asked for.
 */
export async function removeEscrow() {
  await assertEscrowEditable();
  await storage.clearLocalEscrowBundle();
  await storage.setMasterSnapshotWrap(null);
}

/**
 * Rotate the master password. The keypair is untouched, so `pub`, `keyId` and
 * every `wrap_master` ever written on any profile stay valid — a rotation costs
 * nothing and strands no session.
 */
export async function changeMasterPassword(oldPassword, newPassword) {
  const { bundle, source } = await storage.getEscrowRecord();
  if (!bundle) throw new LockError('No parent master password is set up');
  if (source === 'managed') {
    throw new LockError('This escrow key comes from policy; rotate it in the plist');
  }
  if (typeof newPassword !== 'string' || newPassword.length < MIN_MASTER_PASSWORD_LENGTH) {
    throw new LockError(
      `The master password must be at least ${MIN_MASTER_PASSWORD_LENGTH} characters`,
    );
  }
  const rotated = await changeBundlePassword(oldPassword, newPassword, bundle);
  await storage.setLocalEscrowBundle(rotated);
  return rotated;
}

async function assertEscrowEditable() {
  const { source } = await storage.getEscrowRecord();
  if (source === 'managed') {
    throw new LockError('The escrow key on this profile is set by policy and cannot be changed here');
  }
}

// --- lock -------------------------------------------------------------------

/**
 * Snapshot every normal window, encrypt it, close everything, put up the lock
 * window, and enter protection mode.
 *
 * @param {string} reason 'manual' | 'startup' | 'idle'
 */
export async function lock(reason = 'manual') {
  const bundle = await storage.getProfileBundle();
  // Checked before anything is captured or closed, not at the moment of
  // wrapping: a lock that fails halfway would have already taken the tabs away.
  if (!looksLikeKeyBundle(bundle)) throw new LockError('No password is set for this profile');
  if ((await storage.getLockState()).isLocked) return;

  const snapshot = await captureSnapshot();

  // One dataKey per lock, wrapped to every authorized path and then wiped. Only
  // public keys are involved, so this works with nobody present to type anything.
  const dataKey = generateDataKey();
  try {
    await storage.setSnapshot(await encryptSnapshot(dataKey, snapshot));
    await storage.setPasswordSnapshotWrap(await wrapToBundle(bundle, dataKey));

    const escrow = await storage.getEscrowBundle();
    await storage.setMasterSnapshotWrap(escrow ? await wrapToBundle(escrow, dataKey) : null);
  } finally {
    wipe(dataKey);
  }

  const lockWindow = await createLockWindow();

  await storage.setLockState({
    isLocked: true,
    lockedAt: Date.now(),
    reason,
    lockWindowId: lockWindow.id,
  });

  await closeEverythingExceptLockWindow(lockWindow.id);
}

/**
 * The plaintext snapshot: every normal window and the tabs worth restoring.
 * Geometry, window state, focus, tab order, pinning, the active tab and tab
 * groups — everything needed for the restored session to be indistinguishable
 * from the original.
 *
 * Group membership is recorded on each tab as an index into the window's
 * `groups` array rather than as Chrome's group id, because ids are not stable
 * across a restore and an index is all the regrouping step needs.
 */
async function captureSnapshot() {
  const windows = await chrome.windows.getAll({
    populate: true,
    windowTypes: ['normal'],
  });

  const captured = [];
  for (const win of windows) {
    // Incognito's whole point is leaving no trace; capturing those tabs into a
    // record that outlives the session would contradict it. They are closed and
    // forgotten (PLAN.md §10.4).
    if (win.incognito) continue;

    const groups = await captureGroups(win.id);
    const groupIndexById = new Map(groups.map((group, i) => [group.id, i]));

    const tabs = (win.tabs ?? [])
      .filter((tab) => isRestorable(tab.url))
      .map((tab) => ({
        url: tab.url,
        pinned: tab.pinned === true,
        active: tab.active === true,
        group: groupIndexById.get(tab.groupId) ?? null,
      }));
    if (tabs.length === 0) continue;

    captured.push({
      left: win.left,
      top: win.top,
      width: win.width,
      height: win.height,
      state: win.state,
      focused: win.focused === true,
      // Ids are dropped: they do not survive a restore, and tabs reference
      // groups by index into this array.
      groups: groups.map(({ id, ...rest }) => rest),
      tabs,
    });
  }
  return { v: 2, capturedAt: Date.now(), windows: captured };
}

/**
 * Tab groups for one window. `tabGroups` is a separate permission and a separate
 * API from `tabs`, and it is absent on older Chrome builds — a profile without it
 * should still lock, just without group fidelity.
 */
async function captureGroups(windowId) {
  if (!chrome.tabGroups) return [];
  try {
    const groups = await chrome.tabGroups.query({ windowId });
    return groups.map((group) => ({
      id: group.id,
      title: group.title ?? '',
      color: group.color,
      collapsed: group.collapsed === true,
    }));
  } catch {
    return [];
  }
}

function isRestorable(url) {
  return typeof url === 'string' && url !== '' && !UNRESTORABLE.some((p) => url.startsWith(p));
}

// --- unlock -----------------------------------------------------------------

/**
 * @param {string} password
 * @param {'password'|'master'} via
 * @returns {Promise<{ok: true} | {ok: false, error: string, retryAfterMs?: number}>}
 */
export async function unlock(password, via = 'password') {
  const state = await storage.getLockState();
  if (!state.isLocked) return { ok: true };

  const wait = await backoffRemainingMs();
  if (wait > 0) {
    return { ok: false, error: 'Too many attempts. Try again shortly.', retryAfterMs: wait };
  }

  // Unwrapping the key and decrypting the snapshot are one step as far as the
  // caller is concerned: both fail with DecryptError, and both mean "this did
  // not open". Only the first is a wrong password, but the second — a truncated
  // or edited ciphertext — must not throw past here either, or the lock screen
  // gets an exception where it expects a refusal.
  let snapshot;
  try {
    const dataKey = await recoverDataKey(password, via);
    try {
      const blob = await storage.getSnapshot();
      snapshot = blob ? await decryptSnapshot(dataKey, blob) : { windows: [] };
    } finally {
      wipe(dataKey);
    }
  } catch (error) {
    if (!(error instanceof DecryptError)) throw error;
    const retryAfterMs = await recordFailure();
    return { ok: false, error: error.message, retryAfterMs };
  }

  await storage.clearBackoff();
  await restore(snapshot, state.lockWindowId);
  return { ok: true };
}

/** Password -> the profile's (or the parent's) private key -> the snapshot's dataKey. */
async function recoverDataKey(password, via) {
  if (via === 'master') {
    const escrow = await storage.getEscrowBundle();
    const wrap = await storage.getMasterSnapshotWrap();
    if (!escrow || !wrap) throw new DecryptError('Parent unlock is not available here');
    return unwrapWithBundle(password, escrow, wrap);
  }
  const bundle = await storage.getProfileBundle();
  const wrap = await storage.getPasswordSnapshotWrap();
  if (!bundle || !wrap) throw new DecryptError('No locked session to unlock');
  return unwrapWithBundle(password, bundle, wrap);
}

/**
 * Leave protection mode first, then rebuild. Order matters: while `isLocked` is
 * true the reaper closes every window that is not the lock window, so clearing
 * the state is a precondition for restoring, not a postscript to it.
 */
async function restore(snapshot, lockWindowId) {
  isRestoring = true;
  try {
    await storage.clearLockState();
    await sleep(RESTORE_SETTLE_MS);

    // Focus is applied last: every window is created focused (Chrome focuses a
    // new window regardless), so without a final pass the last one restored
    // would always end up on top rather than the one that was.
    let focusWindowId = null;
    // The snapshot is authenticated, so this list is what we wrote — but it has
    // been through JSON and a format version, and a restore that throws halfway
    // strands the user with neither their tabs nor a lock window. Each window is
    // therefore taken on its own: one bad record costs that window, not the
    // session.
    for (const win of asArray(snapshot?.windows)) {
      const createdId = await restoreWindow(win).catch(() => null);
      if (createdId != null && (win.focused || focusWindowId === null)) focusWindowId = createdId;
    }
    if (focusWindowId != null) {
      await chrome.windows.update(focusWindowId, { focused: true }).catch(() => {});
    }

    // The snapshot is consumed on restore: the ciphertext and its wraps are the
    // only copies, and keeping them past an unlock would leave a stale session
    // recoverable by an old password.
    await storage.clearSnapshotRecords();
    if (lockWindowId != null) await removeWindow(lockWindowId);
  } finally {
    isRestoring = false;
  }
}

/**
 * Rebuild one window: geometry, then per-tab state, then groups.
 *
 * The order is forced by Chrome. Pinning moves a tab to the front of the strip,
 * and a pinned tab cannot belong to a group — so pinning must happen before
 * grouping, or the group call would fail on tabs that have since moved.
 *
 * @returns {Promise<number|null>} the new window's id
 */
async function restoreWindow(win) {
  // Tabs without a usable url are dropped *before* the urls are taken, not
  // after: every step below pairs the i-th created tab with the i-th source
  // record, so a filter applied to only one of the two lists would silently
  // shift pinning, focus and group membership onto the wrong tabs.
  const sourceTabs = asArray(win?.tabs).filter(
    (tab) => typeof tab?.url === 'string' && tab.url !== '',
  );
  if (sourceTabs.length === 0) return null;
  const urls = sourceTabs.map((tab) => tab.url);

  // Chrome rejects geometry combined with a non-normal state, so it is one or
  // the other.
  const geometry = win.state && win.state !== 'normal'
    ? { state: win.state }
    : { left: win.left, top: win.top, width: win.width, height: win.height };

  const created = await chrome.windows.create({ url: urls, focused: true, ...geometry });
  const tabs = created?.tabs ?? [];

  for (let i = 0; i < tabs.length; i++) {
    const source = sourceTabs[i];
    if (!source) continue;
    const update = {};
    if (source.pinned) update.pinned = true;
    if (source.active) update.active = true;
    if (Object.keys(update).length > 0) {
      await chrome.tabs.update(tabs[i].id, update).catch(() => {});
    }
  }

  await restoreGroups(win, created?.id, tabs, sourceTabs);
  return created?.id ?? null;
}

/**
 * Recreate the window's tab groups, with their titles, colors and collapsed
 * state. Best-effort throughout: a window whose groups cannot be rebuilt is
 * still a restored window, and losing a group label is not worth losing tabs
 * over.
 */
async function restoreGroups(win, windowId, tabs, sourceTabs) {
  if (!chrome.tabGroups || windowId == null) return;

  // group index -> the new tab ids that belonged to it
  const members = new Map();
  for (let i = 0; i < tabs.length; i++) {
    const source = sourceTabs[i];
    // Pinned tabs cannot be grouped; Chrome would have dropped them from the
    // group on capture anyway, but storage is locally editable so check here.
    if (!source || source.group == null || source.pinned) continue;
    if (!members.has(source.group)) members.set(source.group, []);
    members.get(source.group).push(tabs[i].id);
  }

  for (const [index, tabIds] of members) {
    const group = asArray(win?.groups)[index];
    if (!group) continue;
    try {
      const groupId = await chrome.tabs.group({ tabIds, createProperties: { windowId } });
      await chrome.tabGroups.update(groupId, {
        title: group.title,
        color: group.color,
        collapsed: group.collapsed === true,
      });
    } catch {
      // Grouping is cosmetic. The tabs are already open and that is the point.
    }
  }
}

// --- protection mode --------------------------------------------------------
// Called by the listeners in service_worker.js. Every one of these re-reads the
// lock state, because the worker may have been restarted since the lock began.

/** A window appeared. If it is not the lock window, it does not get to exist. */
export async function onWindowCreated(win) {
  if (isRestoring || isCreatingLockWindow) return;
  const state = await storage.getLockState();
  if (!state.isLocked || win.id === state.lockWindowId) return;
  await removeWindow(win.id);
}

/** A tab appeared. Same rule, one level down. */
export async function onTabCreated(tab) {
  if (isRestoring || isCreatingLockWindow) return;
  const state = await storage.getLockState();
  if (!state.isLocked || tab.windowId === state.lockWindowId) return;
  await chrome.tabs.remove(tab.id).catch(() => {});
}

/** The lock window was closed. Put it back. */
export async function onWindowRemoved(windowId) {
  if (isRestoring) return;
  const state = await storage.getLockState();
  if (!state.isLocked || windowId !== state.lockWindowId) return;

  const replacement = await createLockWindow();
  await storage.setLockState({ ...state, lockWindowId: replacement.id });
}

/** Focus went elsewhere. Take it back. */
export async function onFocusChanged(windowId) {
  if (isRestoring || isCreatingLockWindow) return;
  if (windowId === chrome.windows.WINDOW_ID_NONE) return;
  const state = await storage.getLockState();
  if (!state.isLocked || windowId === state.lockWindowId) return;
  await chrome.windows.update(state.lockWindowId, { focused: true }).catch(() => {});
}

/**
 * Belt-and-braces sweep, on an alarm. Events are the real enforcement — they
 * wake the worker, which makes the listener path self-healing — but a sweep
 * catches anything that slipped through while the worker was down, and repairs
 * a lock window that was closed in that gap.
 */
export async function sweep() {
  if (isRestoring || isCreatingLockWindow) return;
  const state = await storage.getLockState();
  if (!state.isLocked) return;

  const windows = await chrome.windows.getAll();
  const lockWindowPresent = windows.some((win) => win.id === state.lockWindowId);

  if (!lockWindowPresent) {
    const replacement = await createLockWindow();
    await storage.setLockState({ ...state, lockWindowId: replacement.id });
    await closeEverythingExceptLockWindow(replacement.id);
    return;
  }
  await closeEverythingExceptLockWindow(state.lockWindowId);
}

/**
 * Re-establish a lock across a browser restart.
 *
 * A sweep is not enough on its own. Window ids come from a counter that starts
 * over with the browser, so the `lockWindowId` written before Chrome closed very
 * likely names one of the windows Chrome has just restored from the previous
 * session — and the sweep would then spare that window as the lock window, close
 * everything else, and leave the profile sitting on its own tabs with no
 * password prompt in front of them.
 *
 * So the stale id is dropped first, and the sweep builds a real lock window.
 */
export async function resumeLock() {
  const state = await storage.getLockState();
  if (!state.isLocked) return;
  await storage.setLockState({ ...state, lockWindowId: null });
  await sweep();
}

async function closeEverythingExceptLockWindow(lockWindowId) {
  const windows = await chrome.windows.getAll();
  for (const win of windows) {
    if (win.id !== lockWindowId) await removeWindow(win.id);
  }
}

async function createLockWindow() {
  isCreatingLockWindow = true;
  try {
    return await chrome.windows.create({
      url: chrome.runtime.getURL(LOCK_WINDOW_PAGE),
      type: 'popup',
      focused: true,
      ...LOCK_WINDOW_SIZE,
    });
  } finally {
    isCreatingLockWindow = false;
  }
}

/** Closing a window that Chrome already closed is not an error worth propagating. */
function removeWindow(windowId) {
  return chrome.windows.remove(windowId).catch(() => {});
}

// --- failed attempts --------------------------------------------------------

/**
 * How long the lock screen must wait before its next attempt. Exported so the
 * lock window can show a live countdown rather than only learning about the
 * backoff by being refused — and so a lock window recreated mid-backoff (or one
 * reopened after the worker died) starts out in the right state.
 *
 * @returns {Promise<number>} ms still to wait, 0 if an attempt is allowed now
 */
export async function backoffRemainingMs() {
  const { nextAttemptAt } = await storage.getBackoff();
  // Clamped to the same ceiling the backoff itself can reach. Nothing this code
  // writes can exceed it, so a larger value means an edited record or a clock
  // that jumped — neither of which should be able to hold someone out of their
  // own tabs for longer than the policy ever intends.
  return Math.min(Math.max(0, nextAttemptAt - Date.now()), MAX_BACKOFF_MS);
}

/**
 * Record a wrong password. Exponential backoff, persisted with a timestamp so
 * restarting Chrome does not reset it — and deliberately nothing destructive.
 * @returns {Promise<number>} ms until the next attempt is allowed
 */
async function recordFailure() {
  const { failures } = await storage.getBackoff();
  const next = failures + 1;
  const delay =
    next <= FREE_ATTEMPTS ? 0 : Math.min(2 ** (next - FREE_ATTEMPTS) * 1000, MAX_BACKOFF_MS);
  await storage.setBackoff({ failures: next, nextAttemptAt: Date.now() + delay });
  return delay;
}

/** Storage and JSON both survive being edited into the wrong type; iteration does not. */
function asArray(value) {
  return Array.isArray(value) ? value : [];
}

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
