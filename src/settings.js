/**
 * Defaults and validation for the lock triggers.
 *
 * A profile that has never been configured is inert regardless of what is stored
 * here — dormancy is enforced at the trigger site, not by these values. So these
 * defaults only ever describe a profile whose owner has deliberately set a
 * password, which is what makes it reasonable for idle locking to be on: someone
 * who sets a password wants to be locked when they walk away, and a lock that
 * only fires when you remember to ask for it is the one that isn't there when it
 * matters.
 *
 * Startup locking stays off. It is the one trigger that can surprise you before
 * you have done anything, and it is a two-click change on the options page.
 */

import { getStoredSettings, setStoredSettings } from './storage.js';

export const DEFAULTS = Object.freeze({
  lockOnStartup: false,
  lockOnIdle: true,
  /** Seconds of idle before an idle lock fires. Chrome's minimum is 15. */
  idleDelaySeconds: 600,
});

const MIN_IDLE_SECONDS = 15;
const MAX_IDLE_SECONDS = 60 * 60 * 4;

/** @returns {Promise<typeof DEFAULTS>} */
export async function getSettings() {
  return validate({ ...DEFAULTS, ...(await getStoredSettings()) });
}

/**
 * Merge a partial update over what is stored, validating the result.
 * @param {Partial<typeof DEFAULTS>} patch
 */
export async function updateSettings(patch) {
  const next = validate({ ...(await getSettings()), ...patch });
  await setStoredSettings(next);
  return next;
}

/**
 * Coerce anything read from storage into a usable settings object. Storage is
 * locally editable, so this treats its input as untrusted.
 */
function validate(settings) {
  const idle = Number(settings.idleDelaySeconds);
  // `> 0` and not merely finite: `Number(null)` and `Number('')` are both 0, and
  // clamping those up to the 15s minimum would quietly arm a hair-trigger idle
  // lock out of what is really a missing value. Nonsense falls back to the
  // default; only a real number gets clamped.
  const usable = Number.isFinite(idle) && idle > 0;
  return {
    lockOnStartup: settings.lockOnStartup === true,
    lockOnIdle: settings.lockOnIdle === true,
    idleDelaySeconds: usable
      ? Math.min(Math.max(Math.round(idle), MIN_IDLE_SECONDS), MAX_IDLE_SECONDS)
      : DEFAULTS.idleDelaySeconds,
  };
}
