/**
 * Defaults and validation for the lock triggers.
 *
 * The defaults are deliberately conservative: only the manual trigger is on. A
 * profile that has never been configured is inert regardless of what is stored
 * here — dormancy is enforced at the trigger site, not by these values.
 */

import { getStoredSettings, setStoredSettings } from './storage.js';

export const DEFAULTS = Object.freeze({
  lockOnStartup: false,
  lockOnIdle: false,
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
  return {
    lockOnStartup: settings.lockOnStartup === true,
    lockOnIdle: settings.lockOnIdle === true,
    idleDelaySeconds: Number.isFinite(idle)
      ? Math.min(Math.max(Math.round(idle), MIN_IDLE_SECONDS), MAX_IDLE_SECONDS)
      : DEFAULTS.idleDelaySeconds,
  };
}
