/**
 * The settings page: set or change the password, choose the triggers, and see
 * plainly whether a parent can unlock this profile.
 *
 * This page holds no key material and calls no crypto. It hands passwords to the
 * service worker and renders what comes back — the same arrangement as the lock
 * window, for the same reason: `crypto.js` has exactly one caller.
 *
 * Settings save as they are changed. There is no Save button to forget to press,
 * and no state on this page that can disagree with what is stored.
 */

const MIN_PASSWORD_LENGTH = 8;
/**
 * Longer than a profile password, because the master password unlocks every
 * profile and its sealed key is readable by anyone on this computer, so it can be
 * ground offline where the lock screen's backoff cannot see it. Duplicated from
 * the engine rather than imported: pages talk to the worker and never load it.
 * The engine enforces this; here it only decides what the form says.
 */
const MIN_MASTER_PASSWORD_LENGTH = 16;
const SHORTCUTS_PAGE = 'chrome://extensions/shortcuts';
const LOCK_COMMAND = 'lock-now';

const el = (id) => document.getElementById(id);

const passwordSetup = el('password-setup');
const passwordChange = el('password-change');
const triggers = el('triggers');
const settingsMessage = el('settings-message');

// --- password ---------------------------------------------------------------

el('setup-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  const message = el('setup-message');
  const password = el('setup-new').value;

  const complaint = checkNewPassword(password, el('setup-confirm').value);
  if (complaint) {
    message.textContent = complaint;
    return;
  }

  // The RSA keygen takes about a second, and this is the one place the user
  // waits on it, so say so rather than appearing to have ignored the click.
  message.textContent = 'Setting up…';
  message.classList.add('ok');
  const result = await withButtonDisabled(el('setup-submit'), () =>
    chrome.runtime.sendMessage({ type: 'setUpPassword', password }),
  );
  clearFields('setup-new', 'setup-confirm');
  message.classList.remove('ok');

  if (!result?.ok) {
    message.textContent = result?.error ?? 'Could not set the password.';
    return;
  }
  message.textContent = '';
  await render();
});

el('change-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  const message = el('change-message');
  const oldPassword = el('change-old').value;
  const newPassword = el('change-new').value;

  const complaint = checkNewPassword(newPassword, el('change-confirm').value);
  if (complaint) {
    message.textContent = complaint;
    return;
  }

  const result = await withButtonDisabled(el('change-submit'), () =>
    chrome.runtime.sendMessage({ type: 'changePassword', oldPassword, newPassword }),
  );
  clearFields('change-old', 'change-new', 'change-confirm');

  if (!result?.ok) {
    message.textContent = result?.error ?? 'Could not change the password.';
    message.classList.remove('ok');
    return;
  }
  message.textContent = 'Password changed.';
  message.classList.add('ok');
});

/** @returns {string|null} what is wrong with the proposed password, if anything */
function checkNewPassword(password, confirmation, minLength = MIN_PASSWORD_LENGTH) {
  if (password.length < minLength) {
    return `Use at least ${minLength} characters.`;
  }
  if (password !== confirmation) return 'The two passwords do not match.';
  return null;
}

// --- triggers ---------------------------------------------------------------

el('lock-on-startup').addEventListener('change', (event) => {
  save({ lockOnStartup: event.target.checked });
});

el('lock-on-idle').addEventListener('change', (event) => {
  el('idle-delay').disabled = !event.target.checked;
  save({ lockOnIdle: event.target.checked });
});

el('idle-delay').addEventListener('change', (event) => {
  save({ idleDelaySeconds: Number(event.target.value) });
});

el('edit-shortcut').addEventListener('click', () => {
  // Chrome blocks navigating to a chrome:// URL from a link, but opening one in
  // a new tab from an extension page is allowed.
  chrome.tabs.create({ url: SHORTCUTS_PAGE });
});

/**
 * Persist a partial settings change and re-render from what the worker actually
 * stored — the settings module clamps and coerces, so the response is the truth
 * and the control that triggered this is only a proposal.
 */
async function save(patch) {
  const result = await chrome.runtime.sendMessage({ type: 'updateSettings', patch });
  if (!result?.ok) {
    settingsMessage.textContent = result?.error ?? 'Could not save that.';
    settingsMessage.classList.remove('ok');
    return;
  }
  showSettings(result.settings);
  settingsMessage.textContent = 'Saved.';
  settingsMessage.classList.add('ok');
}

function showSettings(settings) {
  el('lock-on-startup').checked = settings.lockOnStartup;
  el('lock-on-idle').checked = settings.lockOnIdle;
  el('idle-delay').disabled = !settings.lockOnIdle;

  const delay = el('idle-delay');
  // A value clamped or restored from an older build may not be one of the
  // offered choices; add it rather than silently showing the wrong one.
  const seconds = String(settings.idleDelaySeconds);
  if (![...delay.options].some((option) => option.value === seconds)) {
    delay.add(new Option(`${Math.round(settings.idleDelaySeconds / 60)} minutes`, seconds));
  }
  delay.value = seconds;
}

/** The shortcut is user-editable in Chrome and can be unassigned, so read it. */
async function showShortcut() {
  const commands = await chrome.commands.getAll();
  const shortcut = commands.find((command) => command.name === LOCK_COMMAND)?.shortcut;
  el('shortcut').textContent = shortcut || 'not set';
}

// --- escrow -----------------------------------------------------------------

/**
 * Escrow is a labeled feature, not a hidden backdoor. If a parent can unlock this
 * profile, this page says so in as many words — including on my own profile, where
 * it is also true.
 */
const ESCROW_COPY = {
  managed:
    'A parent master password can unlock this profile. It is set for every profile on ' +
    'this computer by an administrator, so it cannot be changed or removed here. ' +
    'Unlocking that way shows whoever holds that password the tabs you had open. It ' +
    'does not change or reveal your own password, which keeps working.',
  local:
    'A parent master password can unlock this profile, so a forgotten password is ' +
    'recoverable. Unlocking that way shows whoever holds that password the tabs you had ' +
    'open. It does not change or reveal your own password, which keeps working.',
  none:
    'No parent master password is set up on this profile, so nothing but your own ' +
    'password can open a locked session here. Forget it and those tabs are gone.',
};

function showEscrow(escrow) {
  const source = escrow?.available ? escrow.source : 'none';
  el('escrow-status').textContent = ESCROW_COPY[source] ?? ESCROW_COPY.none;

  // Managed escrow is policy: neither branch of the editing UI applies.
  el('escrow-create').hidden = escrow?.available === true || escrow?.editable !== true;
  el('escrow-manage').hidden = !(escrow?.available === true && escrow?.editable === true);

  if (escrow?.bundle) {
    el('escrow-key-id').textContent = escrow.keyId;
    el('escrow-bundle').value = JSON.stringify(escrow.bundle);
  }
}

el('escrow-create-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  const message = el('escrow-create-message');
  const masterPassword = el('escrow-new').value;

  const complaint = checkNewPassword(
    masterPassword,
    el('escrow-confirm').value,
    MIN_MASTER_PASSWORD_LENGTH,
  );
  if (complaint) {
    message.textContent = complaint;
    message.classList.remove('ok');
    return;
  }

  // Another RSA keygen, another second of waiting to account for.
  message.textContent = 'Generating an escrow key…';
  message.classList.add('ok');
  const result = await withButtonDisabled(el('escrow-create-submit'), () =>
    chrome.runtime.sendMessage({ type: 'createEscrow', masterPassword }),
  );
  clearFields('escrow-new', 'escrow-confirm');

  if (!result?.ok) {
    message.classList.remove('ok');
    message.textContent = result?.error ?? 'Could not set up parent unlock.';
    return;
  }
  message.textContent = '';
  message.classList.remove('ok');
  await render();
});

el('escrow-import-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  const message = el('escrow-import-message');
  message.classList.remove('ok');

  let bundle;
  try {
    bundle = JSON.parse(el('escrow-import').value);
  } catch {
    message.textContent = 'That is not a valid escrow key.';
    return;
  }

  const result = await withButtonDisabled(el('escrow-import-submit'), () =>
    chrome.runtime.sendMessage({ type: 'importEscrow', bundle }),
  );
  if (!result?.ok) {
    message.textContent = result?.error ?? 'Could not install that escrow key.';
    return;
  }
  el('escrow-import').value = '';
  message.textContent = '';
  await render();
});

el('escrow-rotate-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  const message = el('escrow-rotate-message');
  const newPassword = el('escrow-rotate-new').value;

  const complaint = checkNewPassword(
    newPassword,
    el('escrow-rotate-confirm').value,
    MIN_MASTER_PASSWORD_LENGTH,
  );
  if (complaint) {
    message.textContent = complaint;
    message.classList.remove('ok');
    return;
  }

  const result = await withButtonDisabled(el('escrow-rotate-submit'), () =>
    chrome.runtime.sendMessage({
      type: 'changeMasterPassword',
      oldPassword: el('escrow-old').value,
      newPassword,
    }),
  );
  clearFields('escrow-old', 'escrow-rotate-new', 'escrow-rotate-confirm');

  if (!result?.ok) {
    message.classList.remove('ok');
    message.textContent = result?.error ?? 'Could not change the master password.';
    return;
  }
  message.textContent = 'Master password changed. Copy the key again to update other profiles.';
  message.classList.add('ok');
  showEscrow({ ...result, available: true, source: 'local', editable: true, keyId: result.bundle.keyId });
});

el('escrow-remove').addEventListener('click', async () => {
  const message = el('escrow-manage-message');
  const result = await withButtonDisabled(el('escrow-remove'), () =>
    chrome.runtime.sendMessage({ type: 'removeEscrow' }),
  );
  if (!result?.ok) {
    message.textContent = result?.error ?? 'Could not remove the escrow key.';
    return;
  }
  message.textContent = '';
  await render();
});

// --- render -----------------------------------------------------------------

async function render() {
  const status = await chrome.runtime.sendMessage({ type: 'status' });
  const configured = status?.configured === true;

  passwordSetup.hidden = configured;
  passwordChange.hidden = !configured;
  // Triggers are meaningless on a dormant profile: none of them can fire.
  triggers.hidden = !configured;

  showEscrow(status?.escrow);

  if (!configured) {
    el('setup-new').focus();
    return;
  }
  const result = await chrome.runtime.sendMessage({ type: 'getSettings' });
  if (result?.settings) showSettings(result.settings);
  await showShortcut();
}

// --- helpers ----------------------------------------------------------------

function clearFields(...ids) {
  for (const id of ids) el(id).value = '';
}

async function withButtonDisabled(button, work) {
  button.disabled = true;
  try {
    return await work();
  } finally {
    button.disabled = false;
  }
}

await render();
