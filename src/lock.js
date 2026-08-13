/**
 * The lock window. One password field; the service worker does everything else.
 *
 * This page holds no key material and makes no crypto calls — it hands the
 * password to the worker and reports back what happened. On success the worker
 * restores the session and closes this window, so there is no success path to
 * render here.
 *
 * The backoff after wrong guesses is shown as a live countdown rather than a
 * silent refusal. It is deliberately a wait and never anything destructive, so
 * the honest thing is to say how long it is and let it run down on screen.
 *
 * Parent unlock is the second of exactly two unlock paths, and it is offered
 * here in plain sight. A master unlock restores the session and stops there — it
 * does not reset or reveal the profile's own password, which keeps working.
 */

const form = document.getElementById('unlock-form');
const input = document.getElementById('password');
const submit = document.getElementById('submit');
const message = document.getElementById('message');
const prompt = document.getElementById('prompt');
const toggleMode = document.getElementById('toggle-mode');

/** Non-null while a countdown is running, so a second one cannot start. */
let countdownTimer = null;

/** 'password' — this profile's own — or 'master', the parent escrow key. */
let mode = 'password';

const COPY = {
  password: {
    prompt: 'Enter your password to restore your tabs.',
    placeholder: 'Password',
    submit: 'Unlock',
    toggle: 'Parent unlock',
    autocomplete: 'current-password',
  },
  master: {
    prompt: 'Enter the parent master password. This restores the tabs that were open, and leaves this profile’s own password unchanged.',
    placeholder: 'Master password',
    submit: 'Unlock as parent',
    toggle: 'Use my own password',
    autocomplete: 'off',
  },
};

toggleMode.addEventListener('click', () => {
  mode = mode === 'password' ? 'master' : 'password';
  applyMode();
  // A backoff is per profile and covers both paths, so switching modes must not
  // look like a way out of one.
  if (countdownTimer === null) input.focus();
});

function applyMode() {
  const copy = COPY[mode];
  prompt.textContent = copy.prompt;
  input.placeholder = copy.placeholder;
  input.autocomplete = copy.autocomplete;
  input.value = '';
  submit.textContent = copy.submit;
  toggleMode.textContent = copy.toggle;
  message.textContent = countdownTimer === null ? '' : message.textContent;
}

form.addEventListener('submit', async (event) => {
  event.preventDefault();
  if (input.value === '' || countdownTimer !== null) return;

  setBusy(true);
  message.textContent = '';

  const result = await chrome.runtime.sendMessage({
    type: 'unlock',
    password: input.value,
    via: mode,
  });

  input.value = '';

  if (result?.ok) return; // the worker is closing this window

  setBusy(false);
  if (result?.retryAfterMs > 0) {
    startCountdown(result.retryAfterMs);
    return;
  }
  message.textContent = result?.error ?? 'Incorrect password';
  input.focus();
});

/**
 * Hold the form closed for `ms`, ticking once a second. Reads the clock rather
 * than counting ticks, so a throttled or suspended page resumes at the right
 * number instead of drifting slower than the real wait.
 */
function startCountdown(ms) {
  const resumeAt = Date.now() + ms;

  input.disabled = true;
  submit.disabled = true;

  const tick = () => {
    const remaining = resumeAt - Date.now();
    if (remaining <= 0) {
      clearInterval(countdownTimer);
      countdownTimer = null;
      message.textContent = '';
      input.disabled = false;
      submit.disabled = false;
      input.focus();
      return;
    }
    message.textContent = `Too many attempts. Try again in ${formatDelay(remaining)}.`;
  };

  countdownTimer = setInterval(tick, 1000);
  tick();
}

function formatDelay(ms) {
  const seconds = Math.ceil(ms / 1000);
  if (seconds < 60) return `${seconds}s`;
  const minutes = Math.ceil(seconds / 60);
  return `${minutes} min`;
}

function setBusy(busy) {
  submit.disabled = busy;
  input.disabled = busy;
  submit.textContent = busy ? 'Unlocking…' : COPY[mode].submit;
}

// The parent option appears only when a master password could actually open
// *this* session. A session locked before escrow existed carries no wrap_master,
// and offering a path that cannot work would be worse than not offering it.
const status = await chrome.runtime.sendMessage({ type: 'status' });
toggleMode.hidden = status?.escrow?.canUnlockNow !== true;

// A backoff outlives this window: protection mode recreates the lock window if
// it is closed, and the worker is torn down constantly. Neither should hand back
// a form that looks ready when the next attempt would just be refused.
const backoff = await chrome.runtime.sendMessage({ type: 'backoffStatus' });
if (backoff?.retryAfterMs > 0) startCountdown(backoff.retryAfterMs);
else input.focus();
