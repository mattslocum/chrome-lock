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
 */

const form = document.getElementById('unlock-form');
const input = document.getElementById('password');
const submit = document.getElementById('submit');
const message = document.getElementById('message');

/** Non-null while a countdown is running, so a second one cannot start. */
let countdownTimer = null;

form.addEventListener('submit', async (event) => {
  event.preventDefault();
  if (input.value === '' || countdownTimer !== null) return;

  setBusy(true);
  message.textContent = '';

  const result = await chrome.runtime.sendMessage({
    type: 'unlock',
    password: input.value,
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
  submit.textContent = busy ? 'Unlocking…' : 'Unlock';
}

// A backoff outlives this window: protection mode recreates the lock window if
// it is closed, and the worker is torn down constantly. Neither should hand back
// a form that looks ready when the next attempt would just be refused.
const status = await chrome.runtime.sendMessage({ type: 'backoffStatus' });
if (status?.retryAfterMs > 0) startCountdown(status.retryAfterMs);
else input.focus();
