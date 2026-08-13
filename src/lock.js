/**
 * The lock window. One password field; the service worker does everything else.
 *
 * This page holds no key material and makes no crypto calls — it hands the
 * password to the worker and reports back what happened. On success the worker
 * restores the session and closes this window, so there is no success path to
 * render here.
 */

const form = document.getElementById('unlock-form');
const input = document.getElementById('password');
const submit = document.getElementById('submit');
const message = document.getElementById('message');

form.addEventListener('submit', async (event) => {
  event.preventDefault();
  if (input.value === '') return;

  setBusy(true);
  message.textContent = '';

  const result = await chrome.runtime.sendMessage({
    type: 'unlock',
    password: input.value,
  });

  input.value = '';

  if (result?.ok) return; // the worker is closing this window
  setBusy(false);
  message.textContent = describe(result);
  input.focus();
});

function describe(result) {
  if (!result) return 'Something went wrong. Try again.';
  if (result.retryAfterMs > 0) {
    return `${result.error} (${formatDelay(result.retryAfterMs)})`;
  }
  return result.error ?? 'Incorrect password';
}

function formatDelay(ms) {
  const seconds = Math.ceil(ms / 1000);
  if (seconds < 60) return `wait ${seconds}s`;
  return `wait ${Math.ceil(seconds / 60)} min`;
}

function setBusy(busy) {
  submit.disabled = busy;
  input.disabled = busy;
  submit.textContent = busy ? 'Unlocking…' : 'Unlock';
}
