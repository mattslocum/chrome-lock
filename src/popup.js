/**
 * The toolbar popup. Two states: dormant (offer setup) and configured (offer a
 * lock). Password setup lives here rather than behind a window.prompt, so the
 * field is a real password input and the value never renders.
 */

const setup = document.getElementById('setup');
const ready = document.getElementById('ready');
const setupForm = document.getElementById('setup-form');
const newPassword = document.getElementById('new-password');
const confirmPassword = document.getElementById('confirm-password');
const setupSubmit = document.getElementById('setup-submit');
const setupMessage = document.getElementById('setup-message');
const lockNow = document.getElementById('lock-now');
const readyMessage = document.getElementById('ready-message');

const status = await chrome.runtime.sendMessage({ type: 'status' });
show(status?.configured ? ready : setup);
if (!status?.configured) newPassword.focus();

setupForm.addEventListener('submit', async (event) => {
  event.preventDefault();
  setupMessage.textContent = '';

  if (newPassword.value.length < 8) {
    setupMessage.textContent = 'Use at least 8 characters.';
    return;
  }
  if (newPassword.value !== confirmPassword.value) {
    setupMessage.textContent = 'The two passwords do not match.';
    return;
  }

  // The RSA keygen is about a second of work, and this is the only place the
  // user waits on it — better to say so than to look like the click was ignored.
  setupMessage.textContent = 'Setting up…';
  setupSubmit.disabled = true;
  const result = await chrome.runtime.sendMessage({
    type: 'setUpPassword',
    password: newPassword.value,
  });
  setupSubmit.disabled = false;
  newPassword.value = '';
  confirmPassword.value = '';

  if (result?.ok) {
    setupMessage.textContent = '';
    show(ready);
    return;
  }
  setupMessage.textContent = result?.error ?? 'Could not set the password.';
});

for (const button of [document.getElementById('setup-settings'), document.getElementById('ready-settings')]) {
  button.addEventListener('click', () => {
    chrome.runtime.openOptionsPage();
    window.close();
  });
}

lockNow.addEventListener('click', async () => {
  lockNow.disabled = true;
  const result = await chrome.runtime.sendMessage({ type: 'lock' });
  if (result?.ok) {
    window.close();
    return;
  }
  lockNow.disabled = false;
  readyMessage.textContent = result?.error ?? 'Could not lock.';
});

function show(section) {
  setup.hidden = section !== setup;
  ready.hidden = section !== ready;
}
