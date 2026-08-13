# Chrome Lock

A password lock for a Chrome profile. Locking snapshots every open window and tab,
**encrypts** the snapshot, closes everything, and leaves a single popup holding a
password prompt. Entering the password decrypts the snapshot and restores the session —
windows, geometry, tab order, pinned tabs, tab groups.

Manifest V3. No dependencies, no build step, no network calls, ~2,400 lines of readable
ES modules.

## Why this exists

The Chrome Web Store has several profile-lock extensions. I read three of them
carefully before writing this one, and they all share the same defect: **the "locked"
session sits in plaintext on disk.** Disable the extension from `chrome://extensions`
and your tabs come right back. The lock is a screen, not a lock.

The other things I found in them, all real, all shipping:

- MD5 of a security answer as the recovery mechanism
- unsalted SHA-256, and base64 used as though it were hashing
- an `unlock` message handler that takes no password and validates no sender
- a timed auto-reset — an unauthenticated bypass, on by default
- wiping your cookies, saved passwords, downloads, and history after N wrong guesses,
  driven entirely by locally-editable state
- remote config, review nags, a page opened on every install *and* update

So: this one. The security goal is **tab-session confidentiality**, and the design
target is that disabling the extension does not get the tabs back.

## How it gets that property

Each lock generates a fresh random data key, encrypts the snapshot under it with
AES-GCM, then wraps that data key with an RSA-OAEP **public** key and wipes it. Locking
touches public keys only, so the extension holds no secret while locked and needs none
to keep enforcing the lock. Unwrapping requires your password, which is never stored:
the RSA private key is sealed under PBKDF2-SHA-256 at 600,000 iterations (~640 ms per
unlock — tuned to a budget, since it's the only thing between a copied storage file and
an offline grind).

The plaintext snapshot never touches disk. A disabled extension holds no key and no
plaintext — there is nothing to restore and nothing to leak. There is no stored password
verifier; both primitives are authenticated, so a failed unwrap *is* the wrong-password
signal.

Failed attempts get exponential backoff (3 free, then `min(2^(n-3) s, 5 min)`, persisted
across restarts) with a live countdown. Never anything destructive.

## Features

- **Triggers**: toolbar button, keyboard shortcut (Cmd/Ctrl+Shift+L), idle timeout
  (on by default, 10 min, includes OS screen lock), and browser startup (opt-in).
- **Protection mode**: while locked, new windows and tabs are closed, the lock window is
  recreated if you close it, and focus is pulled back to it. Driven by events (which
  wake a terminated MV3 worker) with a 1-minute alarm as a backstop.
- **Multi-profile**: one install serves every Chrome profile on the machine, each with
  its own password and its own encrypted snapshot. Nothing goes in `storage.sync`.
- **Parent escrow** (optional): one master password that can unlock any profile, so a kid
  who forgets theirs isn't stranded and doesn't have to hand over their password. Each
  lock wraps the data key a second time under an escrow public key. It's deliberately
  *visible*, not covert — the lock screen names the option and the options page says
  plainly that a parent can unlock this profile.
- **Dormant until configured**: a profile with no password set is completely inert. No
  triggers, no badge, no notification, no page opened on install or update, ever.
- **Force-install support**: build a signed CRX and a macOS policy plist, so the
  extension can't be removed from `chrome://extensions` and the escrow key is delivered
  to every profile automatically.

## What it does not do

An extension cannot gate access to the Chrome profile itself. With one shared OS login,
anyone who manages to disable Chrome Lock is sitting in that profile with its history
and saved passwords — they just can't get the locked tab session back. Force-install
makes disabling hard; it doesn't make it impossible. Closing that gap properly means
separate OS accounts.

**Saved passwords are covered only while the extension is running, and only by closing
the window.** Protection mode reaps any new window or tab regardless of URL, so opening
`chrome://password-manager` while locked closes it right away — same mechanism as any
other tab, no special case. But that is reactive, not preventive: the window exists for
the moment between `windows.onCreated` firing and the removal landing, which is long
enough for a glance at the list of *sites*. Revealing an actual stored password needs OS
authentication (Touch ID or your login password on macOS), and that is Chrome's barrier,
not this extension's — turn it on. Autofill is a non-issue while locked for the same
reason the tab is: there is no page open to fill into.

The threat model is a shared family computer and risks that are **accidental and
snoopy** — someone wandering into your profile or reading what's on screen — not a
motivated local attacker. Judge it against that.

Also: lose both your password and the master password and that tab session is gone
permanently. Bookmarks, history, saved passwords and extensions live in your Google
account, so the snapshot only ever holds one ephemeral session.

## Install

Development:

```sh
git clone https://github.com/<you>/chrome-lock
# chrome://extensions → Developer mode → Load unpacked → this directory
```

Then click the toolbar icon and set a password (8-character minimum).

For the real install — force-installed by macOS policy, with parent escrow — see
[INSTALL.md](INSTALL.md).

## Build and test

```sh
npm test          # 125 tests, node:test, no dependencies
npm run bench     # measure PBKDF2 cost on this machine
npm run keygen    # signing key (this key is the extension's identity — back it up)
npm run pack      # → dist/chrome-lock-<version>.crx + update.xml
npm run plist     # → dist/com.google.Chrome.plist
```

The CRX build is **reproducible** — same sources and key give the same bytes — so a
published hash is checkable rather than a matter of trust. The packed file list is
explicit in `scripts/lib/release.js` rather than a directory walk, and a test fails if
it drifts from `src/`. Adding a file to a force-installed extension should be a visible
line in a diff.

## Design notes

[architecture.md](architecture.md) is the real documentation: threat model, the
cryptographic design and why it's asymmetric, restore fidelity, storage-as-untrusted-input,
the escrow model, and the project invariants (no `innerHTML`, no `console.*`, no
`storage.sync`, no network calls at runtime — several of them enforced by CSP and swept
by the packaging tests). [PLAN.md](PLAN.md) has the build sequencing and the comparison
against the reference implementations.

## Permissions

`storage`, `tabs`, `tabGroups`, `idle`, `alarms`. No `host_permissions`, no content
scripts, and `connect-src 'none'` in the CSP so the browser itself refuses any network
call this extension might ever try to make.

## License

MIT
