# Chrome Lock — Architecture

The design of *this* extension. For build sequencing, decisions-in-progress, and the
comparison against the three reference implementations, see [PLAN.md](PLAN.md); for the
analyses those decisions came from, see `examples/*/architecture.md` (gitignored).

---

## 1. What it is

A Manifest V3 extension that locks a Chrome profile behind a password. Locking
snapshots every open window and tab, **encrypts** the snapshot, closes everything, and
leaves a single popup window holding a password prompt. Entering the password decrypts
the snapshot and restores the session.

One install serves every Chrome profile on the machine. Each profile has its own
password and its own encrypted snapshot. A single parent **master password** can unlock
any profile, via asymmetric key escrow.

No network calls. No content scripts. No dependencies. No build step.

## 2. Threat model

A shared family computer, one macOS login, family members separated only by Chrome
profiles. The realistic risks are **accidental and snoopy** — a kid wandering into a
sibling's profile or mine, or reading what's on screen. Not a motivated local attacker.

What the design does and does not achieve:

| | |
|---|---|
| Blank the screen of open tabs when I walk away | ✅ |
| Keep tabs unrecoverable if the extension is disabled | ✅ — §4 |
| Keep profiles isolated from each other | ✅ — §6 |
| Let a parent help a kid who forgot their password | ✅ — §7 |
| Prevent someone *disabling* the extension | ⚠️ Only under enterprise policy — §8 |
| Prevent browsing a profile after disabling it | ❌ Not achievable by an extension |

That last row is the standing limit. An extension cannot gate access to the profile
itself; with a shared macOS login, anyone who disables it is in that profile with its
history and saved passwords. Force-install (§8) makes disabling hard enough for this
threat model. Closing the gap properly means separate macOS accounts, deliberately
deferred.

**The security goal is therefore tab-session confidentiality, not access denial.** That
reframing is what makes "disabling must not restore tabs" achievable, and it is the
thing all three reference extensions got wrong — each leaves the full browsing session
in plaintext on disk while claiming to protect it.

## 3. Components

```
service_worker.js       orchestration, message router, lifecycle
  ├── lock-engine.js    snapshot / close / restore / protection mode
  ├── crypto.js         PBKDF2, AES-GCM, RSA-OAEP — sole caller of crypto.subtle
  ├── escrow.js         master-key bundle: read, validate, wrap
  ├── storage.js        typed accessors over chrome.storage.local
  └── settings.js       defaults and validation

lock.html    / lock.js        lock window — password field, parent-unlock option
popup.html   / popup.js       toolbar — Lock now / Settings, or first-run setup
options.html / options.js     password setup and change, triggers, escrow status
```

Plain ES modules; `"type": "module"` service worker. No framework, no bundler,
unminified. Target is comfortably under 1000 lines total — the reference point being
ChromeLock, which ships ~9 MB for roughly 50 KB of real logic.

**Permissions:** `storage`, `tabs`, `windows`, `idle`, `alarms`. No `host_permissions`,
no `content_scripts`. `chrome.storage.managed` (§7) needs no separate permission.
`"incognito": "split"`; `"minimum_chrome_version"` pinned.

## 4. Cryptographic design

The core of the disable-resistance requirement, and the part that differs most from
every reference implementation.

### Envelope encryption

The snapshot is encrypted under a random **data key**; the data key is then wrapped once
per authorized unlock path. That indirection is what lets a master password, and
password *changes*, exist without ever re-encrypting the snapshot.

```
dataKey = getRandomValues(32)                          per profile, created at setup
salt    = getRandomValues(16)                          fresh per wrap
kek     = PBKDF2(password, salt, 600_000, SHA-256)     key-encryption key

wrap_pw     = AES-GCM(kek, dataKey)                    {v, salt, iv, ct, iterations}
wrap_master = RSA-OAEP(escrowPublicKey, dataKey)       {v, keyId, ct}  — §7
```

WebCrypto exclusively — no crypto-js, no MD5, no unsalted SHA-256, no base64-as-hashing.
(Respectively: ChromeLock, ChromeLock, BrowserLock, GoogleChromeProfileLock.)

**There is no stored password verifier.** Earlier drafts derived one from a second salt
as a fast pre-check. It turned out to be redundant *and* costly: AES-GCM is
authenticated, so a failed unwrap already is the wrong-password signal, while a separate
verifier would double the PBKDF2 work on every unlock to learn something the unwrap
tells us anyway. One derivation, one authenticated unwrap.

600,000 iterations measured at **644 ms** per unlock on this machine (`npm run bench`),
inside the ~1 s budget. That cost is the only thing standing between a copied storage
file and an offline password grind, so it is tuned to the budget rather than minimized.

### Snapshot lifecycle

On lock: build the snapshot → `iv = getRandomValues(12)` →
`ciphertext = AES-GCM(dataKey, iv, JSON(snapshot))` → write `{v, iv, ciphertext}` →
drop the plaintext and the key reference. **The plaintext snapshot never touches disk.**

On unlock: unwrap `dataKey` via whichever path the user proved → decrypt → restore →
delete the ciphertext. A fresh IV per encryption keeps reuse of one `dataKey` across
many locks safe.

### Why disabling the extension cannot restore tabs

`dataKey` exists only in memory, only between unwrapping and use. Every wrap on disk
requires a secret the extension does not hold. The service worker is terminated and
restarted freely while locked; it needs no secret to *keep* enforcing the lock, only to
*end* it. So a disabled extension holds no key and no plaintext — there is nothing to
restore, and nothing to leak.

Changing a password rewraps `dataKey` under a new `kek`, leaving the ciphertext and
`wrap_master` untouched.

### Accepted consequences

- Losing both a profile password and the master password loses that tab session,
  permanently. Acceptable: bookmarks, history, saved passwords and extensions live in
  the Google account, so the snapshot holds only one ephemeral session.
- 600k PBKDF2 iterations cost roughly 0.5–1 s per unlock. Tuned in Phase 1 to stay
  under ~1 s.

## 5. Lock engine

### Lock sequence

1. Validate: password set, not already locked, this trigger enabled.
2. `windows.getAll({populate: true, windowTypes: ["normal"]})`, plus tab groups.
   Discard `chrome://`, `chrome-extension://`, `about:` — they do not restore anyway.
3. Encrypt and persist (§4).
4. Create the lock window: `windows.create({url: "lock.html", type: "popup", focused: true})`,
   centered, fixed size.
5. Close captured tabs, then captured windows.
6. Persist `{isLocked, lockedAt, reason, lockWindowId}` — unencrypted; not sensitive, and
   the worker needs it on cold start.
7. Enter protection mode.

### Protection mode

Adapted from ChromeLock, the one thing it got right, minus its unreliable `setInterval`:

- `windows.onCreated` / `tabs.onCreated` → anything that isn't the lock window is removed.
- `windows.onRemoved` → if the lock window closed, recreate it.
- `windows.onFocusChanged` → refocus the lock window.
- `chrome.alarms` sweep every 1 min (the MV3 minimum) as a backstop.

**Events are the real enforcement; the alarm is belt-and-braces.** An MV3 service worker
is terminated after ~30 s idle, so ChromeLock's 2-second `setInterval` silently stops —
but incoming events wake the worker, which makes the listener path self-healing.
`isRestoring` / `isCreatingLockWindow` guards suppress the reaper during legitimate
transitions.

### Unlock

Rate-limit check → unwrap `dataKey` → exit protection mode → ~200 ms settle → recreate
windows with geometry, then tabs with url/pinned/index, then regroup tab groups → delete
ciphertext, clear lock state, close the lock window.

A failed unwrap *is* a wrong password — `crypto.js` surfaces it as `DecryptError`, and
the UI must not distinguish "wrong password" from "corrupt record" to the user beyond
what that error carries.

### Triggers

| Trigger | Mechanism |
|---|---|
| Manual | toolbar popup, and a keyboard shortcut via `commands` |
| Startup | `runtime.onStartup` |
| Idle | `idle.onStateChanged`, including the `locked` state (macOS screen lock) |

### Failed attempts

Exponential backoff, never anything destructive: 3 free attempts, then
`min(2^(n-3) s, 5 min)`, persisted with a timestamp so restarting Chrome doesn't reset
it. Applies to master-password attempts too, per profile.

Explicitly **not** BrowserLock's model, which wipes cookies, saved passwords, downloads
and history after N wrong guesses — driven entirely by locally-editable state. That is a
footgun aimed at the user, not a security feature.

## 6. Multi-profile model

`chrome.storage.local` is scoped per Chrome profile. The binary is shared across every
profile on the machine; all state — salts, verifier, wraps, ciphertext, settings, backoff
counters — is per-profile.

- Each family member sets their own password, independently, on first use.
- No profile can read or decrypt another using its own password. This is Chrome's
  storage isolation, not something we implement — but we must not undermine it, which is
  one more reason nothing goes in `storage.sync` (which is keyed to the *Google account*,
  potentially shared across profiles).
- The single deliberate exception is the master password (§7).

### Dormant until configured

The extension lands on profiles whose owners never asked for it, so "no password set"
means **fully inert**: no startup lock, no idle timer, no shortcut handler, no badge, no
notification, no auto-opened page on install or update, no review nag. The popup shows
one "Set up a password" affordance. Ignoring it costs a dormant profile nothing.

(BrowserLock opens a web page on install *and* update; ChromeLock opens a
remote-configured `tutorialUrl` and nags for a review after 5 locks. We open nothing,
ever.)

## 7. Parent escrow

**Goal:** one master password that can unlock any profile, so a kid who forgets theirs
isn't stranded and doesn't have to share their password with me.

**The constraint that dictates the design:** a profile must escrow its `dataKey` *at
lock time*, when the master password is not present. Symmetric crypto cannot do this —
the profile would need the master key in order to encrypt with it, which means storing
it, which defeats the purpose. Hence asymmetric. This is the only public-key crypto in
the project.

### Setup, once

```
{pub, priv} = RSA-OAEP-3072 / SHA-256                   crypto.subtle.generateKey
mSalt       = getRandomValues(16)
mKek        = PBKDF2(masterPassword, mSalt, 600_000, SHA-256)
privWrapped = AES-GCM(mKek, pkcs8(priv))

escrowBundle = {pub, privWrapped, mSalt, iterations, keyId, version}
```

The bundle carries no plaintext secret — the private key is encrypted under the master
password — so it is safe to distribute to every profile.

### Distribution

`chrome.storage.managed`, populated from the same macOS managed-preferences plist used
for force-install (§8), under the extension's `3rdparty` key. Managed storage is
read-only to the extension and unwritable by the kids. Development fallback: paste the
bundle into the options page.

### At lock time

Store `wrap_master = RSA-OAEP(pub, dataKey)` alongside `wrap_pw`, plus `keyId`. The
profile only ever handles the public half.

### Parent unlock

"Parent unlock" on the lock screen → master password → `mKek` → unwrap `priv` →
RSA-decrypt `wrap_master` → `dataKey` → decrypt and restore.

**It restores and stops.** A master unlock never resets a password: `wrap_pw` is
untouched and the profile's own password keeps working, because the common case is
"forgot it in the moment", not "lost forever". Setting a new password is a separate,
explicitly chosen action available to the profile owner and to a master unlock alike.

### Properties

- **Escrow is enabled on every profile, including mine.** One master password covering
  everything, forgotten-password included, beats an un-escrowed profile that can strand
  me.
- **The master password is a single point of failure, and is offline-attackable.**
  `privWrapped` sits in managed storage readable by every profile, so it can be copied
  and ground against PBKDF2 where our backoff cannot see it. It must be long and random,
  from a password manager — the one credential where "accidental and snoopy" is worth
  ignoring.
- **Escrow is visible, not covert.** The lock screen shows the parent-unlock option and
  the options page states plainly that a parent can unlock this profile. These are kids,
  not adversaries; a hidden parental backdoor discovered later is a worse problem than
  any forgotten password.
- **It reveals the profile's open tabs.** Inherent to restoring a session, and the
  honest cost of the feature.
- Rotating the master password rewraps `privWrapped` and redistributes; `pub` and every
  existing `wrap_master` stay valid. `keyId` lets a future keypair coexist with old wraps.

### No other recovery path

Two wraps per profile, `wrap_pw` and `wrap_master`, and nothing else. No printed
recovery key, no security questions (ChromeLock MD5s the answer), no email OTP
(BrowserLock — reduces the lock to the strength of a mailbox), no timed auto-reset
(ChromeLock, on by default — an unauthenticated bypass by design).

## 8. Installation

Chrome enterprise policy on macOS applies to **all Chrome profiles for a macOS user**,
and force-installed extensions **cannot be disabled or removed** from
`chrome://extensions`. That directly addresses the weakest property in §2.

- Machine-wide: `/Library/Managed Preferences/com.google.Chrome.plist`
- Per macOS user: `/Library/Managed Preferences/<username>/com.google.Chrome.plist`

With one shared login, either installs for every profile — acceptable, and desirable,
since dormancy (§6) means profiles that never set a password are unaffected. The social
cost is that family members can't remove it either; that warrants a heads-up rather than
a surprise.

Requires a packed `.crx` and a hosted `update.xml`. That is the project's only network
dependency, and it is install-time infrastructure, not runtime. Development uses
unpacked loading, which is per-profile.

## 9. Invariants

1. Every `runtime.onMessage` handler validates `sender.id === chrome.runtime.id` and
   returns early otherwise. GoogleChromeProfileLock's `unlockProfile` took no password
   and validated no sender; BrowserLock accepts an unauthenticated `{type:"unlock"}`.
   Same bug, twice.
2. No `innerHTML`. `textContent` and DOM construction only.
3. Nothing sensitive in `storage.sync`.
4. No `console.log` in shipped code.
5. No dead state and no placeholder URLs. (BrowserLock writes
   `open_after: ["https://x.com"]` on every lock and never reads it.)
6. No network calls at runtime, ever. No telemetry, no remote config, no ads on the lock
   screen.
7. Every file readable top-to-bottom in one sitting. If a bundler ever becomes
   necessary, unminified source ships alongside.
8. Once stable: tag it, keep the CRX, and never auto-update from anything I don't
   control. That is the original motivation for the project.
