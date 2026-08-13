# Chrome Lock — Implementation Plan

Own extension, written from scratch. Reference implementations live in `examples/`
(gitignored) with our analysis of each in `examples/*/architecture.md`.

---

## 0. Threat model — read this first, it drives every decision

**The environment:** a shared family computer, **one shared macOS login**, family
members separated only by Chrome profiles. No strangers, no motivated attacker, no one
with a forensics toolkit. The realistic risks are **accidental and snoopy**, not
aggressively malicious — someone wandering into the wrong profile, or idly reading
what's on screen. Nobody here is going to dump LevelDB or attach a debugger.

Calibrate accordingly: this should be frictionless and forgiving, and it must never do
anything destructive. Resisting a determined local attacker is explicitly out of scope,
and a shared macOS login means it was never achievable anyway.

**What we are actually protecting:** the contents of *my* Chrome profile — open tabs,
and by extension the browsing session — from being seen by whoever walks up next.

**What this can and cannot do:**

| Property | Achievable? |
|---|---|
| Blank the screen of open tabs when I walk away | ✅ Yes, reliably |
| Keep tabs unrecoverable if someone disables the extension | ✅ Yes — via encryption (§3) |
| Keep tabs unrecoverable if someone uninstalls the extension | ✅ Yes (they're gone for me too — accepted) |
| Stop someone from *disabling* the extension | ⚠️ Only with enterprise policy (§7) |
| Stop someone browsing my profile after disabling it (history, saved passwords, Gmail) | ❌ **No. Nothing an extension can do.** |

That last row is the honest limit, and with a shared macOS login it applies fully:
anyone who disables the extension is in my profile with my history, saved passwords,
and logged-in sessions. Force-installing via policy (§7) makes disabling meaningfully
harder — hard enough for "accidental and snoopy" — but it is not a boundary. Closing
that gap properly means separate macOS accounts, which is deliberately deferred.

**Design consequence:** the security goal is **tab-session confidentiality**, not
access denial. That reframing is what makes the "disable ≠ restore" requirement
achievable, and it's what all three reference extensions got wrong.

---

## 1. Requirements

### Must have
- Password-gated lock: snapshot all windows/tabs → close them → single lock window.
- **Disabling the extension must not restore tabs.** Only entering the correct
  password can decrypt the snapshot.
- Uninstalling loses the tabs permanently. Accepted.
- Lock triggers: manual (toolbar + keyboard shortcut), browser startup, idle timeout.
- Restore fidelity: URL, pinned, active, tab order, window geometry, tab groups.
- Zero network calls. No telemetry, no ads, no remote config, no host permissions.
- Zero runtime dependencies, no bundler, unminified source — the whole point is that
  I can read it and freeze it.
- **Per-profile independence.** One install serves every Chrome profile on the machine,
  but each profile has its own password and its own encrypted snapshot, with no way to
  read across profiles. See §6.
- **Dormant until configured.** A profile with no password set does nothing at all:
  no locking, no keyboard shortcut, no idle timer, no badge, no nag. See §6.

### Must not have
- No email/OTP recovery (BrowserLock's — reduces lock strength to my mailbox).
- No auto-reset-after-N-days (ChromeLock's — an unauthenticated bypass by design).
- No paywall, no license check, no `PRO99` (GoogleChromeProfileLock's backdoor).
- No `storage.sync` for anything credential- or session-adjacent.
- No content scripts. No `<all_urls>`. Overlay locks are cosmetic.

### Explicit non-goals
- Protecting against someone with the machine and motivation.
- Cross-device sync of any kind.

---

## 2. Permissions

```json
"permissions": ["storage", "tabs", "windows", "idle", "alarms"]
```

No `host_permissions`. No `content_scripts`. No `notifications` (nothing needs to
notify). No `unlimitedStorage`, `tabGroups` is folded into `tabs` for read;
`chrome.tabGroups` needs the `tabGroups` permission for group metadata — add it only
if we implement group name/color restore in Phase 3.

`"minimum_chrome_version"` pinned. `"incognito": "split"` so incognito windows are
handled explicitly rather than accidentally.

`chrome.storage.managed` needs no extra permission — it comes with `storage` — and is
how child profiles receive the parent escrow bundle (§6).

---

## 3. Crypto design — the core of the "disable ≠ restore" requirement

This is the part that differs fundamentally from all three references.

### Envelope encryption
The snapshot is encrypted under a random **data key**, and the data key is then wrapped
once per authorized unlock path. This indirection is what makes a master password (§6),
a recovery key, and password *changes* all possible without re-encrypting the snapshot.

```
dataKey     = getRandomValues(32 bytes)                 // per-profile, generated at setup
salt        = getRandomValues(16 bytes)                 // generated once at setup
kek         = PBKDF2(password, salt, 600_000, SHA-256)  → 256-bit AES-GCM key-encryption key
wrap_pw     = AES-GCM(kek, dataKey)                     // stored
verifier    = PBKDF2(password, salt2, 600_000, SHA-256) → stored, for a fast password check
```
Two independent derivations from separate salts so the stored verifier can't be used as
a key. WebCrypto only — `crypto.subtle`. No crypto-js, no MD5, no unsalted SHA-256.

Changing the password rewraps `dataKey` under a new `kek`; the snapshot is untouched.

**Stored on disk:** `salt`, `salt2`, `verifier`, `wrap_pw`, optional `wrap_master` and
`wrap_recovery` (§6), `iterations`, `version`.
**Never stored:** the password, the `dataKey` in the clear, the password length.

### Snapshot encryption
On lock:
1. Build the snapshot object (windows, tabs, groups).
2. `iv = getRandomValues(12)`; `ciphertext = AES-GCM(dataKey, iv, JSON(snapshot))`.
3. Write `{v, iv, ciphertext}` to `storage.local`. **Plaintext snapshot never
   touches disk.**
4. Zero the in-memory snapshot and drop the `dataKey` reference.

On unlock: unwrap `dataKey` via whichever path the user proved (password, master, or
recovery key) → decrypt → restore → delete ciphertext.

### Where does the key live while locked?
Nowhere. `dataKey` exists only between unwrapping and use; every wrap on disk requires
a secret the extension does not hold. The service worker may be terminated and
restarted arbitrarily while locked; it needs no secret to keep enforcing the lock, only
to end it. This is what makes disable-resistance work: **a disabled extension has no
key and no plaintext, so there is nothing to restore.**

### Consequences to accept
- Forget the password with no master or recovery wrap → tabs are unrecoverable, by
  construction. On child profiles the master wrap (§6) covers this.
- 600k PBKDF2 iterations ≈ 0.5–1s on this machine. Acceptable for an unlock; measure
  and tune in Phase 1 so it stays under ~1s.

---

## 4. Runtime architecture

```
service_worker.js        orchestration + message router (sender-validated)
  ├── lock-engine.js     snapshot / close / restore / protection mode
  ├── crypto.js          PBKDF2 + AES-GCM, no other callers touch subtle
  ├── storage.js         typed accessors over chrome.storage.local
  └── settings.js        defaults + validation

lock.html / lock.js      the lock window UI — password field, nothing else
popup.html / popup.js    Lock now / Settings
options.html / options.js  password setup + change, idle timeout, startup toggle
```

Plain ES modules, `"type": "module"` service worker. No framework. Target well under
1000 lines total (ChromeLock ships ~9 MB for ~50 KB of real logic; that's the
anti-pattern).

### Lock sequence
1. Validate: password is set, not already locked, trigger is enabled for this reason.
2. `windows.getAll({populate: true, windowTypes: ["normal"]})` + `tabGroups.query`.
   Filter out `chrome://`, `chrome-extension://`, `about:` — they don't restore anyway.
3. Encrypt and persist the snapshot (§3).
4. Create the lock window: `windows.create({url:"lock.html", type:"popup", focused:true})`,
   centered on the display, fixed size.
5. Close captured tabs, then captured windows.
6. Persist `{isLocked: true, lockedAt, reason, lockWindowId}` — unencrypted, it's not
   sensitive and the SW needs it on cold start.
7. Enter protection mode.

### Protection mode — keeping it locked
Borrowed from ChromeLock, which got this part right, minus its unreliable `setInterval`:
- `windows.onCreated` → if it isn't the lock window, `windows.remove()` it.
- `tabs.onCreated` → same.
- `windows.onRemoved` → if the lock window was closed, recreate it.
- `windows.onFocusChanged` → refocus the lock window.
- `chrome.alarms` sweep every 1 min (MV3 minimum for packed extensions) calling
  `closeNonLockWindows()` as a backstop.

**Why not `setInterval`:** the MV3 service worker is terminated after ~30s idle;
ChromeLock's 2-second interval silently stops. Event listeners wake the worker, so
they are the real enforcement — the alarm is belt-and-braces. GoogleChromeProfileLock
was the only one of the three to get this right.

Guard flags `isRestoring` / `isCreatingLockWindow` suppress the reaper during
legitimate transitions (both ChromeLock and we need this).

### Unlock
1. Rate-limit check (§5). 2. Derive key, decrypt snapshot; failure to decrypt *is* a
wrong password — no separate verifier comparison needed, though we keep the verifier
for a fast pre-check and clear error messaging. 3. Exit protection mode, ~200ms settle.
4. Recreate windows with geometry → tabs with url/pinned/index → regroup tab groups.
5. Delete the ciphertext, clear lock state, close the lock window.

---

## 5. Failed attempts

Family threat model, so keep it humane: exponential backoff rather than a punitive
lockout, and **never** a destructive response. BrowserLock wipes cookies/saved
passwords/history after N wrong guesses, driven entirely by locally-editable state —
that's a footgun aimed at the user, not a security feature. We do not do that.

Backoff: 3 free attempts, then delay `min(2^(n-3) seconds, 5 min)`, persisted with a
timestamp so restarting the browser doesn't reset it. No counter that wipes anything.

---

## 6. Multi-profile model, dormancy, parent escrow, and recovery

### One install, N independent locks
`chrome.storage.local` is **scoped per Chrome profile**. The extension binary is shared
across every profile on the machine (and force-install in §7 applies to all of them),
but all state — `salt`, `salt2`, `verifier`, the encrypted snapshot, settings, backoff
counters — lives in that profile's own store. Consequences:

- Every family member sets **their own password**, independently, on first use.
- No profile can read or decrypt another profile's state using its own password. This
  is a property of Chrome's storage isolation, not something we implement — but we must
  not undermine it, which is one more reason nothing goes in `storage.sync` (rule §9.3:
  `storage.sync` is keyed to the *Google account*, which several profiles could share).
- The **one** deliberate exception is the parent master password (below), which unwraps
  any profile's data key. Nothing else crosses the profile boundary.
- A password change in one profile has no effect on any other.

### Dormant until configured
Because the extension lands on profiles whose owners never asked for it, "no password
set" must mean **fully inert**:

- No lock on startup, no idle timer registered, no keyboard shortcut handler.
- No badge, no notification, no auto-opened options page on install, no review nag.
  (BrowserLock opens a web page on install *and* update; ChromeLock opens a
  remote-configured `tutorialUrl`. We open nothing, ever.)
- The toolbar popup shows a single "Set up a password" affordance and nothing else.
- Uninstalling or ignoring it costs a dormant profile exactly nothing.

Setup is therefore fully self-service per profile: click the icon, set a password, done.

### Parent escrow — the master password

**Goal:** one master password I know, which can unlock any child profile so I can help
when they forget theirs. Children keep their own passwords private from me and from
each other.

**The constraint that shapes the design:** a child's profile must be able to escrow its
`dataKey` to me *at lock time*, without ever holding the master password. Symmetric
crypto can't do that — the child would need the master key to encrypt with it. So the
escrow is **asymmetric**, and this is the one place the project needs public-key crypto.

#### Setup (once, by me)
```
{pub, priv}  = RSA-OAEP-3072 / SHA-256 keypair            // via crypto.subtle.generateKey
mSalt        = getRandomValues(16 bytes)
mKek         = PBKDF2(masterPassword, mSalt, 600_000, SHA-256)
privWrapped  = AES-GCM(mKek, pkcs8(priv))
escrowBundle = {pub, privWrapped, mSalt, iterations, keyId, version}
```
`escrowBundle` contains **no plaintext secret** — the private key is encrypted under the
master password — so it is safe to distribute to every profile on the machine.

#### Distribution
Preferred: **`chrome.storage.managed`**, populated from the same macOS managed-preferences
plist used for force-install (§7), under the extension's `3rdparty` policy key. Managed
storage is read-only to the extension and unwritable by the children, which is exactly
right. Fallback for development: paste the bundle into the options page.

#### Per-lock (in a child profile)
Alongside `wrap_pw`, store `wrap_master = RSA-OAEP(pub, dataKey)` plus `keyId`. The
child profile only ever touches the public key.

#### Parent unlock (on the child's lock screen)
1. Choose "Parent unlock" → enter master password.
2. `mKek = PBKDF2(masterPassword, mSalt, …)` → unwrap `priv` → `RSA-OAEP-decrypt(priv, wrap_master)` → `dataKey`.
3. Decrypt the snapshot and restore as normal.
4. Restore, and stop there. **A master unlock never forces a password reset.** The
   profile's existing `wrap_pw` is untouched and their old password keeps working — the
   common case is "they forgot it in the moment", not "the password is lost forever".
   Setting a new password is a separate, explicitly-chosen action in the options page,
   available to the profile owner and to a master unlock alike; it rewraps `dataKey`
   under the new password and leaves `wrap_master` alone.

#### Rules
- **Escrow is enabled on every profile, including mine.** I'd rather have one master
  password that covers everything, forgotten-password included, than an un-escrowed
  profile that can strand me. Accepted consequence: the master password becomes a
  single point of failure for the whole machine, so **it should be the strongest
  password in this system** — see the note on offline attack below.
- **Escrow is visible, not covert.** The child's lock screen shows the "Parent unlock"
  option, and the options page states plainly that a parent can unlock this profile.
  These are kids, not adversaries — this is a help mechanism, and building it as a
  hidden backdoor would be both a betrayal and, once discovered, a much bigger problem
  than a forgotten password. Design it as the openly-labeled feature it is.
- **Be clear-eyed about what it grants:** parent unlock reveals the child's open tabs.
  That is inherent to restoring their session, and it's the honest cost of the feature.
- **The master password is offline-attackable, unlike the per-profile ones.**
  `privWrapped` sits in managed storage readable by every profile, so anyone on the
  machine could copy it and grind PBKDF2 against it without tripping our backoff. The
  per-profile passwords have the same exposure in principle, but the master password now
  unlocks *everything*, so make it long and random — passphrase from a manager, not
  something memorable-and-short. This is the one credential in the system where the
  threat model's "accidental and snoopy" framing is worth ignoring.
- Backoff (§5) applies to master-password attempts too, per profile — useful against
  guessing at the lock screen, though it does nothing about the offline path above.
- If the master password is ever changed, `privWrapped` is rewrapped and redistributed;
  `pub` and every existing `wrap_master` stay valid. Losing the master password only
  costs the escrow path, not the children's own passwords.
- `keyId` lets a future keypair rotation coexist with old wraps.

**Decided:** asymmetric master password, escrow on all profiles including mine, and a
master unlock never resets anything.

### Recovery — decided: none

**No printed recovery key, no second backstop.** The master password is the only
recovery path, and losing it means every profile's locked tab session is gone.

That's acceptable because of what is actually at stake. This is Chrome with a Google
account: bookmarks, history, saved passwords, and extensions all live in the Google
account, not in our encrypted blob. The only thing our snapshot holds is **one
ephemeral tab session**. Losing the master password is no worse than losing the
computer — and materially less bad, since everything durable is already backed up.

So there are exactly two unlock paths per profile: the profile's own password, and the
master password. `wrap_pw` and `wrap_master`, nothing else.

Not doing: security questions (ChromeLock MD5s the answer), email OTP, or timed
auto-reset. All three are unauthenticated-bypass shaped.

**Caveat worth verifying in Phase 3 — Chrome Sync cuts both ways here.** Chrome syncs
open tabs to the Google account (`chrome://history/syncedTabs`, visible from any signed-in
device). Two consequences: (a) a forgotten master password may not actually be fatal,
since the tab list might be recoverable from another device, and (b) more importantly,
our snapshot's confidentiality is only as good as that sync surface. Closing the tabs
should push an empty tab list for the device, but **confirm what a second signed-in
device shows while a profile is locked** — if the pre-lock tab list lingers there, the
encryption is doing less work than it appears to.

---

## 7. Installation — and yes, there *is* a way to do it machine-wide

The assumption that this must be installed per-profile is not quite right. Chrome
enterprise policy on macOS applies to **all Chrome profiles for a given macOS user**,
and force-installed extensions **cannot be disabled or removed from
`chrome://extensions`**. That directly upgrades our weakest property.

- Machine-wide, all macOS users: `/Library/Managed Preferences/com.google.Chrome.plist`
- **Per macOS user:** `/Library/Managed Preferences/<username>/com.google.Chrome.plist`

Since we share one macOS login, either path installs it for **every Chrome profile on
the machine**. That's acceptable and arguably good: force-installed extensions can't be
disabled, which is precisely the protection we want, and the dormancy rule (§6) means
profiles that never set a password are unaffected. The social cost is that family
members can't remove it either — worth a heads-up to them rather than a surprise.

Cost: force-install requires a packed `.crx` and a hosted `update.xml` (GitHub Pages
is sufficient — it's the only network dependency in the whole project, and it's
install-time infrastructure, not runtime). Note that force-install also means *I*
can't disable it without editing the plist as admin — which is the point.

**Phasing:** develop as unpacked (`chrome://extensions` → Load unpacked), which is
per-profile and fine. Move to the policy install once the extension is stable.

---

## 8. Build phases

| Phase | Deliverable | Done when |
|---|---|---|
| **1. Crypto core** | `crypto.js` + tests | Envelope encryption round-trips: `dataKey` wrapped/unwrapped under a password; iteration count tuned to <1s; wrong password fails cleanly; password change rewraps without touching the ciphertext |
| **2. Lock engine** | manifest, SW, lock/unlock, encrypted snapshot | Manual lock closes everything, unlock restores; disabling the extension while locked leaves tabs unrecoverable — **verify this explicitly** |
| **3. Fidelity + triggers** | geometry, pinned, order, tab groups; startup + idle + keyboard shortcut | Restored session is visually indistinguishable from the original |
| **4. UI + settings** | options page, password setup/change, backoff UI | Can set and change a password without ever seeing it in a `window.prompt` |
| **4b. Parent escrow** | keypair generation UI, `wrap_master`, "Parent unlock" on the lock screen, managed-storage read | Master password unlocks any profile including mine; the profile's own password still works afterward (no forced reset); escrow is visibly labeled |
| **5. Hardening** | sender validation audit, storage-tamper review, CSP, error paths, multi-profile test | Every `onMessage` handler checks `sender.id === chrome.runtime.id`; SW crash while locked recovers to a locked state; two profiles with different passwords lock/unlock independently and a dormant third profile stays silent |
| **6. Distribution** | pack CRX, host `update.xml`, write the managed-preferences plist incl. the escrow bundle | Survives a Chrome restart and a profile switch; cannot be disabled from `chrome://extensions`; child profiles pick up the escrow bundle from managed storage automatically |

## 9. Cross-cutting rules

1. Every `chrome.runtime.onMessage` handler validates `sender.id === chrome.runtime.id`
   and returns early otherwise. GoogleChromeProfileLock's `unlockProfile` took no
   password and validated no sender; BrowserLock accepts an unauthenticated
   `{type:"unlock"}`. Both are the same bug.
2. No `innerHTML` anywhere. `textContent` and DOM construction only.
3. Nothing sensitive in `storage.sync`.
4. No `console.log` in shipped code (BrowserLock ships `"CML registered!!!"` and a
   notification with the id `"dsadsa"`).
5. No dead state, no placeholder URLs (BrowserLock writes `open_after: ["https://x.com"]`
   on every lock and never reads it).
6. Every file readable top-to-bottom by a human in one sitting. If a bundler ever
   becomes necessary, the unminified source ships alongside.
7. Pin and freeze: once stable, tag the version, keep the CRX, and never auto-update
   from anything I don't control. This is the original motivation for the project.

## 10. Open questions

1. ~~Separate macOS accounts?~~ **Resolved:** no, one shared login, staying that way
   for now. This is a speed bump against accidental/snoopy access, not a boundary (§0).
2. ~~Master password vs. printed recovery keys?~~ **Resolved:** asymmetric master
   password, escrowed on all profiles including mine, never forcing a password reset,
   and **no recovery key of any kind** (§6). Two unlock paths, that's it.
6. **Does a second signed-in device still show the pre-lock tab list while a profile is
   locked?** (§6 caveat) Determines whether Chrome Sync quietly undercuts the snapshot
   encryption. Verify in Phase 3.
3. Idle-lock default: on or off, and what delay? Suggest on at 10 min, matching
   ChromeLock's `idleLockDelay: 600`, but that one defaults it off.
4. Should incognito windows be captured and restored, or just closed and forgotten?
   Forgetting is arguably more correct for incognito's semantics.
5. Lock on system sleep/wake? `chrome.idle` covers screen lock via the `"locked"`
   state — probably sufficient, verify on macOS.
