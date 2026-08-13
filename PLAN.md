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
"permissions": ["storage", "tabs", "tabGroups", "idle", "alarms"]
```

No `host_permissions`. No `content_scripts`. No `notifications` (nothing needs to
notify). No `unlimitedStorage`.

Two corrections found in Phase 3:

- **There is no `"windows"` permission.** `chrome.windows` is available unconditionally,
  and `tabs` is what grants access to tab URLs through it. Chrome warns about unknown
  permission strings, so it was dropped rather than left as decoration.
- **`tabGroups` was added**, as anticipated: reading a group's name, color and collapsed
  state needs it, and Phase 3 restores all three. Group *membership* is visible via
  `tab.groupId` under `tabs` alone, which is why the engine degrades to ungrouped
  restore when the API is missing instead of failing.

`commands` (the keyboard shortcut) is a manifest key, not a permission, and adds no
prompt.

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
dataKey     = getRandomValues(32 bytes)                 // fresh per lock
wrap_pw     = RSA-OAEP(profileBundle.pub, dataKey)      // stored
```
WebCrypto only — `crypto.subtle`. No crypto-js, no MD5, no unsalted SHA-256.

**Implemented, with two changes from this plan:**

1. The stored password *verifier* was dropped. AES-GCM and RSA-OAEP are both
   authenticated, so a failed unwrap already signals a wrong password; a verifier would
   have doubled PBKDF2 cost per unlock for no information.
2. **`wrap_pw` is asymmetric, not `AES-GCM(kek, dataKey)`.** Found in Phase 2: locking
   must *encrypt* the snapshot, and the startup and idle triggers fire with no password
   present. A symmetric wrap would force the extension to hold the key while locked,
   which is the exact property §3 exists to prevent. §6 had already worked this out for
   the parent escrow — it applies to the profile's own password identically. The profile
   now gets its own key bundle (RSA keypair, private half sealed under the password), so
   both unlock paths are one mechanism. Cost: one ~1 s RSA keygen at setup; unlock cost
   unchanged.

See `architecture.md` §4.

Changing the password reseals the private key under a new `kek`. The keypair, and so
every existing wrap and the snapshot, are untouched.

**Stored on disk:** `wrap_pw` (`salt`, `iv`, `ct`, `iterations`), optional `wrap_master`
(§6), `version`.
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
wrong password — there is no verifier. 3. Exit protection mode, ~200ms settle.
4. Recreate windows with geometry → tabs with url/pinned/index → regroup tab groups.
5. Delete the ciphertext and both wraps, clear lock state, close the lock window.

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
but all state — the profile's key bundle, the encrypted snapshot and its wraps, settings,
backoff counters — lives in that profile's own store. Consequences:

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

**Implemented, with two corrections from this plan:**

1. **Removing escrow ends parent unlock for the session locked right now, too.**
   The first draft of it left `wrap_master` in place, reasoning that the dataKey was
   already encrypted to that public key. That is true and useless: unwrapping it needs
   the private key, which lives sealed *inside the bundle being removed*. So the wrap
   becomes unopenable by anyone, and leaving it on disk would be dead state that still
   looked like a recovery path (§9.5). It is cleared with the bundle. Nothing
   destructive results — `wrap_pw` and the ciphertext are untouched, so the owner's own
   password still opens the session.
2. **`manifest.json` needs a `storage.managed_schema`.** Chrome exposes no managed key
   that is not declared in a schema file, so without `managed-schema.json` the plist
   distribution path (§7) would have silently delivered nothing.

Also decided while building it: the master password has a **16-character minimum**,
against 8 for a profile password, because it is the one credential here that is both
offline-attackable and unlocks everything. The options page says why, and points at a
password manager rather than at memorability.

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

Chrome Sync does expose open tabs to the Google account
(`chrome://history/syncedTabs`), so the snapshot is not the only copy of a tab list in
existence. **Explicitly out of scope:** the concern here is a kid on this machine
opening my profile or a sibling's, not what a signed-in device elsewhere can see.

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
| ~~**1. Crypto core**~~ ✅ | `src/crypto.js`, `test/crypto.test.js`, `scripts/bench.js` | **Done.** 23 tests pass; 600k iterations measured at 644 ms; wrong password/master/tampering all raise `DecryptError`; password change rewraps without touching the ciphertext; escrow round-trips and rotation preserves existing wraps |
| ~~**2. Lock engine**~~ ✅ | `manifest.json`, `service_worker.js`, `lock-engine.js`, `storage.js`, `settings.js`, lock + popup pages, `test/lock-engine.test.js` | **Done.** 43 tests pass. Manual lock closes everything and unlock restores; disable-resistance verified explicitly — after a lock, no captured URL appears anywhere in storage, and a fresh runtime given only that storage cannot open the snapshot, destroys nothing trying, and still yields the session to the correct password. Backoff enforced, protection mode self-heals across a simulated worker death. Note: the crypto design changed here — see §3 |
| ~~**3. Fidelity + triggers**~~ ✅ | geometry, pinned, order, focus, tab groups; startup + idle + keyboard shortcut | **Done.** 49 tests pass. Groups restore with title, color and collapsed state, per window rather than merged; the window that had focus gets it back rather than the last one rebuilt; pinned tabs are never grouped (Chrome forbids it); a build without `chrome.tabGroups` still locks and restores. `commands` adds Cmd/Ctrl+Shift+L, dormant on an unconfigured profile; the idle threshold is reapplied on every worker start |
| ~~**4. UI + settings**~~ ✅ | options page, password setup/change, backoff UI | **Done.** 67 tests pass. Password setup and change both live in real `type="password"` fields — no `window.prompt` anywhere. A change reseals the private key and is asserted to leave the ciphertext and the wrap byte-identical, so a session locked under the old password opens under the new one. Settings save as they are edited and the page renders what was *stored*, not what was clicked, because `settings.js` clamps untrusted input; the idle threshold is pushed to `chrome.idle` on change as well as on worker start. The lock screen shows a live countdown during backoff, resumed from storage so a recreated lock window or a restarted worker doesn't hand back a form that would just be refused |
| ~~**4b. Parent escrow**~~ ✅ | keypair generation UI, `wrap_master`, "Parent unlock" on the lock screen, managed-storage read | **Done.** 81 tests pass. A master unlock restores the session and is asserted to leave the profile bundle byte-identical, so the owner's password keeps working; backoff covers the parent path, so it is not a way around a wait. The lock screen offers "Parent unlock" only when a `wrap_master` actually exists for *this* session — a session locked before escrow was set up cannot be opened by it, and advertising the option would be a lie. A managed bundle beats a locally installed one, so a child cannot shadow the parent's key with one whose password they chose, and under policy the profile cannot create, import, rotate or remove. `managed-schema.json` is what makes the plist path work at all: Chrome reads no managed key that is not declared. Two corrections found here — see §6 |
| ~~**5. Hardening**~~ ✅ | `src/messages.js`, storage-tamper review, CSP, error paths, `test/hardening.test.js` | **Done.** 102 tests pass. The router moved out of the service worker so the sender check is one testable entry point rather than a rule per handler, and the handler table got a null prototype so `{type:"constructor"}` finds nothing. Storage is now read as untrusted input throughout: a damaged profile bundle makes the profile dormant rather than half-configured, `isLocked`/`lockWindowId` are coerced, the backoff deadline is clamped to the policy ceiling, a malformed managed bundle no longer shadows a working local one, and malformed base64 surfaces as `DecryptError` like any other failed unwrap. CSP pins `script-src 'self'` and `connect-src 'none'`, which is the no-network invariant made enforceable. Two profiles lock and unlock independently with neither password opening the other and neither backoff touching the other, while a dormant third writes nothing at all. Two real bugs found here — see below |
| ~~**6. Distribution**~~ ✅ (build) | `scripts/keygen.js`, `scripts/pack.js`, `scripts/plist.js`, `scripts/lib/{zip,crx,release}.js`, `test/packaging.test.js`, `INSTALL.md` | **Built; the on-machine verification is still to do — see below.** 125 tests pass. `npm run pack` produces a signed CRX3 with no dependencies and no Chrome binary: the zip and the CRX3 header are written out, which is what lets the test verify the signature over the exact bytes Chrome checks, using a protobuf reader deliberately separate from the writer. The build is **reproducible** — sorted entries, fixed timestamps — so a shipped crx can be re-derived and compared, which is what turns §9.7 (pin and freeze) into something checkable. The packed file list is explicit rather than a directory walk, and a test fails if `src/` and the list ever disagree, so nothing ships or vanishes by accident. `npm run plist` emits the force-install entry and the escrow bundle under `3rdparty`, and on macOS the test runs the real `plutil` and asserts the bundle round-trips through Apple's own parser byte for byte — well-formed XML was never the question, delivering nested base64 intact was. The §9 cross-cutting rules also became tests here, swept over the files that are about to be frozen: no `innerHTML`, no `console.*`, no `chrome.storage.sync`, no `fetch`/`WebSocket`/inline script, and the CSP and permission list pinned |

**Phase 6's remaining work is not code.** Force-install, profile switching, restart
survival and managed-storage delivery are all statements about how a real Chrome on
this machine behaves, and none of them can be driven from a test. `INSTALL.md` carries
them as a six-step checklist to walk once, and it says plainly that it is unverified
until someone does.

### One trap Phase 6 found

**The signing key is the extension's identity, and losing it is worse than it
sounds.** Chrome derives the extension id from the key's public half, and the policy
names that id — so regenerating the key does not produce a new version of this
extension, it produces a *different* extension: new id, empty storage in every
profile, and any profile that happened to be locked left holding an encrypted
snapshot that no installed extension can open. That is the same shape as the failure
§3 accepts for a forgotten password, except it arrives by way of a build script
rather than a decision. `keygen` therefore refuses to overwrite an existing key, and
`INSTALL.md` leads with the consequence rather than burying it.

### Two bugs Phase 5 found

1. **A lock did not survive a browser restart the way it looked like it did.**
   `runtime.onStartup` swept with the `lockWindowId` written before Chrome closed —
   but window ids come from a counter that restarts with the browser, so that id
   very likely names one of the windows Chrome has just restored from the previous
   session. The sweep would spare it as the lock window, close everything else, and
   leave the profile sitting on its own tabs with no prompt in front of them. Now
   `resumeLock` drops the stale id first and the sweep builds a real lock window.
   This is the worst-shaped bug in the project so far: it fails open, and only on
   the path nobody watches.
2. **A corrupt ciphertext threw out of `unlock` instead of being refused.** Only
   the unwrap was inside the guard that turns `DecryptError` into a failed attempt;
   the snapshot decrypt that follows it was not, so an edited or truncated record
   reached the lock screen as an exception where it expects a refusal. Both steps
   are now one guarded block — which is also what architecture.md already said the
   UI must not distinguish.

## 9. Cross-cutting rules

1. Every `chrome.runtime.onMessage` handler validates `sender.id === chrome.runtime.id`
   and returns early otherwise — enforced in one place, `messages.js`, and tested. GoogleChromeProfileLock's `unlockProfile` took no
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
6. ~~Chrome Sync exposing tabs to other devices?~~ **Resolved: out of scope.** The
   threat is a kid on this machine opening another profile, not a remote signed-in
   device.
3. ~~Idle-lock default: on or off, and what delay?~~ **Resolved: on, at 600 s.** Dormancy
   (§6) is what makes an on-by-default trigger safe — the defaults only ever describe a
   profile whose owner deliberately set a password, and someone who does that wants the
   walk-away case covered. Startup locking stays **off**: it is the one trigger that can
   fire before you have done anything. Both are two clicks on the options page.

   Note the interaction with §10.5: `chrome.idle` treats the macOS screen lock as
   immediate, so this default makes screen-lock-triggered locking the common path — and
   that path still has no automated coverage.
4. ~~Should incognito windows be captured and restored?~~ **Resolved: closed and
   forgotten.** Capturing them into a record that outlives the session contradicts the
   point of incognito. Implemented in `captureSnapshot`.
5. Lock on system sleep/wake? `chrome.idle` covers screen lock via the `"locked"`
   state — handled, but **unverified on macOS**: the idle trigger has no automated
   coverage, since `chrome.idle` cannot be driven from a test.
