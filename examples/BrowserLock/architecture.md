# Browser Lock — Extension Architecture Analysis

Analysis of the packaged Chrome extension in `BrowserLock/` (v2.0.4, author `humbldump`,
Web Store ID `nldijlfmoepgjkjhmdiiainkjgmpdnmj`). All source here is **minified production
output**; findings below come from reverse-reading the Vite bundles. Nothing outside this
directory was examined.

---

## 1. What it is

A Manifest V3 extension that "locks" the browser behind a password. Locking works by
**snapshotting every open window/tab, closing them all, and opening a single small popup
window containing a password prompt**. Unlocking re-creates the saved windows and tabs.
There is no OS-level or native component — the lock is entirely a Chrome-extension
behavior.

## 2. File inventory

| Path | Role |
| --- | --- |
| [manifest.json](manifest.json) | MV3 manifest, v2.0.4 |
| [service-worker-loader.js](service-worker-loader.js) | 1-line shim importing the SW chunk |
| [screen.html](screen.html) | Single HTML host for **all** UI (options page, popup, lock screen) |
| [assets/serviceWorker.ts-dkP9bq6a.js](assets/serviceWorker.ts-dkP9bq6a.js) | 6 KB — background event wiring |
| [assets/BLLock-n8n7x0Gc.js](assets/BLLock-n8n7x0Gc.js) | 309 KB — shared core: config, storage, lock engine, i18n, crypto-js, lodash, dayjs |
| [assets/screen.html-7a5JuVXO.js](assets/screen.html-7a5JuVXO.js) | 707 KB — React app: router, Redux store, settings shell, lock screen, API client |
| [assets/SettingPage-…js](assets/SettingPage-k6PzefmW.js) | Lazy route — settings form |
| [assets/PasswordPage-…js](assets/PasswordPage-YXm9jNKt.js) | Lazy route — change password |
| [assets/ValidateMail-…js](assets/ValidateMail-5O1lc65j.js), [ChangeMail-…js](assets/ChangeMail-_uG3ole5.js) | Lazy routes — email verify / change |
| [assets/Tooltip-…js](assets/Tooltip-5cPG5x-B.js) | Shared UI chunk |
| `_locales/{en,es,tr}/messages.json` | Manifest-level strings only (10 keys); app strings are bundled in JS |
| `_metadata/` | Web Store treehash signatures — confirms an unmodified store download |
| `chrome.crx` (1.4 MB) | The original packed CRX, shipped alongside the unpacked files |

Tech stack: **Vite + React 18 + Redux Toolkit + react-router (hash routing) + Mantine +
PrimeReact + Tailwind + i18next + zod + axios + dayjs + lodash + crypto-js + Iconify**.
The UI framework weight (two component libraries) dominates the bundle size.

## 3. Manifest surface

- **Permissions (granted at install):** `notifications`, `tabs`, `windows`, `storage`,
  `unlimitedStorage`, `tabGroups`, `contextMenus`, `idle`
- **Optional (requested in-app):** `history`, `background`, `browsingData` — `browsingData`
  is requested by the quarantine "clear history" toggle
  ([SettingPage.js](assets/SettingPage-k6PzefmW.js)); `background` by the "run in
  background" toggle. `history` is listed but no `chrome.history` call appears in the bundles.
- **Host permissions:** `https://*.browserlock.io/*` only. No content scripts, no
  `<all_urls>`, no `webRequest`, no remote code loading (all JS is local).
- **Command:** `Ctrl+M` / `Cmd+M` → lock now.
- `options_page: screen.html`, `default_popup: screen.html#/ppup`.

## 4. Runtime topology

```
service-worker-loader.js
   └─ serviceWorker chunk ──imports──▶ BLLock core (lock engine + storage)
                                            ▲
screen.html ──▶ screen.html chunk ──────────┘   (same module, separate context)
      ├─ #/         options / settings shell
      ├─ #/pwd      the lock screen (rendered in the popup window)
      ├─ #/ppup     toolbar popup (2 buttons: Lock now, Open settings)
      ├─ #/change-password, #/mail/change, #/mail/validate
```

`screen.html` is reused for three very different surfaces, differentiated only by the hash
route. The lock screen and the settings page therefore share one bundle.

### Service worker responsibilities
([serviceWorker.ts-dkP9bq6a.js](assets/serviceWorker.ts-dkP9bq6a.js))

- **Bootstrap** (`y()`): hydrate storage, register context menus, clear stale
  notifications, register all listeners, run the "extension not activated yet" check.
- **Context menus:** Browser Lock → Lock Browser → Lock now; Open settings.
- **Commands:** `lock_browser_now_fixed` → `lockTheBrowser("manual")` (gated on
  `setting.short_cut_lock.active`).
- **Idle:** `chrome.idle.setDetectionInterval(idle_mode.duration × 60)`. On `idle`, if no
  tab is audible, optionally notify, then lock after a fixed 5 s timeout. On `active`,
  cancel.
- **Tabs:** `onCreated` — while locked, any tab created outside the lock popup window is
  immediately removed. This is the containment mechanism.
- **Windows:** `onCreated` — while locked, a notification says a new window can't be
  opened (note: it *notifies* but does not close the window); while unlocked, triggers
  `lockTheBrowser("auto")`. `onRemoved` — clears the popup reference and resets
  `auto_locked` when the last window closes.
- **Install/update/uninstall:** opens the options page, and opens
  `browserlock.io/installed/{welcome,update}?extid=<runtime id>`; sets an uninstall URL of
  `browserlock.io/installed/uninstall`.
- **Startup:** `chrome.runtime.onStartup` → `lockTheBrowser("auto")`.

## 5. State model

Two persisted stores, both **JSON strings** written into Chrome storage, plus a Redux
mirror in the UI.

### `chrome.storage.local` → `mainStorage` (`Te` in BLLock)
```js
{
  device_id,                    // HmacMD5(Math.random(), "device_id") — generated once
  identity: { name, surname, email, email_verified_at, email_changed_at, phone },
  security: {
    active, attempt, attempted,
    hard_locked, hard_locked_at, hard_locked_open_at,
    browser_password: { password, length, changed_at }   // password = SHA256 hex
  },
  setting: {
    dark, security_mode: "quarantine", language, active,
    auto_lock:      { active, start_state: "restore"|"new_tab"|"url", start_url, run_in_background },
    idle_mode:      { active, duration: 6, notify },
    short_cut_lock: { active, combination },
    quarantine_mode:{ active, hard_lock_duration: 1, max_attempts: 5,
                      clear_history, clear_options: {cookies,passwords,downloads,formData,history},
                      clear_duration, notify }
  },
  misc: { do_not_notify_install, registered }
}
```
Also `tempStorage: { notified: [] }` tracking outstanding notification IDs.

A `chrome.storage.local.onChanged` listener keeps the SW copy in sync; if `mainStorage` is
deleted it is restored from the old value (a mild anti-tamper measure).

### `chrome.storage.session` → `sessionStorage` (`Pe`)
```js
{ lock: { initial_locked, auto_locked, locked, locked_at, unlocked_at,
          locked_reason: "manual"|"auto"|"init",
          popup,               // the chrome.windows.Window of the lock screen
          stored_windows: [],  // full snapshot incl. tabs + tab groups
          open_after: [] } }
```
Session storage clears on browser restart, which is why `onStartup` re-locks.

### Redux (`screen.html` chunk)
`combineReducers({ mainStorage, sessionStorage, clientStorage })`. The `mainStorage` slice's
reducers (`update`, `updateSetting`, `updateSecurity`, `updateIdentity`, `wrongAttempt`,
`clearQuarantine`) each perform a `chrome.storage.local.set` **inside the reducer** — a
side effect in a place Redux expects purity.

## 6. Lock / unlock engine (`BLLock`, `ea`/`B` export)

**`lockTheBrowser(reason)`**
1. Refresh both stores; if already locked and the popup window still exists, no-op.
2. Abort (with a "not active" notification) if `setting.active !== true` or no password set.
3. For `reason === "auto"`, abort if already auto-locked or auto-lock disabled.
4. `getOpenedTabs()` — enumerate all windows, tabs and tab groups, bucketing tabs into
   `nonTabGroupedTabs` and `tabGroups`.
5. Open the lock popup: `chrome.windows.create({type:"popup", 712×616, url:"screen.html#/pwd"})`.
6. Write the snapshot to session storage.
7. Close every tab, then every window.

**Unlock** — the lock screen ([`#/pwd`](screen.html)) compares
`SHA256(input) === security.browser_password.password`:
- Match → dispatch `clearQuarantine`, call `unlockTheBrowser()`.
- Mismatch → dispatch `wrongAttempt` (see quarantine below).

**`unlockTheBrowser()`** flips session state, runs `unlockStrategy()`, then closes the popup.
`unlockStrategy()`: if the lock was `auto` and `auto_lock.start_state` is `new_tab` or
`url`, open a fresh window (optionally at `start_url`) and **discard the snapshot**;
otherwise `reOpenClosedWindows()` re-creates each window, re-creates tabs (preserving
`url` and `pinned`), and regroups grouped tabs via `chrome.tabs.group`.

Unlock can also be triggered by a `{type:"unlock"}` runtime message (see §8).

## 7. Quarantine ("hard lock")

In the `wrongAttempt` reducer ([screen.html chunk ~line 37599](assets/screen.html-7a5JuVXO.js)):
- Increment `security.attempt`.
- At `attempt >= quarantine_mode.max_attempts`: set `hard_locked = true`,
  `hard_locked_at = now`, `hard_locked_open_at = now + hard_lock_duration` minutes, and
  show a red notification. The lock screen renders a countdown from
  `hard_locked_open_at` and refuses to evaluate passwords while hard-locked.
- If `clear_history` is on and the `browsingData` permission has been granted, calls
  `chrome.browsingData.remove({since: now − clear_duration days}, clear_options)` — i.e. a
  **punitive wipe of cookies / saved passwords / downloads / form data / history** on
  repeated wrong guesses. This is the most destructive behavior in the extension and is
  driven entirely by locally-stored, user-editable state.

## 8. Backend integration

Config: `service_base_url: "https://api.browserlock.io"`, `api_path: "/api/v2/bl"`.
Axios client with a thin `get`/`post` wrapper (`Ec`) that normalizes errors — note a
hardcoded Turkish fallback string, `"Bir Hata Oluştu"`.

| Endpoint | Payload | Used by |
| --- | --- | --- |
| `POST /api/v2/bl/email/validate` | `{email, device_id}` | Email verification |
| `POST /api/v2/bl/email/check` | — | declared, used in mail flows |
| `POST /api/v2/bl/otp/password-forget` | `{email, device_id}` | "Forgot password" — sends OTP |
| `POST /api/v2/bl/otp/otp-check` | `{email, device_id, otp}` | On success the client sets a **new local password hash** |
| `POST /api/v2/bl/contact/store` | contact form + `device_id` | Support form |
| `GET /api/v2/bl/messages` | — | In-app message/announcement feed |
| `/captcha/api/{flat,math,default}` | — | Captcha endpoints |

No telemetry beyond `device_id` accompanying these explicit user-initiated calls, and no
browsing data is transmitted. The password hash itself is never sent to the server.

## 9. i18n

Two parallel systems: `chrome.i18n` + `_locales/` for the 10 manifest-visible strings, and
**i18next with `tr`/`en`/`es` catalogs compiled into the JS bundle** for the app UI
(including zod validation messages). Language is picked from
`chrome.i18n.getUILanguage()` with a hardcoded mapping — only exact `es-ES` maps to
Spanish, so `es-MX`, `es-AR` etc. fall back to English. Turkish is matched on `tr` only.

## 10. Observations, weaknesses and bugs

**Security**

1. **Unsalted, single-round SHA-256** for the password
   ([PasswordPage.js:1122](assets/PasswordPage-YXm9jNKt.js), [screen.html chunk:39015](assets/screen.html-7a5JuVXO.js), verification at :40094). crypto-js, not WebCrypto;
   no PBKDF2/scrypt/Argon2 despite crypto-js's PBKDF2 being present in the bundle. A short
   password is trivially recovered from the stored hash by rainbow table.
2. **The hash lives in `chrome.storage.local` in plaintext JSON.** Anyone with filesystem
   access to the profile can read it, and — more importantly — can **overwrite it**, or
   simply set `setting.active = false`, to defeat the lock. `hard_locked`/`attempt` are
   equally editable, so quarantine is bypassable by editing storage.
3. **`browser_password.length` stores the plaintext password length**, an unnecessary hint.
   Worse, in the OTP reset path ([screen.html chunk:39758](assets/screen.html-7a5JuVXO.js))
   `length` is assigned `u.values.password_section.new_password` — **the plaintext password
   itself is written to disk**, not its length. This looks like a copy-paste bug and is the
   most serious concrete defect found.
4. **Password reset requires only email OTP.** Anyone who controls the registered mailbox
   can reset the browser lock. That is a reasonable product tradeoff, but it means the lock
   is only as strong as the email account.
5. The lock is a UI convention, not a security boundary: disabling the extension, launching
   Chrome with a different profile/`--disable-extensions`, or opening the profile directory
   all bypass it entirely. Reasonable for a "keep family members out" tool; not a threat
   model that survives an attacker with local admin.

**Correctness / robustness**

6. **Unauthenticated unlock message.** `chrome.runtime.onMessage` accepts
   `{type:"unlock"}` and unlocks without any credential check
   ([BLLock ~17600](assets/BLLock-n8n7x0Gc.js)). No `externally_connectable` is declared, so
   web pages can't reach it — but any other installed extension able to message this one,
   or any devtools console in an extension page, can unlock the browser. There is also a
   second, do-nothing `onMessage` listener registered in the service worker that logs and
   replies `{status:"ok"}`.
7. **Window creation while locked is only notified, not prevented.** `onCreated` for
   windows shows a notification; only *tabs* are force-closed. The new empty window itself
   persists.
8. **Hardcoded `open_after: ["https://x.com"]`.** Every lock overwrites `open_after` with
   `["https://x.com"]` ([BLLock:17473](assets/BLLock-n8n7x0Gc.js)). Meanwhile the install/update
   handlers push the welcome/update URLs into that same array. **`open_after` is never read
   anywhere in the bundle** — so it is dead state, but the literal `x.com` is a leftover
   that would look alarming to a reviewer and would open x.com if the feature were ever wired up.
9. **Snapshot loss on the `new_tab`/`url` unlock strategy.** If auto-lock's start state is
   `new_tab` or `url`, `stored_windows` is silently discarded — the user's entire session is
   gone. Combined with the snapshot living in `chrome.storage.session`, a browser crash or
   restart while locked also permanently loses all tabs. There is no `local` backup of the
   snapshot.
10. **Tab restore is lossy by design:** only `url` and `pinned` survive. History within a
    tab, scroll position, form state, tab order relative to groups, window geometry, and
    group names/colors on the created group are not restored.
11. **Debug/placeholder code shipped to production:** `console.log("CML registered!!!")`,
    `console.log("Quarantine Mode Enabled!!")`, a notification created with the literal id
    `"dsadsa"` and the message `"BrowserLock is now active"` fired on *every unlock*, a
    debug `"popup is null"` notification, and a support email (`humbldump@pm.me`) embedded
    in an error toast.
12. **Idle lock uses a fixed 5-second grace** regardless of the configured warning; the
    notification claims `duration: 5` via interpolation, so at least they agree.
13. `device_id` is `HmacMD5(Math.random(), …)` — not cryptographically random and not
    unique-by-construction; fine as a loose analytics key, unsuitable as an identifier the
    backend trusts.
14. **Side effects inside Redux reducers** (`chrome.storage.local.set`) make the store
    non-replayable and will misbehave under React StrictMode double-invocation.
15. `idle.setDetectionInterval` is called with `duration || 1` minutes but the registration
    reads `idle_mode.active !== false`, so idle detection registers even when the default
    config has `idle_mode.active = false` — the default object sets `active: !1` while the
    guard is a `!== false` check on a possibly-undefined path. Worth verifying against real
    behavior.
16. The `history` optional permission is declared but never requested or used.
17. Two full component libraries (Mantine + PrimeReact) plus lodash and crypto-js are
    bundled, producing a ~1 MB JS payload for what is functionally a password box and a
    settings form.

## 11. Summary judgment

Architecturally the extension is clean and conventional for MV3: a thin event-driven
service worker, one shared core module holding the lock state machine and storage
abstraction, and a React SPA reused across three surfaces via hash routes. Backend contact
is minimal, scoped to `browserlock.io`, and limited to user-initiated email/OTP/support
flows — there is no data exfiltration and no remote code.

The weaknesses are in the security model rather than the structure: a single-round unsalted
SHA-256 hash sitting in world-readable, world-writable extension storage means the lock
deters casual snooping only, and the plaintext-password-into-`length` bug in the OTP reset
path should be treated as a real defect. The session-snapshot-in-`storage.session` design
is the other significant risk, since it turns a crash while locked into total tab loss.
