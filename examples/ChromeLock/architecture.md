# Chrome Lock — Architecture Analysis

Analysis of the unpacked extension in `ChromeLock/` (Chrome Web Store build, MV3).

| | |
|---|---|
| Name | `Chrome Lock \| Browser Password Lock Extension - ChromeLock.net` |
| Version | 3.28.5 |
| Extension ID | `dfncaoemjmmnbcfldoochfgkhenhegjl` (internal `EXTENSION_IDSTR: "BL"`) |
| Manifest | v3, ES-module service worker |
| Permissions | `storage`, `tabs`, `windows`, `idle` — no host permissions, no content scripts |
| Homepage / API | `https://chromelock.net` / `https://platform.chromelock.net` |
| Origin | Signed CWS package (`_metadata/verified_contents.json`, `key` pinned in manifest) |

---

## 1. What it actually does

A browser-level screen lock. On lock it snapshots every open normal window/tab, closes them all, and leaves a single 480×720 popup window (`lock.html`) on screen. It then actively kills any new window or tab the user opens until the correct password is entered, at which point the saved windows/tabs are restored.

There is also a second, mostly independent subsystem: an account/token client and a server-driven promotion (ad) delivery system, talking to `platform.chromelock.net` over a deliberately obfuscated wire protocol.

---

## 2. File layout

Directory and file names are **intentionally misleading**. Nothing named `webgl`, `physics`, `canvas`, `parser`, or `scheduler` does what its name says; the hash suffixes are also fake (five different files all carry the suffix `7bfeabe5` and have five different MD5s).

### Live code — only 5 JS + 4 CSS files are ever loaded

| Entry point | File | Role |
|---|---|---|
| `background.service_worker` | `services/task/controller.7bfeabe5.js` (1.2 MB) | All logic: lock engine, storage, API client, promo engine |
| `action.default_popup` → `popup.html` | `components/form/shell.7bfeabe5.js` (1.9 MB) | Popup UI (Lock / Settings / Account tabs) |
| `lock.html` | `drivers/pool/gateway.7bfeabe5.js` (1.9 MB) | Lock screen UI |
| `options.html` | `core/runtime/manager.7bfeabe5.js` (1.9 MB) | Options page |
| `lib/codec/feedback.html` | `lib/stream/collector.7bfeabe5.js` (1.9 MB) | Feedback page (not referenced by the manifest; opened by URL) |

Stack: **Vue 3 + Element Plus**, webpack + Babel + core-js 3.32.1, `webextension-polyfill` (`globalThis.browser`), `crypto-js`, `pako` (gzip).

Each of the four UI bundles is a full standalone build — Vue and Element Plus are duplicated four times. Roughly 7.5 MB of the ~9 MB package is redundant framework code.

### Dead weight — 17 JS files and 4 CSS files with zero references

Not in the manifest, not in any HTML, not imported by any live bundle. Each is an IIFE wrapped in a swallowing `try {}`:

```
components/form/controls.a5599f76.js      Tetris board renderer
components/panel/builder.74e10a36.js      2D canvas compositor
components/widget/factory.34657ce1.js     audio spectrum visualizer
core/runtime/context.7de50705.js          audio mixer channels
core/scheduler/worker.30888c2a.js         audio chorus/flanger DSP
drivers/cache/resolver.6bd0553c.js        Minesweeper state machine
drivers/canvas/renderer.b2ea28c2.js       spring/particle physics
drivers/parser/scanner.64eedea0.js        Minesweeper difficulty config
drivers/pool/allocator.b15cc508.js        undo/redo stack
drivers/webgl/adapter.151d8e04.js         particle attractors
lib/codec/decoder.6d94b1c8.js             synth note/frequency tables
lib/math/vector.3fdf274a.js               3D vector math
lib/physics/simulator.a4e8d48a.js         easing function tables
lib/stream/buffer.62c78bf8.js             LFO generator
services/queue/handler.25247596.js        Tetris piece definitions
services/state/manager.d5ac47bc.js        Tetris scoring rules
services/task/executor.fbb90c28.js        Tetris/matrix utility library
components/layout/{grid,flex}.css, components/theme/{base,dark}.css
```

The same filler is also *inlined into the live bundles* — the service worker and all four UI bundles contain Tetris scoring, flocking, and WebGL strings that no code path reaches. The four loaded CSS files each begin with several hundred KB of synth/particle CSS before the real Element Plus rules.

This is padding designed to bury ~50 KB of real logic in ~9 MB of plausible-looking noise, and to defeat naive static review.

---

## 3. Lock engine (service worker)

Three collaborating objects: a **state manager** (storage), a **window manager** (tab/window control), and a **controller** (message handling + orchestration).

### Lock sequence — `lockBrowser(reason)`

1. `validateLockConditions(reason)` — must be initialized (password set), not already locked; for `auto`/`startup` reasons the corresponding setting must be enabled.
2. `captureCurrentState()` — `windows.getAll({populate:true, windowTypes:["normal"]})` + `tabs.query({})`, filtering out `chrome-extension://`, `chrome://`, `edge://`, `about:`. Records per tab: `url`, `title`, `pinned`, `active`, `index`, `windowId`; per window: geometry and focus.
3. Persist that snapshot to `browser_lock_saved_state`.
4. `createLockWindow()` — `windows.create({url: lock.html, type:"popup", width:480, height:720, focused})`, centered. Not focused when the reason is `idle`.
5. `closeAllTabs()` then `closeAllWindows()` for everything captured.
6. Persist `{isLocked, lockTime, reason, lockWindowId}`.
7. `enableProtectionMode()`.

### Protection mode — how it stays locked

- `windows.onCreated` → `handleNewWindow`: if the new window contains `lock.html`, adopt it as the lock window; otherwise `windows.remove()` it immediately. If no lock window exists any more, recreate one.
- `tabs.onCreated` → `handleNewTab`: same treatment.
- A `setInterval` **every 2 seconds** runs `closeNonLockWindows()`, removing every window whose id ≠ `lockWindowId`. This is the belt-and-braces sweep that catches anything the event listeners miss.

Guard flags `isRestoring` / `isCreatingLockWindow` suppress the reaper during legitimate transitions.

### Unlock — `unlockBrowser(password)`

Rejects if `isTemporarilyLocked()`. Verifies the hash; on failure `recordFailedAttempt()` increments the counter and, at **3 failures, sets `lockedUntil = now + 5 minutes`**. On success: disable protection mode → 200 ms settle delay → clear lock state → restore saved windows and tabs (or open a fresh window if nothing was saved).

### Lock triggers

| Trigger | Mechanism | Reason string |
|---|---|---|
| Popup button | `lock:lock-browser` message | `manual` |
| Keyboard | `commands.onCommand` — `Alt+Shift+L` (`Cmd+Shift+L` on macOS) | `shortcut` |
| Browser start | `runtime.onStartup`, gated on `autoLockOnStartup` (default **on**) | `startup` |
| Idle | `idle.onStateChanged`, detection interval 600 s; gated on `idleLockEnabled` (default off, `idleLockDelay` 600 s) | `idle` |

### Message bus

Single `runtime.onMessage` router keyed on string constants. Lock namespace: `lock:get-status`, `lock:get-info`, `lock:get-settings`, `lock:save-settings`, `lock:set-password`, `lock:change-password`, `lock:lock-browser`, `lock:unlock`, `lock:set-security-question`, `lock:verify-security`, `lock:reset-password`, `lock:trigger-auto-reset`, `lock:cancel-auto-reset`, `lock:perform-auto-reset`, `lock:open-url-after-unlock`. Plus `api:*`, `promo:*`, `review:*`, `ensure-initialized`, `refresh-data`, `open-new-tab`, `get-page-info`.

Every handler returns `{success, message, timestamp, ...extra}` via `createResponse()`.

---

## 4. Storage schema (`chrome.storage.local`)

Lock keys (`browser_lock_*`):

| Key | Shape |
|---|---|
| `browser_lock_settings` | `{autoLockOnStartup: true, idleLockEnabled: false, idleLockDelay: 600, autoResetDays: 3}` |
| `browser_lock_password_hash` | **MD5 hex string** |
| `browser_lock_security_question` | `{question, answerHash}` — answer is trimmed then MD5'd |
| `browser_lock_security` | `{failedAttempts, lockedUntil, lastFailTime, hasSecurityQuestion}` |
| `browser_lock_state` | `{isLocked, lockTime, reason, lockWindowId}` |
| `browser_lock_saved_state` | full window/tab snapshot incl. every URL and title |
| `browser_lock_auto_reset` | `{triggeredAt, expiresAt}` |
| `browser_lock_reset_confirm` | `{needsConfirm, timestamp}` |

Account/promo keys: `xAuth` (bearer token), `tokenTime`, `userInfo`, `dock`, `promotions`, `anonymousCode`, `workCount`, `reviewShown`.

`anonymousCode` is a locally generated 32-char random hex string (`Math.random()`-based, not a device fingerprint), created on first login and persisted.

---

## 5. Password and recovery model

```js
md5Hash(t)          { return CryptoJS.MD5(t).toString() }
hashPassword(t)     { return this.md5Hash(t) }
verifyPassword(a,b) { return this.md5Hash(a) === b }
hashSecurityAnswer(t){ return this.md5Hash(t.trim()) }
```

- **Unsalted MD5**, single round, for both the password and the security answer. Trivially reversed via rainbow tables. Minimum length enforced in the UI is 4 characters; the service worker only checks `length < 1`.
- `crypto-js`'s PBKDF2 (250k iterations, SHA-256) is present in the bundle but is **not used** for password handling — it ships as part of the library.
- Recovery path 1: security question → `verifySecurityAnswer` → set a new password hash and clear the failed-attempt counter.
- Recovery path 2: **auto-reset** (default on, `autoResetDays: 3`). Triggering it starts a countdown; on expiry `performAutoReset()` nulls the password hash, the security question, the security counters, the lock state and the saved window state — a built-in, unauthenticated bypass with a waiting period.
- Everything lives in `chrome.storage.local`, which is a plain LevelDB file on disk. Anyone with filesystem access can read the hash, overwrite it, or set `isLocked:false` directly. **The lock is a deterrent against casual shoulder-surfing, not against an attacker with the machine.**

---

## 6. Backend client and promotion system

All traffic goes to `https://platform.chromelock.net`. Five endpoints, declaratively described in one config module:

| Logical call | Path |
|---|---|
| login | `/polyvarien/api/dim_fog_v4` |
| userInfo | `/polyvarien/coral_titanium_v1/rho_field_v3` |
| dock (remote config) | `/polyvarien/gold_ice_v4/theta_pixel_v3` |
| promotion fetch | `/polyvarien/top_slot_v8/blue_isle_v4` |
| promotion action | `/polyvarien/static_quasar_v2/back_spiral_v2` |

Each endpoint descriptor carries an obfuscation spec:

- **Field aliasing** — real names are mapped to nonsense on the wire (`appId` → `multi_space_v1`, `anonymousCode` → `smart_power_v2`, `token` → `deep_brass_v4`, `userId` → `mild_spark_v7`); `responseMap` reverses it on receipt.
- **Noise injection** — decoy fields mixed into url/body/header, both static (`coral_build: "stable-3.2.1"`, `coral_runtime: "chromium-ext"`) and dynamic (`coral_trace` random, `coral_epoch` timestamp, `coral_tz` from `Intl.DateTimeFormat().resolvedOptions().timeZone`, `mist_loc` from `navigator.language`).
- **`fieldOrder`** — payload keys are emitted in a fixed shuffled order.
- **gzip** on request and/or response bodies (pako), base64-wrapped.

Auth: anonymous login posts `{appId: <extension id>, anonymousCode, idStr: "BL"}` and receives a token stored as `xAuth`, sent thereafter in a header and refreshed every 24 h (`TOKEN_REFRESH_INTERVAL: 864e5`).

**Promotions** are server-delivered ad units keyed by "placement", with `mediaType`/`mediaUrl`/`actionUrl`/`extraConfig` and a `displaySessionId`. The client reports `view` (with `viewDurationMs`), `click`, and `close` back to the promotion-action endpoint. Locale strings confirm they render **on the lock screen** ("Will open after you unlock the browser") — i.e. the lock UI is also an ad surface, and `lock:open-url-after-unlock` queues a promoted URL to open once the user unlocks.

The **dock** endpoint is remote configuration: it supplies `tutorialUrl`, `feedbackUrl`, and support/website links. On `install` the extension opens `dock.tutorialUrl` in a new tab; on `install` and `update` it sets the uninstall URL. Outbound URLs are decorated with `?scene=<install|uninstall|…>&product=chrome-lock&anonymousCode=<id>&version=<v>&browser=chrome`.

A **review nag** fires after 5 lock operations (`REVIEW_WORK_THRESHOLD: 5`, counter `workCount`, suppressed by `reviewShown`), with a star-rating UI that routes 5-star raters to the Web Store.

---

## 7. Localization

`_locales/` covers 55 locales with a complete message catalog (~180 keys). This part of the extension is genuinely well built.

---

## 8. Assessment

**Sound:**
- The lock mechanism itself is well-engineered for what MV3 permits — event listeners plus a periodic sweep is the correct defensive combination, and window/tab restoration is faithful.
- Minimal permission set: no host permissions, no content scripts, no ability to read page content.
- Thorough i18n.

**Concerns, roughly by severity:**

1. **Unsalted MD5** for password and security answer, with the hash sitting in readable local storage. Should be PBKDF2/scrypt with a per-install salt — the library for it is already bundled.
2. **Auto-reset is on by default** and wipes the password after 3 days with no authentication. That is an intentional lockout escape hatch, but it is also an unauthenticated bypass anyone with physical access can start and wait out.
3. **Full browsing state is persisted in plaintext.** `browser_lock_saved_state` holds every open URL and page title, unencrypted, for the duration of the lock — a privacy-sensitive artifact created by a privacy tool.
4. **Deliberate anti-analysis throughout.** Misleading directory/file names, fake content hashes, ~17 unreferenced decoy libraries, inline filler inside live bundles, aliased API field names, injected noise parameters, gzipped bodies, and nonsense endpoint paths. None of this serves the user; it serves evasion of review and network inspection.
5. **Ad delivery on the lock screen**, with view/click/close telemetry sent to first-party servers, plus remote-configured URLs auto-opened on install.
6. **~9 MB package** for ~50 KB of functional code; four duplicate copies of Vue + Element Plus.
7. A `setInterval` in an MV3 service worker is unreliable across worker termination; the `onCreated` listeners are what actually keep the lock enforced.

**Bottom line:** the locking behavior works as advertised and the permission surface is narrow, but the cryptography is inadequate, the default auto-reset undercuts the security claim, and the packaging is engineered to resist inspection while shipping a server-controlled ad channel. Treat it as a privacy screen against passers-by, not as protection for a machine that might be handled by someone motivated.
