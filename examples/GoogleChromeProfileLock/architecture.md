# Google Chrome Profile Lock — Architecture Analysis

Analysis of the packed extension in [GoogleChromeProfileLock/](.) — version 1.5, Manifest V3, ~2,000 lines across 8 source files.

---

## 1. Overview

"Google Chrome Profile Lock" presents itself as a password gate for a Chrome profile. Functionally it is a **UI-level overlay lock**, not a security boundary: it stores a base64-encoded password in `chrome.storage.sync` and paints a `<div>` overlay on top of pages. It is monetized as freemium via Gumroad license keys, with Pro gating auto-lock, themes, per-site locks, and the security log.

| Property | Value |
| --- | --- |
| Manifest version | 3 |
| Version | 1.5 |
| Permissions | `storage`, `tabs`, `alarms` |
| Host permissions | `https://api.gumroad.com/*` |
| Content scripts | `content.js` on `<all_urls>` |
| Distribution | Chrome Web Store (`update_url` = clients2.google.com), signed (`key` + `_metadata/`) |

## 2. File Inventory

| File | Lines | Role |
| --- | --- | --- |
| [manifest.json](manifest.json) | 37 | MV3 declaration, permissions, signing key |
| [background.js](background.js) | 231 | Service worker — lock state, password, alarms, security log |
| [content.js](content.js) | 278 | Injected on every page; builds the lock overlay + recovery UI |
| [popup.js](popup.js) | 346 | Toolbar popup — setup, lock/unlock, license activation, review nudge |
| [options.js](options.js) | 249 | Options page — Pro settings, license activation |
| [license.js](license.js) | 38 | Shared Gumroad verify + silent re-check helpers |
| [popup.html](popup.html) | 485 | Popup markup + inline CSS |
| [options.html](options.html) | 329 | Options markup + inline CSS |
| `icons/*.png` | — | 16/32/48/128 icons |
| `_metadata/` | — | Web Store integrity hashes (`computed_hashes`, `verified_contents`) |

`license.js` is loaded before `popup.js` / `options.js` in both HTML pages and shares globals via the window scope — there is no module system, bundler, or build step. Source is unminified and hand-written.

## 3. Component Architecture

```
┌──────────────┐   sendMessage    ┌───────────────────┐
│  popup.js    │ ───────────────► │  background.js    │
│ (popup.html) │ ◄─────────────── │ (service worker)  │
└──────┬───────┘   response       └────────┬──────────┘
       │                                   │
       │ openOptionsPage()                 │ chrome.storage.sync
       ▼                                   ▼
┌──────────────┐                  ┌───────────────────┐
│  options.js  │ ───────────────► │  storage.sync     │
│(options.html)│    direct r/w    │  storage.local    │
└──────┬───────┘                  └────────▲──────────┘
       │                                   │
       │ license.js (shared)               │ direct read
       ▼                                   │
┌──────────────┐                  ┌────────┴──────────┐
│ api.gumroad  │                  │   content.js      │
│    .com      │                  │ (every page,      │
└──────────────┘                  │  <all_urls>)      │
                                  └───────────────────┘
```

**Two coexisting data paths.** Lock/unlock/password operations go through message passing to the service worker; settings and license state are written directly to `chrome.storage.sync` from the popup and options page. `content.js` reads `isPro` / `protectedSites` / `lockTheme` straight from storage but routes password verification through the worker. There is no single source of truth for state mutation.

### background.js — service worker

Message router over `chrome.runtime.onMessage` with six actions:

| Action | Handling |
| --- | --- |
| `lockProfile` | Sets `isLocked`, clears alarm, closes every non-extension tab |
| `unlockProfile` | Clears `isLocked` — **no password required** |
| `checkLockStatus` | Async read (correctly returns `true` to keep the channel open) |
| `setPassword` | Generates a recovery key, stores `btoa(password)` |
| `resetPassword` | Compares recovery key case-insensitively, sets new password |
| `unlockWithPassword` | Compares `btoa(password)` to stored hash |

Auto-lock uses `chrome.alarms` rather than `setTimeout`, correctly accounting for MV3 worker termination — the code comments show this was a deliberate fix. The timer resets on `tabs.onActivated` / `tabs.onUpdated`, and a `storage.onChanged` listener re-evaluates immediately when `isPro` or `lockTimeout` changes. Auto-lock is Pro-only; `resetLockTimer` clears the alarm outright for free users.

### content.js — the lock overlay

Runs on every URL at default (`document_idle`) timing. On load it asks the worker for global lock status and reads `protectedSites` from storage, then decides:

```
isGlobalLocked || (isPro && siteMatches && !sessionStorage.site_unlocked)
    → showLockScreen(isGlobal)
```

`showLockScreen` builds a `position: fixed; z-index: 999999` overlay containing two views (login / recovery) via a single `innerHTML` assignment, with a themed gradient background pulled from `lockTheme`. Successful per-site unlock sets `sessionStorage.site_unlocked` so the tab stays open for the session.

Site matching is a naive substring test against the full URL: `location.href.includes(site)`. An entry like `mail` matches any URL containing that string anywhere, including query strings.

### popup.js / options.js

Popup handles first-run password setup (with one-time recovery-key display), lock/unlock buttons, Pro badge, license activation, and a review nudge. The nudge is reasonably well designed: gated on ≥10 unlocks or ≥7 days since install, with a 14-day cooldown after "Later", stored in `chrome.storage.local` so counters don't sync across devices.

Options exposes the four Pro settings (timeout, theme, protected sites, security log) with a dual gate — DOM `disabled` attributes plus an `if (!isPro) return;` guard in each handler. Password change uses `window.prompt`, which renders the new password in cleartext.

### license.js — Gumroad integration

`POST https://api.gumroad.com/v2/licenses/verify` with a hardcoded product ID. Activation increments the uses count and rejects `data.uses > 1` as a crude one-device limit. Silent re-verification runs when `lastLicenseCheck` is older than 24h, and on failure clears `isPro`, `gumroadKey`, and plan fields. Network errors are swallowed so offline users retain Pro.

## 4. State Model

**`chrome.storage.sync`** (syncs across devices — includes the password):

`isLocked`, `hasPassword`, `passwordHash`, `recoveryKey`, `lockTimeout` (min, default 5), `lockTheme` (`purple|dark|sunset|ocean`), `protectedSites[]`, `securityLog[]` (capped at 5), `isPro`, `gumroadKey`, `proPlan`, `subscriptionCancelled`, `lastLicenseCheck`

**`chrome.storage.local`** (device-only): `installDate`, `unlockCount`, `reviewPrompt`

**`sessionStorage`** (per tab, per origin): `site_unlocked`

## 5. Security Assessment

The lock is cosmetic. Several findings are severe enough that the extension should not be relied on to protect anything.

### Critical

1. **Passwords are base64-encoded, not hashed** — [background.js:122](background.js#L122), [background.js:140](background.js#L140). `btoa(password)` is trivially reversible. The code comment ("Simple base64 encoding") acknowledges this. Anyone with a devtools console can run `chrome.storage.sync.get('passwordHash')` and `atob` the result.
2. **Password and recovery key sync to Google's servers in cleartext-equivalent form** via `storage.sync`, propagating to every signed-in device.
3. **`unlockProfile` needs no password** — [background.js:101](background.js#L101). Any page that can reach the extension (and any extension page) can clear the lock by sending `{action:'unlockProfile'}`; the message listener has no sender validation.
4. **The overlay is trivially removed.** It is a DOM node in the page's own document. `document.getElementById('profile-lock-screen').remove()`, disabling JavaScript, view-source, devtools, or reading the page before `document_idle` all bypass it. Underlying page content is fully loaded behind the overlay.
5. **Recovery key generated with `Math.random()`** — [background.js:191](background.js#L191). Not cryptographically secure; `crypto.getRandomValues` is available.

### High

6. **License bypass backdoor** — [popup.js:211](popup.js#L211) and [options.js:158](options.js#L158). If the Gumroad fetch rejects, the literal key `PRO99` activates Pro. Blocking `api.gumroad.com` (hosts file, offline, DNS) plus that key grants Pro permanently.
7. **XSS in the security log** — [options.js:77-85](options.js#L77-L85). Log entries are interpolated into `innerHTML` without escaping. The `type`/`description` values are currently extension-controlled, so it is not reachable today, but the pattern is one storage write away from being exploitable.
8. **Hostname injected into overlay HTML** — [content.js:80](content.js#L80). `window.location.hostname` goes into a template string assigned to `innerHTML`. Chrome normalizes hostnames, so exploitation is unlikely, but attacker-influenced page context is being concatenated into markup.
9. **`lockProfile` closes every tab** — [background.js:90-96](background.js#L90-L96). Auto-lock silently destroys all open tabs and any unsaved work in them, with no warning or restore.

### Medium

10. **Content script on `<all_urls>`** with no `run_at` specified — broad injection surface for a feature that only needs to act when locked.
11. **Password entered via `window.prompt`** — [options.js:204](options.js#L204) — shown in cleartext, and no old-password confirmation is required to change it.
12. **No rate limiting** on unlock or recovery-key attempts.
13. **Minimum password length is 4 characters.**
14. **Per-site unlock keyed on `sessionStorage`**, which the page's own scripts can read and write.
15. **`securityLog` timestamps store only time-of-day**, no date — [background.js:173](background.js#L173) — making the log near-useless for forensics.

## 6. Code Quality

**Strengths:** unminified and readable; consistent naming; comments explain *why* (the alarms-over-setTimeout note, the review-nudge guard rationale); shared license logic factored into `license.js` instead of duplicated; MV3 lifecycle handled correctly for alarms and async message responses; the review nudge is respectfully implemented.

**Weaknesses:**
- Gumroad activation logic is **duplicated verbatim** between [popup.js:168-222](popup.js#L168-L222) and [options.js:118-167](options.js#L118-L167) — including the `PRO99` backdoor — despite `license.js` existing for exactly this.
- `showMessage` / `showMessageIn` duplicated across popup and options.
- Popup event listeners are attached inside `showMainSection`, which `initializePopup` re-invokes after activation — **listeners stack** on repeated calls, so a later click fires the handler multiple times.
- All CSS and the entire overlay UI live in inline strings; no stylesheet.
- No build system, no tests, no linting, no type checking, no error boundaries around storage callbacks.
- Mixed async styles — `async/await` in popup/options, hand-rolled `new Promise` wrappers around callback APIs in background.
- `content.js` calls `checkProfileLock()` both on `DOMContentLoaded` and immediately at top level; at `document_idle` the event has usually already fired, but a race can produce two overlays.

## 7. Data Flows

**First-run setup:** popup → `setPassword` → worker generates recovery key, stores `btoa(password)` → key displayed once → user confirms → main view.

**Manual lock:** popup → `lockProfile` → alarm cleared, `isLocked=true`, all non-extension tabs closed, event logged.

**Unlock from a page:** overlay → `unlockWithPassword` → worker compares `btoa(password)` → on match clears `isLocked`, logs, increments `unlockCount`, overlay removed.

**Auto-lock (Pro):** tab activity → `resetLockTimer` → alarm at `lockTimeout` minutes → `onAlarm` → `lockProfile`.

**Recovery:** overlay recovery view → `resetPassword` → case-insensitive key compare → new password stored, profile unlocked.

**License activation:** popup/options → Gumroad verify (`increment_uses_count=true`) → reject if `uses > 1` → store Pro fields; on network error, `PRO99` grants Pro.

## 8. External Dependencies

- `api.gumroad.com/v2/licenses/verify` — the only network call; the license key is transmitted, no analytics or telemetry are sent anywhere.
- `saahmed.gumroad.com/l/chrome-profile-lock-pro` — purchase page, opened in a tab.
- `chromewebstore.google.com/detail/<id>/reviews` — review nudge target.

No third-party libraries, CDNs, or bundled code. No tracking pixels or remote script execution. `_metadata/verified_contents.json` confirms Web Store signing; the `key` field pins the extension ID.

## 9. Summary

Architecturally this is a small, conventional MV3 extension: a service worker owning lock state, a content script painting an overlay, two UI surfaces, and a Gumroad paywall. The MV3-specific details (alarms, async messaging) are handled correctly, and the code is readable and well-commented.

The security model, however, does not deliver what the description promises. Base64 is not hashing, a DOM overlay is not access control, the password syncs to Google's servers, `unlockProfile` requires no credential, and a hardcoded `PRO99` fallback defeats the paywall. Treat this as a deterrent against casual shoulder-surfing, not as profile protection.

**Highest-value fixes**, in order: replace `btoa` with PBKDF2/SHA-256 over WebCrypto with a per-install salt; remove the `PRO99` fallback; require a password for `unlockProfile`; switch the recovery key to `crypto.getRandomValues`; replace `innerHTML` interpolation with `textContent` / DOM construction; deduplicate the activation logic into `license.js`; and move popup listener wiring out of the re-invoked render path.
