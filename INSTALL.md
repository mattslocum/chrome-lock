# Installing Chrome Lock

Two ways to run this, and they are for different purposes.

**Unpacked** (`chrome://extensions` → Load unpacked → this directory) is for
development. It is per-profile, and it can be disabled from
`chrome://extensions` in one click — which is fine while building, and not fine
as the actual install.

**Force-installed by policy** is the real one. Chrome enterprise policy on macOS
applies to every Chrome profile under a macOS user, and a force-installed
extension **cannot be disabled or removed** from `chrome://extensions`. That is
the whole point of this phase: it upgrades the weakest property in the threat
model (architecture.md §2). The same policy file also delivers the parent escrow
key to every profile, so nobody has to install it by hand.

Note what force-install costs, and say it out loud to the family first: *nobody*
can remove the extension afterwards, including me, without editing a root-owned
file. Profiles that never set a password stay completely dormant (architecture.md
§7), so this costs them nothing — but it should not be a surprise.

---

## One-time setup

### 1. Generate the signing key

```sh
npm run keygen
```

Writes `keys/chrome-lock.pem` and prints the extension id.

**This key is the extension's identity.** Chrome derives the extension id from
its public half, and the policy names that id. Consequences worth internalising
before going further:

- **Lose the key** and you cannot ship an update. A new key is a *different*
  extension: new id, new (empty) storage in every profile, and any profile that
  happened to be locked keeps an encrypted snapshot no installed extension can
  open.
- **Leak the key** and someone else can sign an update Chrome will accept and
  install silently, on every profile.

So: back it up where the master password lives, and nowhere else. `keys/` is
gitignored.

### 2. Generate the parent escrow key

In any profile with the extension loaded: toolbar icon → Settings → the escrow
section → generate, with the master password.

The master password has a 16-character minimum and should come out of a password
manager. It is the one credential here that is both offline-attackable and able
to open every profile (architecture.md §8) — `privWrapped` sits in a file every
profile can read, so it can be copied and ground against PBKDF2 where the lock
screen's backoff cannot see it.

Copy the JSON from the escrow key field into a file:

```sh
pbpaste > escrow.json     # gitignored
```

The bundle holds **no plaintext secret** — its private half is sealed under the
master password — which is exactly why it is safe to hand to every profile.

### 3. Turn on GitHub Pages

The crx and `update.xml` are served from GitHub Pages out of `docs/` on `main`:

```
updateBaseUrl  https://mattslocum.github.io/chrome-lock
publishDir     docs
```

Both are already set in `release.config.json`. What is left is enabling Pages
once, in the repo: **Settings → Pages → Source: Deploy from a branch → `main`,
folder `/docs`**. The first deploy takes a minute or two; the site is live when
`https://mattslocum.github.io/chrome-lock/update.xml` returns the XML rather than
a 404.

This is the project's only network dependency, and it is install-time
infrastructure, not runtime (architecture.md §9).

**Nothing secret is published.** The crx holds the same source that is already in
a public repo. The escrow bundle goes in the plist, not the crx, and `keys/`,
`dist/` and `escrow*.json` are gitignored. What *does* become public is the
extension's existence and its code, which was always the intent — the whole point
is that it is readable.

You can leave `updateBaseUrl` unset for a dry run. But without an update URL there
is no `ExtensionInstallForcelist` entry, and without that the extension can still
be disabled — which is the property this whole phase exists to buy. Fine for a
rehearsal, not for the real install.

---

## Building a release

```sh
npm test          # 125 tests; the packaging ones check what actually ships
npm run pack      # → dist/chrome-lock-<version>.crx and dist/update.xml
```

`pack` writes the crx and `update.xml` into **both** `dist/` (the gitignored
build output) and `docs/` (what Pages serves). It always writes the pair
together: a crx published without an `update.xml` naming its version is an update
Chrome never looks at, and an `update.xml` pointing at a crx that isn't there is a
404 on every profile at once.

It prints the extension id, the file count, and a SHA-256 of the crx. The build is
**reproducible** — same sources, same key, same bytes — so that hash is worth
recording next to the tag. It is what lets you check later that a crx in the wild
is the one you built (architecture.md §10.8).

Publish by committing:

```sh
git add docs && git commit -m "Publish 0.6.0" && git push
```

## Writing the policy file

```sh
npm run plist -- --escrow escrow.json
```

Writes `dist/com.google.Chrome.plist` containing two things:

- `ExtensionInstallForcelist` — `<extension-id>;<update-url>`, which installs the
  extension on every profile and makes it unremovable.
- `3rdparty` → `extensions` → `<extension-id>` → `escrowBundle` — the escrow key,
  landing in `chrome.storage.managed`.

Chrome delivers **no** managed key that `managed-schema.json` has not declared,
which is why that file ships in the crx and is referenced from the manifest. A
managed bundle also takes precedence over a locally-installed one, so a profile
cannot shadow the parent's escrow key with one whose password it chose
(architecture.md §8).

## Installing the policy

Per macOS user (which, with one shared login, is everyone):

```sh
sudo mkdir -p "/Library/Managed Preferences/$USER"
sudo cp dist/com.google.Chrome.plist "/Library/Managed Preferences/$USER/com.google.Chrome.plist"
sudo chown root:wheel "/Library/Managed Preferences/$USER/com.google.Chrome.plist"
sudo chmod 644 "/Library/Managed Preferences/$USER/com.google.Chrome.plist"
```

Machine-wide instead: drop the `/$USER` from the destination path.

## While you are here: require OS auth for saved passwords

Not part of this extension, and worth doing anyway on the same machine.

Protection mode closes any window or tab created while a profile is locked, so
`chrome://password-manager` is shut the moment it opens — but that is a removal
racing a creation, not a gate, and the site list is legible in the interval.
Chrome has an actual gate for this:

**Settings → Autofill and passwords → Google Password Manager → Settings → *Use
your screen lock when filling passwords* (and *Require re-authentication to show
passwords*).**

With one shared macOS login this is the only thing standing between a curious kid
and a revealed password, whether or not a profile is locked. It closes the glance
gap that no extension can close, because an extension cannot gate a `chrome://`
page — it can only close the window after Chrome has already drawn it.

Then quit Chrome completely (⌘Q — closing the windows is not enough) and reopen
it.

---

## Verifying it worked

Nothing below is covered by the test suite: it is all about how a real Chrome on
a real machine behaves, so it has to be walked through by hand once.

1. **`chrome://policy`** — `ExtensionInstallForcelist` shows the id, status OK.
   If it does not appear, the plist is not being read: check ownership and that
   Chrome was fully quit. "Reload policies" on that page re-reads without a
   restart.
2. **`chrome://extensions`** — Chrome Lock is present, marked *Installed by
   enterprise policy*, with **no Remove button and no enable/disable toggle**.
   That is the property being bought here.
3. **Escrow reached the profile** — open Settings; the escrow section should say
   the key came from policy, and offer no create/import/rotate/remove controls.
   A managed profile is administered from the plist.
4. **A second profile** — switch profiles. The extension is there, dormant: no
   badge, no prompt, nothing until someone sets a password. Set one, lock, and
   confirm the lock screen offers **Parent unlock**, and that the master password
   opens it.
5. **Neither password opens the other profile.** Storage is per-profile
   (architecture.md §7); this is worth confirming once rather than assuming.
6. **A restart** — lock a profile, quit Chrome entirely, reopen. It must come
   back to a lock window, not to the restored tabs. This is the path Phase 5
   found a bug on, and it is the one nobody watches.

## Updating

1. Bump `version` in `manifest.json` (Chrome compares against `update.xml`).
2. `npm test && npm run pack`.
3. Commit `docs/` and push. Pages redeploys on its own.

Chrome polls roughly every five hours; `chrome://extensions` → Update forces it.
Only the version in `update.xml` triggers a download.

Old crx files accumulate in `docs/` as versions go by. Leave them — that is the
archive, and keeping the artifact you actually shipped is the point of §10.8.

## Backing out

Remove the plist and fully restart Chrome:

```sh
sudo rm "/Library/Managed Preferences/$USER/com.google.Chrome.plist"
```

The extension becomes an ordinary removable one again. **Unlock every locked
profile first.** Uninstalling discards the encrypted snapshot along with
everything else, and that snapshot is the only copy of those tab sessions — by
construction (architecture.md §4).
