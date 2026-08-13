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

### 3. Decide where the crx will live, if you want auto-update

Set `updateBaseUrl` in `release.config.json` to wherever `dist/` will be served
from over https — a GitHub Pages site is enough. This is the project's only
network dependency, and it is install-time infrastructure, not runtime
(architecture.md §9).

You can skip it. Without an update URL there is no `ExtensionInstallForcelist`
entry, and without that the extension can still be disabled — so skipping it
means skipping the property this phase exists for. It is fine for a dry run and
not fine for the real install.

---

## Building a release

```sh
npm test          # 125 tests; the packaging ones check what actually ships
npm run pack      # → dist/chrome-lock-<version>.crx and dist/update.xml
```

`pack` prints the extension id, the file count, and a SHA-256 of the crx. The
build is **reproducible** — same sources, same key, same bytes — so that hash is
worth recording next to the tag. It is what lets you check later that a crx in
the wild is the one you built (architecture.md §10.8).

Upload `dist/chrome-lock-<version>.crx` and `dist/update.xml` to the
`updateBaseUrl` location.

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
3. Upload both files.

Chrome polls roughly every five hours; `chrome://extensions` → Update forces it.
Only the version in `update.xml` triggers a download, so publishing a crx without
updating the xml does nothing.

## Backing out

Remove the plist and fully restart Chrome:

```sh
sudo rm "/Library/Managed Preferences/$USER/com.google.Chrome.plist"
```

The extension becomes an ordinary removable one again. **Unlock every locked
profile first.** Uninstalling discards the encrypted snapshot along with
everything else, and that snapshot is the only copy of those tab sessions — by
construction (architecture.md §4).
