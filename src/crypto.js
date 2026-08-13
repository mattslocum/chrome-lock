/**
 * Envelope encryption for Chrome Lock.
 *
 * The tab snapshot is encrypted under a random 32-byte `dataKey`. The dataKey is
 * never stored in the clear; instead it is *wrapped* once per authorized unlock
 * path:
 *
 *   wrap_pw     AES-GCM under a key derived from the profile's own password
 *   wrap_master RSA-OAEP under the parent escrow public key  (see escrow.js usage)
 *
 * That indirection is what lets a password change, and a parent master unlock,
 * exist without ever re-encrypting the snapshot itself.
 *
 * The only module that touches crypto.subtle. Everything here works unchanged in
 * a Chrome service worker and in Node >=20, so it is testable without a browser.
 */

export const PBKDF2_ITERATIONS = 600_000;
export const FORMAT_VERSION = 1;

const KEY_BYTES = 32; // AES-256
const SALT_BYTES = 16;
const IV_BYTES = 12; // 96-bit, the GCM-recommended size
const RSA_MODULUS_BITS = 3072;

/** Wrong password, wrong master password, or tampered ciphertext. */
export class DecryptError extends Error {
  constructor(message = 'Decryption failed') {
    super(message);
    this.name = 'DecryptError';
  }
}

// --- encoding helpers -------------------------------------------------------
// Stored records go through JSON into chrome.storage.local, so every binary
// field is base64. These avoid String.fromCharCode(...spread) so they stay safe
// for inputs larger than the argument limit.

/** @param {Uint8Array} bytes @returns {string} */
export function toB64(bytes) {
  let binary = '';
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}

/** @param {string} b64 @returns {Uint8Array} */
export function fromB64(b64) {
  const binary = atob(b64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

const utf8 = new TextEncoder();
const utf8Decode = new TextDecoder();

function randomBytes(n) {
  return crypto.getRandomValues(new Uint8Array(n));
}

/**
 * Best-effort wipe of a key buffer once it is no longer needed. JS gives no real
 * guarantee here (the GC may have copied it already), but it shortens the window
 * in which a plaintext key sits in a live heap.
 * @param {Uint8Array} bytes
 */
export function wipe(bytes) {
  if (bytes instanceof Uint8Array) bytes.fill(0);
}

// --- password-derived key wrapping ------------------------------------------

/**
 * PBKDF2-HMAC-SHA256 over the password, producing the AES-GCM key-encryption key.
 * @param {string} password
 * @param {Uint8Array} salt
 * @param {number} iterations
 */
async function deriveKek(password, salt, iterations) {
  const material = await crypto.subtle.importKey(
    'raw',
    utf8.encode(password),
    'PBKDF2',
    false,
    ['deriveKey'],
  );
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt, iterations, hash: 'SHA-256' },
    material,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt'],
  );
}

/** @returns {Uint8Array} a fresh 32-byte data key */
export function generateDataKey() {
  return randomBytes(KEY_BYTES);
}

/**
 * Wrap a dataKey under a password. The returned record is safe to persist.
 *
 * There is deliberately no separate stored password "verifier": AES-GCM is
 * authenticated, so a failed unwrap *is* the wrong-password signal, at no extra
 * cost. Adding a verifier would double the PBKDF2 work per unlock to tell us
 * something the unwrap already tells us.
 *
 * @param {string} password
 * @param {Uint8Array} dataKey
 * @param {{iterations?: number}} [opts]
 */
export async function wrapWithPassword(password, dataKey, opts = {}) {
  const iterations = opts.iterations ?? PBKDF2_ITERATIONS;
  const salt = randomBytes(SALT_BYTES);
  const iv = randomBytes(IV_BYTES);
  const kek = await deriveKek(password, salt, iterations);
  const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, kek, dataKey);
  return {
    v: FORMAT_VERSION,
    salt: toB64(salt),
    iv: toB64(iv),
    ct: toB64(new Uint8Array(ct)),
    iterations,
  };
}

/**
 * Recover the dataKey from a password wrap.
 * @param {string} password
 * @param {ReturnType<typeof wrapWithPassword> extends Promise<infer T> ? T : never} wrap
 * @returns {Promise<Uint8Array>}
 * @throws {DecryptError} on a wrong password or tampered record
 */
export async function unwrapWithPassword(password, wrap) {
  assertVersion(wrap);
  const kek = await deriveKek(password, fromB64(wrap.salt), wrap.iterations);
  try {
    const raw = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: fromB64(wrap.iv) },
      kek,
      fromB64(wrap.ct),
    );
    return new Uint8Array(raw);
  } catch {
    throw new DecryptError('Incorrect password');
  }
}

// --- snapshot encryption ----------------------------------------------------

/**
 * Encrypt the tab snapshot. A fresh IV per call, so reusing one dataKey across
 * many locks is safe.
 * @param {Uint8Array} dataKey
 * @param {unknown} snapshot JSON-serializable
 */
export async function encryptSnapshot(dataKey, snapshot) {
  const key = await importDataKey(dataKey);
  const iv = randomBytes(IV_BYTES);
  const ct = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv },
    key,
    utf8.encode(JSON.stringify(snapshot)),
  );
  return { v: FORMAT_VERSION, iv: toB64(iv), ct: toB64(new Uint8Array(ct)) };
}

/**
 * @param {Uint8Array} dataKey
 * @param {{v: number, iv: string, ct: string}} blob
 * @throws {DecryptError} on a wrong key or tampered ciphertext
 */
export async function decryptSnapshot(dataKey, blob) {
  assertVersion(blob);
  const key = await importDataKey(dataKey);
  let plaintext;
  try {
    plaintext = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: fromB64(blob.iv) },
      key,
      fromB64(blob.ct),
    );
  } catch {
    throw new DecryptError('Snapshot could not be decrypted');
  }
  return JSON.parse(utf8Decode.decode(plaintext));
}

function importDataKey(dataKey) {
  return crypto.subtle.importKey('raw', dataKey, 'AES-GCM', false, [
    'encrypt',
    'decrypt',
  ]);
}

// --- parent escrow (asymmetric) ---------------------------------------------

/**
 * Create the parent escrow bundle.
 *
 * A profile must wrap its dataKey for the parent *at lock time*, when the master
 * password is not present — so this has to be asymmetric. The bundle contains no
 * plaintext secret (the private key is encrypted under the master password) and
 * is therefore safe to distribute to every profile via chrome.storage.managed.
 *
 * @param {string} masterPassword
 * @param {{iterations?: number}} [opts]
 */
export async function createEscrowBundle(masterPassword, opts = {}) {
  const iterations = opts.iterations ?? PBKDF2_ITERATIONS;
  const { publicKey, privateKey } = await crypto.subtle.generateKey(
    {
      name: 'RSA-OAEP',
      modulusLength: RSA_MODULUS_BITS,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: 'SHA-256',
    },
    true,
    ['encrypt', 'decrypt'],
  );

  const spki = new Uint8Array(await crypto.subtle.exportKey('spki', publicKey));
  const pkcs8 = new Uint8Array(await crypto.subtle.exportKey('pkcs8', privateKey));

  const mSalt = randomBytes(SALT_BYTES);
  const iv = randomBytes(IV_BYTES);
  const mKek = await deriveKek(masterPassword, mSalt, iterations);
  const privWrapped = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, mKek, pkcs8);
  wipe(pkcs8);

  return {
    v: FORMAT_VERSION,
    keyId: await keyIdFor(spki),
    pub: toB64(spki),
    privWrapped: { iv: toB64(iv), ct: toB64(new Uint8Array(privWrapped)) },
    mSalt: toB64(mSalt),
    iterations,
  };
}

/**
 * Wrap a dataKey for the parent. Uses only the public half — the profile doing
 * this never sees the master password or the private key.
 * @param {{keyId: string, pub: string}} bundle
 * @param {Uint8Array} dataKey
 */
export async function wrapForMaster(bundle, dataKey) {
  assertVersion(bundle);
  const pub = await crypto.subtle.importKey(
    'spki',
    fromB64(bundle.pub),
    { name: 'RSA-OAEP', hash: 'SHA-256' },
    false,
    ['encrypt'],
  );
  const ct = await crypto.subtle.encrypt({ name: 'RSA-OAEP' }, pub, dataKey);
  return { v: FORMAT_VERSION, keyId: bundle.keyId, ct: toB64(new Uint8Array(ct)) };
}

/**
 * Parent unlock: master password -> private key -> dataKey.
 * @param {string} masterPassword
 * @param {object} bundle
 * @param {{keyId: string, ct: string}} wrap
 * @returns {Promise<Uint8Array>}
 * @throws {DecryptError} on a wrong master password, or a wrap from another keypair
 */
export async function unwrapWithMaster(masterPassword, bundle, wrap) {
  assertVersion(bundle);
  assertVersion(wrap);
  if (wrap.keyId !== bundle.keyId) {
    throw new DecryptError('Escrow wrap was made for a different master key');
  }
  const priv = await unwrapPrivateKey(masterPassword, bundle);
  try {
    const raw = await crypto.subtle.decrypt({ name: 'RSA-OAEP' }, priv, fromB64(wrap.ct));
    return new Uint8Array(raw);
  } catch {
    throw new DecryptError('Escrow wrap could not be decrypted');
  }
}

/**
 * Re-encrypt the escrow private key under a new master password. The keypair is
 * unchanged, so `keyId`, `pub`, and every existing wrap_master stay valid — no
 * profile needs to re-wrap anything.
 * @param {string} oldPassword
 * @param {string} newPassword
 * @param {object} bundle
 * @param {{iterations?: number}} [opts]
 */
export async function rotateMasterPassword(oldPassword, newPassword, bundle, opts = {}) {
  const iterations = opts.iterations ?? bundle.iterations ?? PBKDF2_ITERATIONS;
  const priv = await unwrapPrivateKey(oldPassword, bundle);
  const pkcs8 = new Uint8Array(await crypto.subtle.exportKey('pkcs8', priv));

  const mSalt = randomBytes(SALT_BYTES);
  const iv = randomBytes(IV_BYTES);
  const mKek = await deriveKek(newPassword, mSalt, iterations);
  const privWrapped = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, mKek, pkcs8);
  wipe(pkcs8);

  return {
    ...bundle,
    privWrapped: { iv: toB64(iv), ct: toB64(new Uint8Array(privWrapped)) },
    mSalt: toB64(mSalt),
    iterations,
  };
}

/** Cheap check that a master password is correct, without needing a wrap. */
export async function verifyMasterPassword(masterPassword, bundle) {
  try {
    await unwrapPrivateKey(masterPassword, bundle);
    return true;
  } catch {
    return false;
  }
}

async function unwrapPrivateKey(masterPassword, bundle) {
  const mKek = await deriveKek(masterPassword, fromB64(bundle.mSalt), bundle.iterations);
  let pkcs8;
  try {
    pkcs8 = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: fromB64(bundle.privWrapped.iv) },
      mKek,
      fromB64(bundle.privWrapped.ct),
    );
  } catch {
    throw new DecryptError('Incorrect master password');
  }
  // Marked extractable so rotateMasterPassword can re-export it. The plaintext
  // key exists only for the duration of an unlock.
  return crypto.subtle.importKey(
    'pkcs8',
    pkcs8,
    { name: 'RSA-OAEP', hash: 'SHA-256' },
    true,
    ['decrypt'],
  );
}

/** Stable short id for a public key, so a future keypair can coexist with old wraps. */
async function keyIdFor(spki) {
  const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', spki));
  return [...digest.slice(0, 8)].map((b) => b.toString(16).padStart(2, '0')).join('');
}

function assertVersion(record) {
  if (!record || typeof record !== 'object') {
    throw new DecryptError('Malformed record');
  }
  if (record.v !== FORMAT_VERSION) {
    throw new DecryptError(`Unsupported record version: ${record.v}`);
  }
}
