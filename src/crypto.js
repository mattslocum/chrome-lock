/**
 * Envelope encryption for Chrome Lock.
 *
 * Each lock generates a fresh 32-byte `dataKey`, encrypts the tab snapshot under
 * it, and then *wraps* that dataKey once per authorized unlock path:
 *
 *   wrap_pw     RSA-OAEP under this profile's own public key
 *   wrap_master RSA-OAEP under the parent escrow public key
 *
 * Both wraps use the identical mechanism — a **key bundle**: an RSA-OAEP keypair
 * whose private half is encrypted under a password (PBKDF2 + AES-GCM). The
 * public half is plaintext and is all a lock needs.
 *
 * Why asymmetric even for the profile's own password: locking must encrypt the
 * snapshot at a moment when no password is present — the startup and idle
 * triggers fire with nobody typing. Symmetric wrapping would require the
 * extension to hold the key while locked, which is exactly the property that
 * makes "disabling the extension must not restore tabs" true. With a keypair,
 * locking needs only the public half, and no secret is retained.
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

/**
 * PBKDF2-HMAC-SHA256 over the password, producing the AES-GCM key-encryption key
 * that protects a bundle's private key.
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

/** @returns {Uint8Array} a fresh 32-byte data key, for exactly one snapshot */
export function generateDataKey() {
  return randomBytes(KEY_BYTES);
}

// --- key bundles ------------------------------------------------------------

/**
 * Create a key bundle: an RSA-OAEP keypair whose private half is encrypted under
 * `password`.
 *
 * Used for both unlock paths. A profile makes one for itself at first-run setup;
 * the parent makes one for escrow and distributes it via chrome.storage.managed.
 * Either way the bundle carries **no plaintext secret**, so it is safe to store
 * in the clear and safe to hand to every profile on the machine.
 *
 * @param {string} password
 * @param {{iterations?: number}} [opts]
 */
export async function createKeyBundle(password, opts = {}) {
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
  const bundle = await sealBundle(pkcs8, spki, password, iterations);
  wipe(pkcs8);
  return bundle;
}

/**
 * Wrap a dataKey to a bundle. Uses only the public half — the caller needs no
 * password, which is what lets an idle or startup lock encrypt a snapshot with
 * nobody present.
 *
 * @param {{keyId: string, pub: string}} bundle
 * @param {Uint8Array} dataKey
 */
export async function wrapToBundle(bundle, dataKey) {
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
 * Whether `bundle` is a usable key bundle.
 *
 * Structural checks are not enough: an escrow bundle can arrive by being pasted
 * into the options page or written into a managed-preferences plist by hand, so
 * the only answer worth trusting is whether its public half actually encrypts.
 * A bundle that passes here can wrap a dataKey at lock time — which is the one
 * moment where a broken bundle would be discovered far too late to matter.
 *
 * Says nothing about the private half: that needs the password, and the parent
 * is the only one who has it.
 *
 * @param {unknown} bundle
 * @returns {Promise<boolean>}
 */
export async function validateKeyBundle(bundle) {
  if (!bundle || typeof bundle !== 'object') return false;
  const { v, keyId, pub, privWrapped, salt, iterations } = bundle;
  if (v !== FORMAT_VERSION) return false;
  if (typeof keyId !== 'string' || typeof pub !== 'string' || typeof salt !== 'string') {
    return false;
  }
  if (!Number.isInteger(iterations) || iterations < 1) return false;
  if (!privWrapped || typeof privWrapped.iv !== 'string' || typeof privWrapped.ct !== 'string') {
    return false;
  }
  try {
    await wrapToBundle(bundle, generateDataKey());
    return true;
  } catch {
    return false;
  }
}

/**
 * Unlock path: password -> bundle's private key -> dataKey.
 *
 * There is deliberately no stored password *verifier*. RSA-OAEP and AES-GCM are
 * both authenticated, so a failed unwrap already is the wrong-password signal; a
 * verifier would double the PBKDF2 work per unlock to learn nothing new.
 *
 * @param {string} password
 * @param {object} bundle
 * @param {{keyId: string, ct: string}} wrap
 * @returns {Promise<Uint8Array>}
 * @throws {DecryptError} on a wrong password, or a wrap made for another keypair
 */
export async function unwrapWithBundle(password, bundle, wrap) {
  assertVersion(bundle);
  assertVersion(wrap);
  if (wrap.keyId !== bundle.keyId) {
    throw new DecryptError('This wrap was made for a different key');
  }
  const priv = await unwrapPrivateKey(password, bundle);
  try {
    const raw = await crypto.subtle.decrypt({ name: 'RSA-OAEP' }, priv, fromB64(wrap.ct));
    return new Uint8Array(raw);
  } catch {
    throw new DecryptError('Wrapped key could not be decrypted');
  }
}

/**
 * Re-encrypt a bundle's private key under a new password. The keypair itself is
 * unchanged, so `keyId`, `pub`, and every wrap ever made to this bundle stay
 * valid — changing a password never touches a snapshot, and rotating the master
 * password never invalidates a profile's escrow wrap.
 *
 * @param {string} oldPassword
 * @param {string} newPassword
 * @param {object} bundle
 * @param {{iterations?: number}} [opts]
 * @throws {DecryptError} if oldPassword is wrong
 */
export async function changeBundlePassword(oldPassword, newPassword, bundle, opts = {}) {
  const iterations = opts.iterations ?? bundle.iterations ?? PBKDF2_ITERATIONS;
  const priv = await unwrapPrivateKey(oldPassword, bundle);
  const pkcs8 = new Uint8Array(await crypto.subtle.exportKey('pkcs8', priv));
  const resealed = await sealBundle(pkcs8, fromB64(bundle.pub), newPassword, iterations);
  wipe(pkcs8);
  return { ...bundle, ...resealed };
}

/** Check a password against a bundle without needing a wrap to decrypt. */
export async function verifyBundlePassword(password, bundle) {
  try {
    await unwrapPrivateKey(password, bundle);
    return true;
  } catch {
    return false;
  }
}

async function sealBundle(pkcs8, spki, password, iterations) {
  const salt = randomBytes(SALT_BYTES);
  const iv = randomBytes(IV_BYTES);
  const kek = await deriveKek(password, salt, iterations);
  const privWrapped = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, kek, pkcs8);
  return {
    v: FORMAT_VERSION,
    keyId: await keyIdFor(spki),
    pub: toB64(spki),
    privWrapped: { iv: toB64(iv), ct: toB64(new Uint8Array(privWrapped)) },
    salt: toB64(salt),
    iterations,
  };
}

async function unwrapPrivateKey(password, bundle) {
  assertVersion(bundle);
  const kek = await deriveKek(password, fromB64(bundle.salt), bundle.iterations);
  let pkcs8;
  try {
    pkcs8 = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: fromB64(bundle.privWrapped.iv) },
      kek,
      fromB64(bundle.privWrapped.ct),
    );
  } catch {
    throw new DecryptError('Incorrect password');
  }
  // Marked extractable so changeBundlePassword can re-export it. The plaintext
  // key exists only for the duration of one unlock.
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

// --- snapshot encryption ----------------------------------------------------

/**
 * Encrypt the tab snapshot under a dataKey.
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

function assertVersion(record) {
  if (!record || typeof record !== 'object') {
    throw new DecryptError('Malformed record');
  }
  if (record.v !== FORMAT_VERSION) {
    throw new DecryptError(`Unsupported record version: ${record.v}`);
  }
}
