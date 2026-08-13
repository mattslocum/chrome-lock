/**
 * CRX3 packing, and the extension id that falls out of the signing key.
 *
 * Chrome's own `--pack-extension` would do this, but it needs a Chrome binary
 * on the build machine and gives no way to check what went into the file. The
 * format is small enough to write out, and writing it out is what lets
 * `test/packaging.test.js` verify the signature and the id rather than trust
 * them.
 *
 * Layout:
 *
 *   "Cr24" | uint32le version=3 | uint32le headerLength | CrxFileHeader | zip
 *
 * `CrxFileHeader` is a protobuf with two fields we use: repeated
 * `sha256_with_rsa` proofs (field 2), each `{public_key, signature}`, and
 * `signed_header_data` (field 10000), which holds the 16-byte crx id.
 *
 * The signature covers a domain-separated concatenation, so a signature over
 * one extension's payload cannot be replayed as another's:
 *
 *   "CRX3 SignedData\x00" | uint32le(len(signedHeaderData)) | signedHeaderData | zip
 */

import { createHash, createSign, createPublicKey } from 'node:crypto';

const MAGIC = Buffer.from('Cr24', 'utf8');
const SIGNATURE_CONTEXT = Buffer.from('CRX3 SignedData\x00', 'latin1');

const FIELD_SHA256_WITH_RSA = 2;
const FIELD_SIGNED_HEADER_DATA = 10000;
const FIELD_PUBLIC_KEY = 1;
const FIELD_SIGNATURE = 2;
const FIELD_CRX_ID = 1;

const WIRE_LENGTH_DELIMITED = 2;

function varint(value) {
  const bytes = [];
  let remaining = value;
  do {
    let byte = remaining & 0x7f;
    remaining = Math.floor(remaining / 128);
    if (remaining > 0) byte |= 0x80;
    bytes.push(byte);
  } while (remaining > 0);
  return Buffer.from(bytes);
}

/** Encode one length-delimited protobuf field. */
function field(number, payload) {
  const tag = varint(number * 8 + WIRE_LENGTH_DELIMITED);
  return Buffer.concat([tag, varint(payload.length), payload]);
}

/** The DER SubjectPublicKeyInfo Chrome hashes to get the extension id. */
export function publicKeyDer(privateKeyPem) {
  return createPublicKey(privateKeyPem).export({ type: 'spki', format: 'der' });
}

/** The raw 16-byte crx id: the first half of SHA-256 over the SPKI. */
export function crxId(publicKeyDerBytes) {
  return createHash('sha256').update(publicKeyDerBytes).digest().subarray(0, 16);
}

/**
 * The extension id as Chrome displays it: the crx id in hex, with 0-9a-f
 * remapped onto a-p. The alphabet shift exists so ids can never be mistaken
 * for a hash; it carries no extra information.
 *
 * @param {Buffer} id  the 16 raw bytes from {@link crxId}
 * @returns {string} 32 characters, a-p
 */
export function extensionId(id) {
  return id
    .toString('hex')
    .split('')
    .map((c) => String.fromCharCode(c.charCodeAt(0) + (c >= '0' && c <= '9' ? 49 : 10)))
    .join('');
}

/** The extension id for a signing key, which is the only thing that fixes it. */
export function extensionIdForKey(privateKeyPem) {
  return extensionId(crxId(publicKeyDer(privateKeyPem)));
}

/**
 * Sign a zip payload into a CRX3 file.
 *
 * @param {Buffer} zipBytes
 * @param {string|Buffer} privateKeyPem  an RSA private key in PEM form
 * @returns {Buffer}
 */
export function makeCrx(zipBytes, privateKeyPem) {
  const publicKey = publicKeyDer(privateKeyPem);
  const signedHeaderData = field(FIELD_CRX_ID, crxId(publicKey));

  const signedHeaderLength = Buffer.alloc(4);
  signedHeaderLength.writeUInt32LE(signedHeaderData.length, 0);

  const signature = createSign('sha256')
    .update(SIGNATURE_CONTEXT)
    .update(signedHeaderLength)
    .update(signedHeaderData)
    .update(zipBytes)
    .sign(privateKeyPem);

  const proof = Buffer.concat([
    field(FIELD_PUBLIC_KEY, publicKey),
    field(FIELD_SIGNATURE, signature),
  ]);

  const header = Buffer.concat([
    field(FIELD_SHA256_WITH_RSA, proof),
    field(FIELD_SIGNED_HEADER_DATA, signedHeaderData),
  ]);

  const prologue = Buffer.alloc(12);
  MAGIC.copy(prologue, 0);
  prologue.writeUInt32LE(3, 4); // crx version
  prologue.writeUInt32LE(header.length, 8);

  return Buffer.concat([prologue, header, zipBytes]);
}

/**
 * Split a CRX3 file back into its parts, for verification.
 *
 * Deliberately strict: anything unexpected throws rather than being skipped,
 * because the only caller is a test asserting the packer produced what it
 * claimed to.
 *
 * @param {Buffer} crx
 * @returns {{headerLength: number, header: Buffer, zip: Buffer}}
 */
export function parseCrx(crx) {
  if (!crx.subarray(0, 4).equals(MAGIC)) throw new Error('not a crx: bad magic');
  const version = crx.readUInt32LE(4);
  if (version !== 3) throw new Error(`unsupported crx version ${version}`);
  const headerLength = crx.readUInt32LE(8);
  return {
    headerLength,
    header: crx.subarray(12, 12 + headerLength),
    zip: crx.subarray(12 + headerLength),
  };
}
