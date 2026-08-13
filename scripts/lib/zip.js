/**
 * A minimal ZIP writer.
 *
 * A `.crx` is a signed header followed by an ordinary zip, so packing needs a
 * zip and the project has no dependencies to reach for. This writes the subset
 * of the format Chrome reads: local headers, deflated entries, and a central
 * directory. No zip64, no encryption, no directory entries — none of which a
 * dozen-file extension needs.
 *
 * Archives are **reproducible**: entries are sorted, timestamps are fixed, and
 * deflate is called at a fixed level, so the same sources pack to the same
 * bytes. That is what makes "tag it, keep the CRX, never auto-update"
 * (architecture.md §10.8) checkable rather than a matter of trust — a rebuilt
 * crx can be compared against the one that was shipped.
 */

import { deflateRawSync } from 'node:zlib';

// 1980-01-01 00:00:00, the earliest a DOS timestamp can express. Any fixed
// value would do; this one is the conventional choice for reproducible builds.
const DOS_TIME = 0;
const DOS_DATE = (1 << 5) | 1; // year 1980, month 1, day 1

const CRC_TABLE = (() => {
  const table = new Uint32Array(256);
  for (let i = 0; i < 256; i += 1) {
    let c = i;
    for (let bit = 0; bit < 8; bit += 1) {
      c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    }
    table[i] = c >>> 0;
  }
  return table;
})();

function crc32(buffer) {
  let c = 0xffffffff;
  for (let i = 0; i < buffer.length; i += 1) {
    c = CRC_TABLE[(c ^ buffer[i]) & 0xff] ^ (c >>> 8);
  }
  return (c ^ 0xffffffff) >>> 0;
}

/**
 * Pack files into a zip archive.
 *
 * @param {Array<{name: string, data: Buffer}>} files  archive-relative paths
 *   (forward slashes) and their contents. Order does not matter; entries are
 *   sorted by name so the output is stable.
 * @returns {Buffer}
 */
export function makeZip(files) {
  const sorted = [...files].sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0));

  const local = [];
  const central = [];
  let offset = 0;

  for (const file of sorted) {
    const name = Buffer.from(file.name, 'utf8');
    const crc = crc32(file.data);
    const compressed = deflateRawSync(file.data, { level: 9 });

    // Deflate can be larger than the input on incompressible data; storing it
    // uncompressed is both smaller and what every other zip writer does.
    const useDeflate = compressed.length < file.data.length;
    const body = useDeflate ? compressed : file.data;
    const method = useDeflate ? 8 : 0;

    const header = Buffer.alloc(30);
    header.writeUInt32LE(0x04034b50, 0); // local file header signature
    header.writeUInt16LE(20, 4); // version needed to extract: 2.0
    header.writeUInt16LE(0x0800, 6); // flags: names are UTF-8
    header.writeUInt16LE(method, 8);
    header.writeUInt16LE(DOS_TIME, 10);
    header.writeUInt16LE(DOS_DATE, 12);
    header.writeUInt32LE(crc, 14);
    header.writeUInt32LE(body.length, 18);
    header.writeUInt32LE(file.data.length, 22);
    header.writeUInt16LE(name.length, 26);
    header.writeUInt16LE(0, 28); // no extra field

    local.push(header, name, body);

    const entry = Buffer.alloc(46);
    entry.writeUInt32LE(0x02014b50, 0); // central directory signature
    entry.writeUInt16LE(20, 4); // version made by
    entry.writeUInt16LE(20, 6); // version needed
    entry.writeUInt16LE(0x0800, 8);
    entry.writeUInt16LE(method, 10);
    entry.writeUInt16LE(DOS_TIME, 12);
    entry.writeUInt16LE(DOS_DATE, 14);
    entry.writeUInt32LE(crc, 16);
    entry.writeUInt32LE(body.length, 20);
    entry.writeUInt32LE(file.data.length, 24);
    entry.writeUInt16LE(name.length, 28);
    entry.writeUInt16LE(0, 30); // extra length
    entry.writeUInt16LE(0, 32); // comment length
    entry.writeUInt16LE(0, 34); // disk number
    entry.writeUInt16LE(0, 36); // internal attributes
    entry.writeUInt32LE(0o644 << 16, 38); // external attributes: regular file
    entry.writeUInt32LE(offset, 42);

    central.push(entry, name);

    offset += header.length + name.length + body.length;
  }

  const localBytes = Buffer.concat(local);
  const centralBytes = Buffer.concat(central);

  const end = Buffer.alloc(22);
  end.writeUInt32LE(0x06054b50, 0); // end of central directory
  end.writeUInt16LE(0, 4); // this disk
  end.writeUInt16LE(0, 6); // disk with central directory
  end.writeUInt16LE(sorted.length, 8);
  end.writeUInt16LE(sorted.length, 10);
  end.writeUInt32LE(centralBytes.length, 12);
  end.writeUInt32LE(localBytes.length, 16);
  end.writeUInt16LE(0, 20); // no archive comment

  return Buffer.concat([localBytes, centralBytes, end]);
}
