// Crop a non-interlaced PNG to its top N rows. Safe because PNG row filters
// only reference the row above, so dropping bottom scanlines leaves the kept
// rows' filter chain intact. Usage: node pngcrop.mjs <in.png> <out.png> <rows>
//
// Used by render.sh to trim the ~87px of chrome that headless Chrome reserves
// off the bottom of a --window-size render (see render.sh for the why).
import { readFileSync, writeFileSync } from 'node:fs';
import zlib from 'node:zlib';

const [, , inPath, outPath, rowsArg] = process.argv;
const keepRows = parseInt(rowsArg, 10);
const buf = readFileSync(inPath);
const SIG = Buffer.from([137, 80, 78, 71, 13, 10, 26, 10]);
if (!buf.subarray(0, 8).equals(SIG)) throw new Error('not a PNG');

const crcTable = (() => {
  const t = new Uint32Array(256);
  for (let n = 0; n < 256; n++) {
    let c = n;
    for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    t[n] = c >>> 0;
  }
  return t;
})();
function crc32(bytes) {
  let c = 0xffffffff;
  for (let i = 0; i < bytes.length; i++) c = crcTable[(c ^ bytes[i]) & 0xff] ^ (c >>> 8);
  return (c ^ 0xffffffff) >>> 0;
}
function chunk(type, data) {
  const len = Buffer.alloc(4); len.writeUInt32BE(data.length, 0);
  const typeBuf = Buffer.from(type, 'ascii');
  const crcBuf = Buffer.alloc(4);
  crcBuf.writeUInt32BE(crc32(Buffer.concat([typeBuf, data])), 0);
  return Buffer.concat([len, typeBuf, data, crcBuf]);
}

let off = 8, ihdr = null; const idats = [];
let width, height, colorType, bitDepth, interlace;
while (off < buf.length) {
  const len = buf.readUInt32BE(off);
  const type = buf.toString('ascii', off + 4, off + 8);
  const data = buf.subarray(off + 8, off + 8 + len);
  if (type === 'IHDR') {
    ihdr = Buffer.from(data);
    width = data.readUInt32BE(0); height = data.readUInt32BE(4);
    bitDepth = data[8]; colorType = data[9]; interlace = data[12];
  } else if (type === 'IDAT') idats.push(Buffer.from(data));
  off += 12 + len;
  if (type === 'IEND') break;
}
if (interlace !== 0) throw new Error('interlaced not supported');
if (bitDepth !== 8) throw new Error('bitDepth ' + bitDepth + ' not supported');
const channels = { 0: 1, 2: 3, 3: 1, 4: 2, 6: 4 }[colorType];
if (!channels) throw new Error('colorType ' + colorType + ' not supported');
const stride = 1 + width * channels;

const raw = zlib.inflateSync(Buffer.concat(idats));
if (keepRows > height) throw new Error(`keepRows ${keepRows} > height ${height}`);
const cropped = raw.subarray(0, keepRows * stride);

const newIhdr = Buffer.from(ihdr);
newIhdr.writeUInt32BE(keepRows, 4);
const newIdat = zlib.deflateSync(cropped, { level: 9 });
writeFileSync(outPath, Buffer.concat([
  SIG, chunk('IHDR', newIhdr), chunk('IDAT', newIdat), chunk('IEND', Buffer.alloc(0)),
]));
console.log(`${inPath} ${width}x${height} (ct${colorType}) -> ${outPath} ${width}x${keepRows}`);
