// Port of tests/application_client/boilerplate_transaction.py Transaction.serialize
// Layout: nonce(u64 BE) || to(20) || value(u64 BE) || varint(memo_len) || memo(ascii)

const UINT64_MAX = (1n << 64n) - 1n;

function u64BE(n) {
  let v = BigInt(n);
  if (v < 0n || v > UINT64_MAX) throw new Error(`u64 out of range: ${n}`);
  const b = new Uint8Array(8);
  for (let i = 7; i >= 0; i--) {
    b[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  return b;
}

function writeVarint(n) {
  if (n < 0xfc) return Uint8Array.of(n);
  if (n <= 0xffff) {
    const b = new Uint8Array(3);
    b[0] = 0xfd;
    b[1] = n & 0xff;
    b[2] = (n >> 8) & 0xff;
    return b;
  }
  if (n <= 0xffffffff) {
    const b = new Uint8Array(5);
    b[0] = 0xfe;
    for (let i = 0; i < 4; i++) b[1 + i] = (n >> (8 * i)) & 0xff;
    return b;
  }
  throw new Error("varint too large for this CLI");
}

function parseAddress(hex) {
  const s = hex.startsWith("0x") ? hex.slice(2) : hex;
  if (s.length !== 40) throw new Error(`address must be 20 bytes: ${hex}`);
  const out = new Uint8Array(20);
  for (let i = 0; i < 20; i++) out[i] = parseInt(s.slice(2 * i, 2 * i + 2), 16);
  return out;
}

export function serializeTransaction({ nonce, to, value, memo }) {
  const toBytes = parseAddress(to);
  const memoBytes = new TextEncoder().encode(memo);
  const varintLen = writeVarint(memoBytes.length);
  const parts = [u64BE(nonce), toBytes, u64BE(value), varintLen, memoBytes];
  const total = parts.reduce((s, p) => s + p.length, 0);
  const buf = new Uint8Array(total);
  let off = 0;
  for (const p of parts) {
    buf.set(p, off);
    off += p.length;
  }
  return buf;
}
