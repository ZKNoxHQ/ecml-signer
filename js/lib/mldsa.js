// ML-DSA parameter sets and APDU wire helpers for the ECML-Signer app.
//
// The ML-DSA INS take the parameter set in P2: 0x00 = ML-DSA-44 (the value
// every pre-existing client sends, so the protocol is unchanged for them),
// 0x01 = ML-DSA-65. SIGN_TX_MLDSA carries it in the low bits of P2, beside
// the 0x80 "more chunks" flag.

export const CLA = 0xe0;

export const INS = {
  SIGN_TX_MLDSA: 0x08,
  SAMPLE_IN_BALL: 0x0b,
  KEYGEN_DILITHIUM_CORE: 0x0c,
  KEYGEN_DILITHIUM: 0x11,
  GET_SIG_CHUNK: 0x12,
  GET_PK_CHUNK: 0x13,
  ECDSA_SIGN_HASH: 0x15,
  HYBRID_SIGN_HASH: 0x16,
  HYBRID_SIGN_USEROP: 0x17,
};

export const P2_MORE = 0x80;
export const P2_LAST = 0x00;
export const MAX_APDU_DATA = 255;

export const PARAMS = {
  44: { p2: 0x00, name: "ML-DSA-44", pkBytes: 1312, sigBytes: 2420, tau: 39, cTildeBytes: 32 },
  65: { p2: 0x01, name: "ML-DSA-65", pkBytes: 1952, sigBytes: 3309, tau: 49, cTildeBytes: 48 },
};

export function param(level) {
  const p = PARAMS[String(level)];
  if (!p) throw new Error(`unsupported ML-DSA level: ${level} (use 44 or 65)`);
  return p;
}

// SLIP-0010 ed25519-mode derivation requires all-hardened path components.
export const DEFAULT_PATH = "m/44'/1'/0'/0'/0'";

export function packDerivationPath(pathStr) {
  const parts = pathStr.replace(/^m\//, "").split("/");
  if (parts.length > 10) throw new Error(`derivation path too long: ${pathStr}`);
  const out = new Uint8Array(1 + 4 * parts.length);
  out[0] = parts.length;
  for (let i = 0; i < parts.length; i++) {
    const seg = parts[i];
    const hardened = seg.endsWith("'") || seg.endsWith("h");
    const n = parseInt(hardened ? seg.slice(0, -1) : seg, 10);
    if (!Number.isInteger(n) || n < 0) throw new Error(`bad path segment: ${seg}`);
    const v = (hardened ? 0x80000000 : 0) | (n & 0x7fffffff);
    out[1 + 4 * i + 0] = (v >>> 24) & 0xff;
    out[1 + 4 * i + 1] = (v >>> 16) & 0xff;
    out[1 + 4 * i + 2] = (v >>> 8) & 0xff;
    out[1 + 4 * i + 3] = v & 0xff;
  }
  return out;
}

/** The 255-byte chunks GET_PK_CHUNK / GET_SIG_CHUNK are fetched in. */
export function chunkSizes(total) {
  const out = [];
  for (let off = 0; off < total; off += MAX_APDU_DATA) {
    out.push(Math.min(MAX_APDU_DATA, total - off));
  }
  return out;
}

/** Fetch a whole buffer through a chunk INS (P1 = index, P2 = length). */
export async function fetchChunks(transport, ins, total) {
  const parts = [];
  const sizes = chunkSizes(total);
  for (let i = 0; i < sizes.length; i++) {
    const r = await transport.send(CLA, ins, i, sizes[i], Buffer.alloc(0));
    const data = r.slice(0, r.length - 2);
    if (data.length !== sizes[i]) {
      throw new Error(`chunk ${i}: got ${data.length} bytes, expected ${sizes[i]}`);
    }
    parts.push(Buffer.from(data));
  }
  const out = Buffer.concat(parts);
  if (out.length !== total) throw new Error(`fetched ${out.length} bytes, expected ${total}`);
  return new Uint8Array(out);
}

export async function getPublicKeyChunks(transport, p) {
  return fetchChunks(transport, INS.GET_PK_CHUNK, p.pkBytes);
}

export async function getSignatureChunks(transport, p) {
  return fetchChunks(transport, INS.GET_SIG_CHUNK, p.sigBytes);
}

/** KEYGEN_DILITHIUM (0x11): derive the ML-DSA key of a BIP32 path, return the pk. */
export async function keygen(transport, path, p) {
  await transport.send(CLA, INS.KEYGEN_DILITHIUM, 0x00, p.p2, Buffer.from(packDerivationPath(path)));
  return getPublicKeyChunks(transport, p);
}

/** Split the SIGN_TX_MLDSA response: pk_len(2 BE) || pk || sig_len(2 BE) || sig. */
export function parseMldsaResponse(buf) {
  if (buf.length < 4) throw new Error(`response too short: ${buf.length} bytes`);
  const pkLen = (buf[0] << 8) | buf[1];
  if (buf.length < 2 + pkLen + 2) throw new Error("truncated pk in response");
  const pk = buf.slice(2, 2 + pkLen);
  const rest = buf.slice(2 + pkLen);
  const sigLen = (rest[0] << 8) | rest[1];
  if (rest.length !== 2 + sigLen) {
    throw new Error(`trailing bytes: expected ${2 + sigLen}, got ${rest.length}`);
  }
  return { pk, sig: rest.slice(2, 2 + sigLen) };
}

/**
 * SIGN_TX_MLDSA (0x08): chunked upload of the path and the raw transaction,
 * one response carrying pk and signature. The device Keccak-256s the raw
 * transaction and signs the digest with an empty context.
 *
 * Note: on Nano X the ML-DSA-65 response (5265 B) does not fit in the device's
 * I/O buffer, which is kept small there for stack headroom; the device answers
 * 0x6A84 (SWO_INSUFFICIENT_MEMORY). Use hybridSignHash, or fetch the key and
 * signature with the chunk INS.
 */
export async function signTxMldsa(transport, path, txBytes, p) {
  await transport.send(CLA, INS.SIGN_TX_MLDSA, 0x00, P2_MORE | p.p2, Buffer.from(packDerivationPath(path)));

  const chunks = [];
  for (let off = 0; off < txBytes.length; off += MAX_APDU_DATA) {
    chunks.push(txBytes.slice(off, Math.min(off + MAX_APDU_DATA, txBytes.length)));
  }
  if (chunks.length === 0) throw new Error("empty transaction");

  let p1 = 1;
  for (let i = 0; i < chunks.length - 1; i++) {
    await transport.send(CLA, INS.SIGN_TX_MLDSA, p1, P2_MORE | p.p2, Buffer.from(chunks[i]));
    p1 += 1;
  }
  const last = await transport.send(
    CLA,
    INS.SIGN_TX_MLDSA,
    p1,
    P2_LAST | p.p2,
    Buffer.from(chunks[chunks.length - 1]),
  );
  return parseMldsaResponse(new Uint8Array(last.slice(0, last.length - 2)));
}

/**
 * HYBRID_SIGN_HASH (0x16): one user approval, two signatures of the same
 * 32-byte hash. The ECDSA half comes back inline as
 * [len:1][DER sig][v:1]; the ML-DSA half is fetched with the chunk INS.
 *
 * The ML-DSA signature is the pure FIPS 204 signature of the hash with an
 * empty context, i.e. of M' = 0x00 || 0x00 || hash: exactly what
 * ZKNOX_dilithium / ZKNOX_dilithium65 `verify(pk, bytes32 hash, sig)` checks
 * on-chain (ETHDILITHIUM).
 */
export async function hybridSignHash(transport, path, hash32, p) {
  if (hash32.length !== 32) throw new Error("hash must be 32 bytes");
  const data = Buffer.concat([Buffer.from(packDerivationPath(path)), Buffer.from(hash32)]);
  const r = await transport.send(CLA, INS.HYBRID_SIGN_HASH, 0x00, p.p2, data);
  const body = new Uint8Array(r.slice(0, r.length - 2));

  const ecdsaLen = body[0];
  const ecdsaSig = body.slice(1, 1 + ecdsaLen);
  const v = body[1 + ecdsaLen];

  const pk = await getPublicKeyChunks(transport, p);
  const sig = await getSignatureChunks(transport, p);
  return { ecdsa: { der: ecdsaSig, v }, mldsa: { pk, sig } };
}

/**
 * HYBRID_SIGN_USEROP (0x17): the 4-step ERC-4337 v0.7 flow. P2 carries the
 * parameter set on every step. Returns the same shape as hybridSignHash.
 */
export async function hybridSignUserOp(transport, path, { metadata, packed, callData }, p) {
  if (metadata.length !== 104) throw new Error("metadata must be 104 bytes");
  if (packed.length !== 192) throw new Error("packed fields must be 192 bytes");
  await transport.send(CLA, INS.HYBRID_SIGN_USEROP, 0x00, p.p2, Buffer.from(packDerivationPath(path)));
  await transport.send(CLA, INS.HYBRID_SIGN_USEROP, 0x01, p.p2, Buffer.from(metadata));
  await transport.send(CLA, INS.HYBRID_SIGN_USEROP, 0x02, p.p2, Buffer.from(packed));
  const r = await transport.send(CLA, INS.HYBRID_SIGN_USEROP, 0x03, p.p2, Buffer.from(callData ?? []));
  const body = new Uint8Array(r.slice(0, r.length - 2));

  const ecdsaLen = body[0];
  const ecdsaSig = body.slice(1, 1 + ecdsaLen);
  const v = body[1 + ecdsaLen];

  const pk = await getPublicKeyChunks(transport, p);
  const sig = await getSignatureChunks(transport, p);
  return { ecdsa: { der: ecdsaSig, v }, mldsa: { pk, sig } };
}
