// Hybrid ECDSA + ML-DSA signature of a 32-byte hash (HYBRID_SIGN_HASH, INS 0x16).
//
// One approval on the device produces both halves: the secp256k1 signature
// comes back inline, the ML-DSA key and signature through the chunk INS.
// The ML-DSA half is the pure FIPS 204 signature of the hash with an empty
// context, i.e. of M' = 0x00 || 0x00 || hash -- exactly what
// ZKNOX_dilithium (ML-DSA-44) and ZKNOX_dilithium65 (ML-DSA-65)
// `verify(pk, bytes32 hash, sig)` check on-chain (ETHDILITHIUM).
//
// Usage:
//   node hybrid.js --hash <32-byte hex> [--mldsa 65] [--path <p>] [--out h.json]
//   node hybrid.js --message "hello"          # keccak256 of the message
//   node hybrid.js --mldsa 65 --speculos      # against a Speculos emulator
//
// The JSON output feeds verify.js (ML-DSA half) and
// ETHDILITHIUM/js/sign65.js / the on-chain verifier.

import { writeFileSync } from "node:fs";
import { keccak_256 } from "@noble/hashes/sha3.js";
import { openTransport, hybridSignHash } from "./lib/ledger.js";
import { parseCommon, hex, hexToBytes } from "./lib/args.js";

async function main() {
  const args = parseCommon(process.argv, { hash: null, message: null });
  const p = args.param;

  let hash32;
  if (args.hash) hash32 = hexToBytes(args.hash);
  else if (args.message) hash32 = keccak_256(new TextEncoder().encode(args.message));
  else hash32 = keccak_256(new TextEncoder().encode("ECML-Signer hybrid demo"));
  if (hash32.length !== 32) throw new Error("hash must be 32 bytes");

  console.error(`Scheme: ECDSA + ${p.name}`);
  console.error(`Path  : ${args.path}`);
  console.error(`Hash  : ${hex(hash32)}`);
  console.error("Approve the hybrid signature on your Ledger...");

  const transport = await openTransport(args.transport);
  let result;
  try {
    result = await hybridSignHash(transport, args.path, hash32, p);
  } finally {
    await transport.close();
  }

  const bundle = {
    path: args.path,
    mldsa: args.level,
    msg_hash_hex: hex(hash32),
    ecdsa_der_hex: hex(result.ecdsa.der),
    ecdsa_v: result.ecdsa.v,
    pk_hex: hex(result.mldsa.pk),
    sig_hex: hex(result.mldsa.sig),
  };

  const json = JSON.stringify(bundle, null, 2);
  if (args.outFile) {
    writeFileSync(args.outFile, json);
    console.error(
      `Wrote ${args.outFile} (ecdsa=${result.ecdsa.der.length}B, ` +
        `pk=${result.mldsa.pk.length}B, sig=${result.mldsa.sig.length}B)`,
    );
  } else {
    console.log(json);
  }
}

main().catch((e) => {
  console.error(e.message || e);
  process.exit(1);
});
