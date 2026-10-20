// Verify an ML-DSA signature produced by the device, off-chain, via
// @noble/post-quantum. The device signs a 32-byte hash with an empty context,
// matching ml_dsa44.verify / ml_dsa65.verify on that hash.
//
// Usage:
//   node verify.js <signed.json>                                   # sign.js / hybrid.js output
//   node verify.js --pk <hex> --sig <hex> --msg-hash <hex> [--mldsa 65]
//   node verify.js --pk <hex> --sig <hex> --tx <hex>               # will keccak256 the tx

import { readFileSync } from "node:fs";
import { keccak_256 } from "@noble/hashes/sha3.js";
import { ml_dsa44, ml_dsa65 } from "@noble/post-quantum/ml-dsa";
import { PARAMS } from "./lib/mldsa.js";
import { hexToBytes } from "./lib/args.js";

const VERIFIER = { 44: ml_dsa44, 65: ml_dsa65 };

function parseArgs(argv) {
  const out = { file: null, pk: null, sig: null, msgHash: null, tx: null, level: null };
  const positional = [];
  for (let i = 2; i < argv.length; i++) {
    const k = argv[i];
    if (!k.startsWith("--")) { positional.push(k); continue; }
    const v = argv[++i];
    switch (k) {
      case "--pk": out.pk = v; break;
      case "--sig": out.sig = v; break;
      case "--msg-hash": out.msgHash = v; break;
      case "--tx": out.tx = v; break;
      case "--mldsa": out.level = Number(v); break;
      default: throw new Error(`unknown flag: ${k}`);
    }
  }
  if (positional.length === 1) out.file = positional[0];
  else if (positional.length > 1) throw new Error("too many positional args");
  return out;
}

function loadInputs(args) {
  if (args.file) {
    const j = JSON.parse(readFileSync(args.file, "utf8"));
    return {
      pk: hexToBytes(j.pk_hex),
      sig: hexToBytes(j.sig_hex),
      msgHash: hexToBytes(j.msg_hash_hex),
      level: args.level ?? j.mldsa ?? null,
    };
  }
  if (!args.pk || !args.sig) throw new Error("need --pk and --sig (or a signed.json path)");
  const pk = hexToBytes(args.pk);
  const sig = hexToBytes(args.sig);
  let msgHash;
  if (args.msgHash) msgHash = hexToBytes(args.msgHash);
  else if (args.tx) msgHash = keccak_256(hexToBytes(args.tx));
  else throw new Error("need --msg-hash or --tx");
  return { pk, sig, msgHash, level: args.level };
}

function main() {
  const args = parseArgs(process.argv);
  const { pk, sig, msgHash, level: loadedLevel } = loadInputs(args);

  // The parameter set is implied by the key length unless given.
  let level = args.level ?? loadedLevel;
  if (!level) {
    level = Object.keys(PARAMS).find((l) => PARAMS[l].pkBytes === pk.length);
    if (!level) throw new Error(`cannot infer the parameter set from a ${pk.length}-byte pk`);
  }
  const p = PARAMS[String(level)];
  if (!p) throw new Error(`unsupported ML-DSA level: ${level}`);

  if (pk.length !== p.pkBytes) throw new Error(`pk length ${pk.length} != ${p.pkBytes} (${p.name})`);
  if (sig.length !== p.sigBytes) throw new Error(`sig length ${sig.length} != ${p.sigBytes} (${p.name})`);
  if (msgHash.length !== 32) throw new Error(`msg_hash length ${msgHash.length} != 32`);

  const ok = VERIFIER[String(level)].verify(pk, msgHash, sig);
  console.log(`${p.name}: ${ok ? "VALID" : "INVALID"}`);
  if (!ok) process.exit(2);
}

main();
