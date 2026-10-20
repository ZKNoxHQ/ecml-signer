// Sign a Transaction on a Ledger running ECML-Signer (SIGN_TX_MLDSA, INS 0x08).
// Outputs a JSON bundle {path, mldsa, tx_hex, msg_hash_hex, pk_hex, sig_hex}
// that verify.js consumes.
//
// The device Keccak-256s the raw tx bytes and signs the digest with ML-DSA
// (empty context).
//
// Usage:
//   node sign.js
//   node sign.js --mldsa 65 --nonce 1 --to 0xde0b... --value 666 --memo mldsa \
//                --path "m/44'/1'/0'/0'/0'" --out signed.json
//
// Note: on Nano X the ML-DSA-65 response does not fit in the device's I/O
// buffer (kept small there for stack headroom) and the device answers 0x6A84;
// use hybrid.js, which fetches the key and signature through the chunk INS.

import { writeFileSync } from "node:fs";
import { keccak_256 } from "@noble/hashes/sha3.js";
import { openTransport, signTxMldsa } from "./lib/ledger.js";
import { serializeTransaction } from "./lib/transaction.js";
import { parseCommon, hex } from "./lib/args.js";

async function main() {
  const args = parseCommon(process.argv, {
    nonce: 1,
    to: "0xde0b295669a9fd93d5f28d9ec85e40f4cb697bae",
    value: 666,
    memo: "mldsa",
  });
  const p = args.param;

  const tx = serializeTransaction({
    nonce: Number(args.nonce),
    to: args.to,
    value: Number(args.value),
    memo: args.memo,
  });
  const msgHash = keccak_256(tx);

  console.error(`Scheme: ${p.name}`);
  console.error(`Path  : ${args.path}`);
  console.error(`Tx    : ${hex(tx)}`);
  console.error(`Hash  : ${hex(msgHash)}`);
  console.error("Approve the transaction on your Ledger...");

  const transport = await openTransport(args.transport);
  let pk, sig;
  try {
    ({ pk, sig } = await signTxMldsa(transport, args.path, tx, p));
  } finally {
    await transport.close();
  }

  const bundle = {
    path: args.path,
    mldsa: args.level,
    tx_hex: hex(tx),
    msg_hash_hex: hex(msgHash),
    pk_hex: hex(pk),
    sig_hex: hex(sig),
  };

  const json = JSON.stringify(bundle, null, 2);
  if (args.outFile) {
    writeFileSync(args.outFile, json);
    console.error(`Wrote ${args.outFile} (pk=${pk.length}B, sig=${sig.length}B)`);
  } else {
    console.log(json);
  }
}

main().catch((e) => {
  console.error(e.message || e);
  process.exit(1);
});
