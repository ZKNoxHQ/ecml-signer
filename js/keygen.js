// Export the ML-DSA public key of a BIP32 path from a Ledger running
// ECML-Signer. Uses KEYGEN_DILITHIUM (INS 0x11) + GET_PK_CHUNK (0x13), so no
// signature and no on-device approval are involved.
//
// Usage:
//   node keygen.js                             # ML-DSA-44, default path
//   node keygen.js --mldsa 65                  # ML-DSA-65
//   node keygen.js --mldsa 65 --path "m/44'/1'/0'/0'/1'" --out pk.bin
//   node keygen.js --mldsa 65 --speculos       # against a Speculos emulator

import { writeFileSync } from "node:fs";
import { openTransport, keygen } from "./lib/ledger.js";
import { parseCommon, hex } from "./lib/args.js";

async function main() {
  const args = parseCommon(process.argv);
  const p = args.param;

  console.error(`Scheme: ${p.name}`);
  console.error(`Path  : ${args.path}`);

  const transport = await openTransport(args.transport);
  try {
    const pk = await keygen(transport, args.path, p);
    if (pk.length !== p.pkBytes) {
      throw new Error(`unexpected pk length ${pk.length}, expected ${p.pkBytes}`);
    }
    console.log(hex(pk));
    if (args.outFile) {
      writeFileSync(args.outFile, Buffer.from(pk));
      console.error(`Wrote ${pk.length} bytes to ${args.outFile}`);
    }
  } finally {
    await transport.close();
  }
}

main().catch((e) => {
  console.error(e.message || e);
  process.exit(1);
});
