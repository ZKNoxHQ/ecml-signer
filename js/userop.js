// Hybrid ECDSA + ML-DSA clear-signing of an ERC-4337 v0.7 UserOperation
// (HYBRID_SIGN_USEROP, INS 0x17).
//
// The device is fed the UserOp in four APDUs (path / metadata / packed fields /
// callData), recomputes the userOpHash itself, verifies keccak256(callData)
// against the declared hashCallData, and clear-signs `To` / `Value` extracted
// from execute(address,uint256,bytes). One approval yields both halves: ECDSA
// inline, ML-DSA pk+sig through the chunk INS.
//
// This doubles as a cross-check of the device's hash construction: the
// userOpHash below is computed independently here, and the ML-DSA signature is
// over the *device's* hash. If the two constructions disagree, verify.js on the
// resulting bundle reports INVALID.
//
// Usage:
//   node userop.js                                  # demo UserOp, ML-DSA-44
//   node userop.js --mldsa 65 --out userop.json     # then: node verify.js userop.json
//   node userop.js --to 0x2222... --value 1000000000000000000
//   node userop.js --token 0x4444... --to 0x3333... --amount 1000000   # ERC-20 transfer
//   node userop.js --blind                          # send no callData (hash-only review)
//
// The device clear-signs exactly two shapes: a native transfer (To / Value)
// and an ERC-20 transfer (Token / To / Amount). Anything else, including
// --data with another inner call, is blind signing and is refused unless the
// user enabled "Blind signing" in the app Settings.
//   node userop.js --mldsa 65 --speculos            # against a Speculos emulator

import { writeFileSync } from "node:fs";
import { keccak_256 } from "@noble/hashes/sha3.js";
import { openTransport, hybridSignUserOp } from "./lib/ledger.js";
import { parseCommon, hex, hexToBytes } from "./lib/args.js";

// EntryPoint v0.7, canonical address on every chain.
const ENTRY_POINT_V07 = "0x0000000071727de22e5e9d8baf0edac6f37da032";
// execute(address,uint256,bytes)
const EXECUTE_SELECTOR = "b61d27f6";

const concat = (...parts) => Buffer.concat(parts.map((p) => Buffer.from(p)));

// Big-endian 32-byte ABI word from a decimal or 0x-hex scalar.
function word(value) {
  const v = BigInt(value);
  if (v < 0n || v >= 1n << 256n) throw new Error(`value out of uint256 range: ${value}`);
  return Buffer.from(v.toString(16).padStart(64, "0"), "hex");
}

// 20-byte address, right-aligned in a 32-byte word when ABI-encoded.
function address(a) {
  const b = hexToBytes(a);
  if (b.length !== 20) throw new Error(`address must be 20 bytes: ${a}`);
  return Buffer.from(b);
}

const padWord = (addr20) => concat(Buffer.alloc(12), addr20);

// ERC-20 transfer(address to, uint256 amount) inner call.
const ERC20_TRANSFER_SELECTOR = "a9059cbb";
function encodeErc20Transfer(to, amount) {
  return concat(Buffer.from(ERC20_TRANSFER_SELECTOR, "hex"), padWord(to), word(amount));
}

// execute(dest, value, data) calldata. `data` is the inner bytes payload.
function encodeExecute(dest, value, data) {
  const tail = concat(data, Buffer.alloc((32 - (data.length % 32)) % 32));
  return concat(
    Buffer.from(EXECUTE_SELECTOR, "hex"),
    padWord(dest),
    word(value),
    word(0x60), // offset of the bytes argument
    word(data.length),
    tail,
  );
}

// Mirror of compute_userop_hash() in src/handler/hybrid_sign_userop.c:
//   inner = keccak256(abi.encode(sender, nonce, hashInitCode, hashCallData,
//                                accountGasLimits, preVerificationGas,
//                                gasFees, hashPaymasterAndData))
//   userOpHash = keccak256(abi.encode(inner, entryPoint, chainId))
function computeUserOpHash({ sender, nonce, packed, entryPoint, chainId }) {
  const inner = keccak_256(concat(padWord(sender), nonce, packed));
  return keccak_256(concat(inner, padWord(entryPoint), chainId));
}

async function main() {
  const args = parseCommon(process.argv, {
    chainId: "11155111", // Sepolia
    entryPoint: ENTRY_POINT_V07,
    sender: "0x1111111111111111111111111111111111111111",
    nonce: "42",
    to: "0x2222222222222222222222222222222222222222",
    value: "1000000000", // wei
    data: "", // inner payload of execute() (anything but a transfer is blind)
    token: "", // ERC-20 contract: send `--amount` of it to `--to`
    amount: "0", // ERC-20 amount, in base units
    blind: false, // send an empty callData step
  });
  const p = args.param;

  const chainId = word(args.chainId);
  const entryPoint = address(args.entryPoint);
  const sender = address(args.sender);
  const nonce = word(args.nonce);

  if (args.token && args.data) throw new Error("--token and --data are exclusive");
  // ERC-20: execute(token, 0, transfer(to, amount)); native: execute(to, value, data).
  const callData = args.token
    ? encodeExecute(address(args.token), 0, encodeErc20Transfer(address(args.to), args.amount))
    : encodeExecute(
        address(args.to),
        args.value,
        args.data ? Buffer.from(hexToBytes(args.data)) : Buffer.alloc(0),
      );

  // The callData step is a single APDU, so the payload must fit in one lc.
  if (callData.length > 255) {
    throw new Error(`callData is ${callData.length} bytes, max 255 (--data is too long)`);
  }

  // hashCallData always commits to the real callData. With --blind we simply
  // withhold the preimage, which is what makes the device fall back to showing
  // the bare userOpHash instead of To/Value.
  const packed = concat(
    Buffer.alloc(32), // hashInitCode — no initCode
    keccak_256(callData), // hashCallData
    Buffer.alloc(32), // accountGasLimits
    Buffer.alloc(32), // preVerificationGas
    Buffer.alloc(32), // gasFees
    Buffer.alloc(32), // hashPaymasterAndData
  );

  const metadata = concat(chainId, entryPoint, sender, nonce); // 104 B
  const userOpHash = computeUserOpHash({ sender, nonce, packed, entryPoint, chainId });

  console.error(`Scheme  : ECDSA + ${p.name}`);
  console.error(`Path    : ${args.path}`);
  console.error(`Chain   : ${BigInt(args.chainId)}`);
  console.error(`Sender  : 0x${hex(sender)}`);
  if (args.blind) {
    console.error("CallData: (withheld — device reviews the userOpHash only)");
  } else if (args.token) {
    console.error(`Token   : ${args.token}`);
    console.error(`To      : ${args.to}`);
    console.error(`Amount  : ${BigInt(args.amount)} (base units)`);
  } else {
    console.error(`To      : ${args.to}`);
    console.error(`Value   : ${BigInt(args.value)} wei`);
    if (args.data) console.error("Data    : custom inner call -> blind signing (opt-in needed)");
  }
  console.error(`UserOpHash: ${hex(userOpHash)}`);
  console.error("Approve the UserOp on your Ledger...");

  const transport = await openTransport(args.transport);
  let result;
  try {
    result = await hybridSignUserOp(
      transport,
      args.path,
      { metadata, packed, callData: args.blind ? Buffer.alloc(0) : callData },
      p,
    );
  } finally {
    await transport.close();
  }

  const bundle = {
    path: args.path,
    mldsa: args.level,
    // The device signs the hash it computed; verify.js checking this locally
    // computed one is the cross-check.
    msg_hash_hex: hex(userOpHash),
    userop: {
      chain_id: String(BigInt(args.chainId)),
      entry_point: `0x${hex(entryPoint)}`,
      sender: `0x${hex(sender)}`,
      nonce: String(BigInt(args.nonce)),
      call_data_hex: hex(callData),
      clear_signed: !args.blind && !args.data,
    },
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
