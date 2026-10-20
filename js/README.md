# ECML-Signer JS CLI

Node CLI to keygen / sign a Transaction on a Ledger running ECML-Signer, and
verify the signature off-chain.

Verification currently runs locally via [`@noble/post-quantum`]. The
`ZKNOX_dilithium` contract on Sepolia (`0x2b31Db0F627Ad59d03D4F6b64bdB3F3315082108`)
needs the pk pre-expanded off-chain (into `aHat`, `tr`, unpacked `t1`) and
stored via SSTORE2 before its `verify()` can be called; that path is not
wired here yet. When you want it, the expansion logic lives in
`~/Documents/ZKNOXHQ/ETHDILITHIUM/js/utils_mldsa.js`.

## Setup

```
cd js
npm install
```

The Ledger must be connected via USB, unlocked, and running the ECML-Signer app.
On Linux you may need a udev rule for HID access — see
`https://github.com/LedgerHQ/udev-rules`.

## Commands

### `npm run keygen` — export the ML-DSA-44 public key

The app has no dedicated GET_PK for ML-DSA, so keygen signs a stub Transaction
and keeps the pk. You **will** be prompted on the device.

```
node keygen.js                                     # default path m/44'/1'/0'/0'/0'
node keygen.js "m/44'/1'/0'/0'/1'"                 # alternate path
node keygen.js "m/44'/1'/0'/0'/0'" pk.bin          # also write raw 1312 bytes
```

### `npm run sign` — sign a Transaction

```
node sign.js                                       # signs a demo tx, prints JSON
node sign.js --nonce 42 --to 0xde0b...bae \
             --value 1000 --memo hello \
             --out signed.json                     # write JSON to file
```

Output JSON:

```json
{
  "path": "m/44'/1'/0'/0'/0'",
  "tx_hex": "...",
  "msg_hash_hex": "...",   // keccak256(tx)
  "pk_hex": "...",         // 1312 bytes hex
  "sig_hex": "..."         // 2420 bytes hex
}
```

### `npm run userop` — clear-sign an ERC-4337 v0.7 UserOperation

Drives `HYBRID_SIGN_USEROP` (INS 0x17) through its four steps (path → metadata
→ packed fields → callData). The device recomputes the userOpHash, checks
`keccak256(callData)` against the declared `hashCallData`, and clear-signs two
shapes: a native transfer (To / Value) and an ERC-20 transfer (Token / To /
Amount, from `execute(token, 0, transfer(to, amount))`). Anything else, such as
`--data` with another inner call or `--blind`, is blind signing: refused unless
*Blind signing* is enabled in the app Settings.

```
node userop.js                                     # demo UserOp, ML-DSA-44
node userop.js --mldsa 65 --out userop.json        # then: node verify.js userop.json
node userop.js --to 0x...dead --value 1000000000000000000
node userop.js --token 0x...usdc --to 0x...bob --amount 1000000   # ERC-20, clear-signed
node userop.js --chain-id 1 --sender 0x... --nonce 7 --data <hex>   # blind: needs the opt-in
node userop.js --blind                             # withhold callData: hash-only review
```

`msg_hash_hex` in the output bundle is the userOpHash computed *here*, while
the signature is over the hash the *device* computed — so `verify.js` on the
bundle is an end-to-end cross-check of the two ERC-4337 hash constructions. A
mismatch shows up as `INVALID`.

`--blind` keeps `hashCallData` honest and only withholds the preimage, which is
what makes the device fall back to displaying the bare userOpHash. The
userOpHash is identical either way.

Note the callData step is a single APDU, so `--data` is capped at 123 bytes
(132 B of `execute` framing + payload ≤ 255).

### `npm run verify` — verify off-chain

```
node verify.js signed.json                                     # from sign.js output
node verify.js --pk <hex> --sig <hex> --msg-hash <hex>
node verify.js --pk <hex> --sig <hex> --tx <hex>               # hashes tx for you
```

Exits with status 0 on VALID, 2 on INVALID.

## Wire notes

- APDU: `CLA=0xE0 INS=0x08` (SIGN_TX_MLDSA). Chunk 0 carries the derivation
  path (BIP32 with all-hardened components — required by SLIP-0010 ed25519
  mode). Subsequent chunks carry the serialized Transaction, split at 255 B.
- Response: `pk_len(2 BE) || pk(1312) || sig_len(2 BE) || sig(≤2420)`. The
  "unwrap" is just stripping those length prefixes to hand `pk` / `sig` to a
  verifier.
- The device Keccak-256s the raw tx and signs the 32-byte digest with an
  empty ML-DSA context (`ctx=NULL, ctx_len=0`).


## ML-DSA-65

Every command takes `--mldsa 44` (default) or `--mldsa 65`; the level rides in
P2 of the APDU. The sizes follow: public key 1312 / 1952 bytes, signature
2420 / 3309.

```bash
node keygen.js --mldsa 65                        # derive and print the ML-DSA-65 pk
node sign.js   --mldsa 65 --value 1500           # sign a transaction
node hybrid.js --mldsa 65 --message hi \
               --out hybrid.json                 # ECDSA + ML-DSA-65 over keccak256(hi)
node userop.js --mldsa 65 --out userop.json      # ERC-4337 UserOp, clear-signed
node verify.js hybrid.json                       # level read from the bundle
```

The ML-DSA half of a hybrid signature is the pure FIPS 204 signature of the
32-byte hash with an empty context, so it verifies on-chain against
`ZKNOX_dilithium65` (ETHDILITHIUM) without any re-encoding: expand the public
key with `ETHDILITHIUM/js/mldsa65.js` (`publicKeyToBlob65`), store it with
`setKey`, and pass the 3309-byte signature to `verify`.

`--speculos[:host:port]` talks to an emulator instead of a USB device; the
device protocol itself is covered by `tests/standalone` (ragger + Speculos).
