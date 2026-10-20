# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **Blind signing is now opt-in.** A `Blind signing` switch in the app Settings,
  stored in NVM and **off** on a fresh install; turning it on requires
  confirming a warning screen. Instructions that sign bytes the review screen
  cannot represent are refused with the new status word
  `SW_BLIND_SIGNING_DISABLED` (`0xB00A`) until the user enables it:
  `ECDSA_SIGN_HASH` (0x15), `HYBRID_SIGN_HASH` (0x16), `SIGN_DILITHIUM` (0x0F),
  and `HYBRID_SIGN_USEROP` (0x17) whenever it cannot be clear-signed: `callData`
  withheld, or any call other than `execute(address,uint256,bytes)` (e.g.
  `executeBatch`), whose review would show only the userOpHash. With the opt-in
  on, that review carries the SDK blind-signing warning. A UserOp whose
  `callData` is an `execute` call is clear-signed (To, Value) and keeps working
  with the setting off.
- `SET_SETTING` (0x0D), a test-only instruction for putting the device in a
  known settings state without driving the UI.
- The `SIGN_DILITHIUM` (0x0F) review shows which ML-DSA parameter set is about
  to sign (`Signer: ML-DSA-44` / `ML-DSA-65`). The instruction has no selector
  and uses the last loaded key, so the screen was the only place the user could
  learn it. Its finalize tests now run for both sets and verify the signature
  against the exported public key.

### Changed

- **BREAKING (hosts):** the four instructions above now answer `0xB00A` on a
  fresh install instead of signing. A host that needs them must tell the user
  to enable `Blind signing` in the app Settings first.
- **BREAKING (test harness):** the test-only instructions `DUMMY` (0x0A),
  `SAMPLE_IN_BALL` (0x0B) and `KEYGEN_DILITHIUM_CORE` (0x0C) are compiled out of
  production builds and answer `SWO_INVALID_INS` there. `KEYGEN_DILITHIUM_CORE`
  ran key generation from a host-supplied seed, which must not be reachable on a
  device holding funds. Build with `TEST_INS=1` (implied by `DEBUG=1`) to run
  `tests/standalone`. Note object files do not depend on `DEFINES`, so switching
  the flag requires removing `build/<target>` first.
- The settings menu no longer carries the two boilerplate `Dummy` switches. The
  NVM layout changed with them; existing installs re-initialise to the defaults
  on first run, which lands with blind signing off.
- The blind-sign branch of `SIGN_TX` triggers on the transaction memo, which is
  attacker-controlled; it is now behind the opt-in. It is demo code inherited
  from the boilerplate and should be removed.

### Removed

- **Swap support.** The app can no longer be called as a library by the
  Exchange app (`os_lib_call`): `ENABLE_TESTING_SWAP` is off, and `src/swap/`,
  the swap branches of `SIGN_TX` and `app_main`, `SW_SWAP_FAIL` (`0xC000`),
  `tests/swap/` and the `tests_swap` CI job are gone. It was boilerplate demo
  code (production `ENABLE_SWAP` was never on), it still looked the app up as
  "Boilerplate" so it had been broken since the rename, and it compiled swap
  code into every release binary.

### Fixed

- `HYBRID_SIGN_USEROP` has end-to-end coverage for the first time (finalize,
  clear-signing review, both signature halves, user rejection), for both
  parameter sets, with the userOpHash verified against an independent
  reimplementation of the ERC-4337 v0.7 construction.
- The `SIGN_DILITHIUM` finalize tests are no longer skipped; they needed the
  `*_with_warning` navigation scenarios, not the timing fix their docstring
  claimed.

## [2.4.0] - 2026-09-16

### Added

- **ML-DSA-65 (FIPS 204, security category 3)** beside ML-DSA-44, selected by
  P2 on every ML-DSA instruction (`0x00` = ML-DSA-44, `0x01` = ML-DSA-65; the
  low bits of P2 for `SIGN_TX_MLDSA`). `0x00` is what every existing client
  already sends, so the wire protocol is unchanged for them. See
  "ML-DSA PARAMETER SET (P2)" in `APP_SPECIFICATION.md`.
  - Hybrid `ECDSA + ML-DSA-65` signing through `HYBRID_SIGN_HASH` (0x16) and
    `HYBRID_SIGN_USEROP` (0x17), which fixes the parameter set on its first
    APDU and rejects a later one disagreeing.
  - `KEYGEN_DILITHIUM_CORE` / `KEYGEN_DILITHIUM` / `SAMPLE_IN_BALL` (tau = 49)
    and the chunk-fetch instructions, whose bounds follow the loaded key.
  - Seeds are derived with a per-set SLIP-0010 personalization
    (`"ML-DSA-44 seed"` unchanged, `"ML-DSA-65 seed"` new), so the two keys of
    one BIP32 path are independent.
  - The review screens name the scheme (`Signer: ECDSA + ML-DSA-65`).
- `tests/standalone/test_mldsa65.py`: the NIST ACVP ML-DSA keyGen vectors
  reproduced on-device for both sets (`tests/kat/acvp_mldsa_keygen.json`),
  parameter isolation, chunk bounds, SampleInBall weight, and hybrid /
  transaction signing verified against FIPS 204 with `cryptography`.
- `tests/standalone/test_stack_watermark.py` and `src/debug/stack_watermark.c`
  (`make DEBUG_STACK_WATERMARK=1`): the peak stack depth, readable over the
  wire, used to size the ML-DSA buffers per device.
- JavaScript client support for both parameter sets (`js/`, `--mldsa 65`),
  including `js/hybrid.js` for the hybrid flows.

### Fixed

- **Stack overflow on the hybrid signing path (Nano X, Stax, Flex).** The
  ML-DSA workspace runs inside the NBGL review callback, so the path peaked at
  ~18.8 KB of stack — more than those devices have (12.0 KB on Nano X and
  16.7 KB on Stax/Flex with the previous 4096-byte I/O buffer). This affected
  ML-DSA-44 as well; Speculos does not enforce the stack boundary, so it
  surfaced only under measurement. Enabling the SDK's low-RAM ML-DSA
  implementation (`HAVE_MLDSA_OPTIMIZATION`) brings the peak to ~14.2 KB, and
  the I/O buffer is now sized per device, leaving 2.4-6.6 KB free everywhere.
- `GET_PK_CHUNK` / `GET_SIG_CHUNK` bound their slices by the real size of the
  loaded key rather than the buffer, so the unused tail of an ML-DSA-44 key in
  the (larger) ML-DSA-65 buffers is never returned.
- The ML-DSA response is assembled by the I/O layer instead of a multi-kilobyte
  stack copy.

### Changed

- `SIGN_TX_MLDSA` (0x08) answers the public key and the signature in one APDU
  and needs an enlarged I/O buffer; on **Nano X** that buffer does not fit
  beside the stack, so the instruction now returns `SWO_INVALID_INS` there.
  Both parameter sets remain fully usable on Nano X through the hybrid and
  chunk-fetched flows.

## [2.1.0] - 2023-10-06

### Changed

- Improving the settings use case in order to be able to use app settings parameters stored in NVM
- add a NBGL use case choice when a setting switch is toggled

## [2.0.0] - 2023-07-10

### Added

- Stax porting
- Extensive CI, including mandatory `guidelines_enforcer.yml`
- Extensive `README.md` to modify/compile/test the application on most OS (Linux, MacOS, Windows)
- Extensive `Ragger` tests

### Changed

- Simplified `Makefile` (complexity delegated to the SDK's `Makefile.standard_app`)
- Simplified overall code (moved into the SDK)
- Improving several UI flows to fit Ledger UI guidelines
- Removing `TRY`/`CATCH` usage (using `_no_throw` SDK functions)
- Cleaning unnecessary resources (moved into the SDK)

### Fixed

- Multiple minor lint, prototype or misspell fixes

## [1.0.1] - 2021-01-11

### Fix

- Missing header includes

## [1.0.0] - 2020-11-19

### Added

- Initial commit with the brand new Boilerplate application
