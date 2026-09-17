# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
