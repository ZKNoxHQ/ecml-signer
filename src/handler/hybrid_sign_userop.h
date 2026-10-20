#pragma once

#include <stdint.h>
#include <stdbool.h>

#include "buffer.h"
#include "lcx_mldsa.h"

/**
 * HYBRID_SIGN_USEROP (INS 0x17) — ERC-4337 v0.7 UserOperation hybrid clear-signing.
 *
 * Ported from ZKNOX-HW-MLDSA; this INS is the one ZKNOX got right (proper
 * step-guarded state machine, hash-verified callData, clear-signing review).
 *
 * Multi-APDU protocol (P2 = ML-DSA parameter set on EVERY APDU of the
 * sequence: 0x00 = ML-DSA-44, 0x01 = ML-DSA-65; the set is fixed by the
 * P1 = 0x00 APDU and a later APDU carrying another value is
 * SWO_INCORRECT_P1_P2):
 *   P1 = 0x00  BIP32 path.
 *              cdata = [path_len:1][path:4*path_len]
 *   P1 = 0x01  UserOp metadata (exactly 104 bytes):
 *              cdata = chain_id(32) || entry_point(20) || sender(20) || nonce(32)
 *   P1 = 0x02  Packed fields (exactly 192 bytes = 6 * 32):
 *              cdata = hashInitCode(32) || hashCallData(32) || accountGasLimits(32)
 *                    || preVerificationGas(32) || gasFees(32) || hashPaymasterAndData(32)
 *   P1 = 0x03  Raw callData (0..255 bytes). Triggers finalize.
 *              If len > 0: device verifies keccak256(callData) == hashCallData
 *              (SWO_INCORRECT_DATA otherwise), then decodes it as below.
 *              If len == 0: no callData verification.
 *
 *              Clear signing requires a canonically ABI-encoded
 *              execute(address dest, uint256 value, bytes data) whose inner
 *              `data` is one of:
 *                - empty: a native transfer, shown as To / Value (wei);
 *                - transfer(address to, uint256 amount) with value == 0: an
 *                  ERC-20 transfer, shown as Token / To / Amount (base units).
 *              Anything else — callData withheld, another outer call such as
 *              executeBatch, any other inner call (approve, ...), or a
 *              non-canonical encoding — leaves nothing trustworthy to show but
 *              the userOpHash, which is blind signing: it is refused with
 *              SW_BLIND_SIGNING_DISABLED unless the user enabled blind signing
 *              in Settings, and otherwise reviewed behind the SDK blind-signing
 *              warning.
 *
 *              Once callData is processed the device computes:
 *                userOpHash = keccak256(abi.encode(
 *                    keccak256(pack(sender,nonce,hashInitCode,hashCallData,
 *                                   accountGasLimits,preVerificationGas,
 *                                   gasFees,hashPaymasterAndData)),
 *                    entryPoint, chainId))
 *              stores it in G_context.tx_info.m_hash, and triggers the review.
 *
 *   Any P1 out of order returns SWO_INCORRECT_P1_P2.
 *   Wrong lc for P1 = 0x01 / 0x02 returns SWO_WRONG_DATA_LENGTH.
 *   callData hash mismatch returns SWO_INCORRECT_DATA and wipes the accumulator.
 *
 * Response (async, after user approval): same layout as HYBRID_SIGN_HASH —
 * ECDSA sig inline, ML-DSA pk/sig via GET_PK_CHUNK / GET_SIG_CHUNK (sizes of
 * the parameter set).
 */
int handler_hybrid_sign_userop(buffer_t *cdata, uint8_t p1, MLDSA_param_t param);

/**
 * Accessors used by the NBGL display layer. All pointers are into a static
 * accumulator that lives from the first APDU (P1=0x00) until the review
 * completes; they are wiped on rejection or fatal error mid-flow.
 */
/** What the device could decode from the callData, i.e. what it can clear-sign. */
typedef enum {
    USEROP_CALL_NONE = 0,  // nothing decodable: blind signing (userOpHash only)
    USEROP_CALL_NATIVE,    // execute(dest, value, "")           -> To, Value (wei)
    USEROP_CALL_ERC20,     // execute(token, 0, transfer(to, n)) -> Token, To, Amount
} userop_call_kind_t;

const uint8_t *userop_get_sender(void);
const uint8_t *userop_get_chain_id(void);
userop_call_kind_t userop_get_call_kind(void);
/** NATIVE: the destination. ERC20: the token recipient. */
const uint8_t *userop_get_call_to(void);
/** NATIVE: the value in wei. ERC20: the token amount in base units. */
const uint8_t *userop_get_call_value(void);
/** ERC20 only: the token contract. */
const uint8_t *userop_get_call_token(void);
