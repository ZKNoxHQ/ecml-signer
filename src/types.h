#pragma once

#include <stddef.h>  // size_t
#include <stdint.h>  // uint*_t
#include <stdbool.h>

#include "bip32.h"
#include "lcx_mldsa.h"

#include "constants.h"
#include "tx_types.h"

/**
 * Enumeration with expected INS of APDU commands.
 */
typedef enum {
    GET_VERSION = 0x03,        /// version of the application
    GET_APP_NAME = 0x04,       /// name of the application
    GET_PUBLIC_KEY = 0x05,     /// public key of corresponding BIP32 path
    SIGN_TX = 0x06,            /// sign transaction with BIP32 path
    SIGN_TOKEN_TX = 0x07,      /// sign token transaction with BIP32 path and token address
    SIGN_TX_MLDSA = 0x08,         /// sign transaction with an ML-DSA-44 key derived from BIP32 path
    DUMMY = 0x0a,                 /// echo cdata (I/O smoke test)
    SAMPLE_IN_BALL = 0x0b,        /// ML-DSA SampleInBall over host-provided c_tilde
    KEYGEN_DILITHIUM_CORE = 0x0c, /// ML-DSA-44 keygen from a caller-supplied 32-byte seed
    SIGN_DILITHIUM = 0x0f,        /// ML-DSA-44 sign the currently-loaded key (3-part APDU)
    KEYGEN_DILITHIUM = 0x11,      /// ML-DSA-44 keygen from a BIP32 path (SLIP-0010 "mldsa-44")
    GET_SIG_CHUNK = 0x12,         /// fetch a 255-byte-max slice of the stored ML-DSA-44 signature
    GET_PK_CHUNK = 0x13,          /// fetch a 255-byte-max slice of the stored ML-DSA-44 public key
    ECDSA_SIGN_HASH = 0x15,       /// blind-sign a 32-byte hash with secp256k1 for a BIP32 path
    HYBRID_SIGN_HASH = 0x16,      /// sign a 32-byte hash with ECDSA (inline) AND ML-DSA-44 (chunk-fetched)
    HYBRID_SIGN_USEROP = 0x17,    /// hybrid clear-sign an ERC-4337 v0.7 UserOperation
    PROVIDE_TOKEN_INFO = 0x22     /// provide dynamic token info via CAL TLV descriptor
} command_e;
/**
 * Enumeration with parsing state.
 */
typedef enum {
    STATE_NONE,     /// No state
    STATE_PARSED,   /// Transaction data parsed
    STATE_APPROVED  /// Transaction data approved
} state_e;

/**
 * Enumeration with user request type.
 */
typedef enum {
    CONFIRM_ADDRESS,            /// confirm address derived from public key
    CONFIRM_TRANSACTION,        /// confirm transaction information
    CONFIRM_TOKEN_TRANSACTION,  /// confirm token transaction information
    CONFIRM_PQ_SIGN,            /// confirm ML-DSA raw payload signing (INS 0x0f)
    CONFIRM_ECDSA_SIGN_HASH,    /// confirm blind-sign of a 32-byte hash (INS 0x15)
    CONFIRM_HYBRID_SIGN_HASH,   /// confirm hybrid ECDSA+ML-DSA blind-sign of a 32-byte hash (INS 0x16)
    CONFIRM_HYBRID_SIGN_USEROP  /// confirm hybrid clear-sign of an ERC-4337 v0.7 UserOp (INS 0x17)
} request_type_e;

/**
 * Structure for public key context information.
 */
typedef struct {
    uint8_t raw_public_key[65];  /// format (1), x-coordinate (32), y-coodinate (32)
    uint8_t chain_code[32];      /// for public key derivation
} pubkey_ctx_t;

#define TOKEN_ADDRESS_LEN 32

/**
 * Structure for token information.
 */
typedef struct {
    const char *ticker;  /// token ticker
    uint8_t decimals;    /// number of decimals
} token_info_t;

/**
 * Structure for transaction information context.
 */
typedef struct {
    uint8_t raw_tx[MAX_TRANSACTION_LEN];  /// raw transaction serialized
    size_t raw_tx_len;                    /// length of raw transaction
    transaction_t transaction;            /// structured transaction

    // Token related
    bool is_token_tx;         /// flag to indicate if this is a token transaction
    token_info_t token_info;  /// token information retrieved using the token address

    // MLDSA sign selector
    bool is_mldsa;  /// flag: use ML-DSA-44 signing instead of ECDSA

    // Signature related
    uint8_t m_hash[32];                  /// message hash digest
    uint8_t signature[MAX_DER_SIG_LEN];  /// transaction signature encoded in DER
    uint8_t signature_len;               /// length of transaction signature
    uint8_t v;                           /// parity of y-coordinate of R in ECDSA signature

    // ML-DSA-44 outputs (populated by SIGN_TX_MLDSA or the KEYGEN_DILITHIUM* /
    // SIGN_DILITHIUM primitive INS family)
    uint8_t mldsa_pk[MLDSA44_PUBLICKEYBYTES];  /// ML-DSA-44 public key
    uint8_t mldsa_sig[MLDSA44_SIGBYTES];       /// ML-DSA-44 signature
    size_t mldsa_sig_len;                      /// actual signature length written
    uint8_t mldsa_seed[32];                    /// SLIP-0010 seed (kept for CORE keygen / SIGN)
} transaction_ctx_t;

/**
 * Structure for global context.
 */
typedef struct {
    state_e state;  /// state of the context
    union {
        pubkey_ctx_t pk_info;       /// public key context
        transaction_ctx_t tx_info;  /// transaction context
    };
    request_type_e req_type;              /// user request
    uint32_t bip32_path[MAX_BIP32_PATH];  /// BIP32 path
    uint8_t bip32_path_len;               /// length of BIP32 path
} global_ctx_t;
