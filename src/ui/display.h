#pragma once

#include <stdbool.h>  // bool

#if defined(TARGET_NANOX) || defined(TARGET_NANOS2)
#define ICON_APP_BOILERPLATE C_app_boilerplate_14px
#define ICON_APP_HOME        C_home_boilerplate_14px
#define ICON_APP_WARNING     C_icon_warning
#elif defined(TARGET_STAX) || defined(TARGET_FLEX)
#define ICON_APP_BOILERPLATE C_app_boilerplate_64px
#define ICON_APP_HOME        ICON_APP_BOILERPLATE
#define ICON_APP_WARNING     C_Warning_64px
#elif defined(TARGET_APEX_P)
#define ICON_APP_BOILERPLATE C_app_boilerplate_48px
#define ICON_APP_HOME        ICON_APP_BOILERPLATE
#define ICON_APP_WARNING     LARGE_WARNING_ICON
#endif

/**
 * Callback to reuse action with approve/reject in step FLOW.
 */
typedef void (*action_validate_cb)(bool);

/**
 * Display address on the device and ask confirmation to export.
 *
 * @return 0 if success, negative integer otherwise.
 *
 */
int ui_display_address(void);

/**
 * Display transaction information on the device and ask confirmation to sign.
 *
 * @return 0 if success, negative integer otherwise.
 *
 */
int ui_display_transaction(void);

/**
 * Display blind-sign transaction information on the device and ask confirmation to sign.
 *
 * @return 0 if success, negative integer otherwise.
 *
 */
int ui_display_blind_signed_transaction(void);

/**
 * Display token transaction information on the device and ask confirmation to sign.
 *
 * @return 0 if success, negative integer otherwise.
 *
 */
int ui_display_token_transaction(void);

/**
 * Display an opaque ML-DSA payload for approval (SIGN_DILITHIUM finalize).
 *
 * The payload is shown as a length + hex preview under a blind-signing warning
 * since the device has no way to interpret its meaning.
 *
 * @return 0 if success, negative integer otherwise.
 */
int ui_display_pq_sign(void);

/**
 * Display a 32-byte hash for blind-sign approval (ECDSA_SIGN_HASH).
 *
 * @return 0 if success, negative integer otherwise.
 */
int ui_display_ecdsa_sign_hash(void);

/**
 * Display a 32-byte hash for hybrid (ECDSA + ML-DSA-44) blind-sign approval.
 *
 * @return 0 if success, negative integer otherwise.
 */
int ui_display_hybrid_sign_hash(void);

/**
 * Display an ERC-4337 UserOperation for hybrid (ECDSA + ML-DSA-44) approval.
 *
 * Shows Chain ID / Sender / To / Value (wei) when callData was verified and
 * parsed as `execute(address,uint256,bytes)`; falls back to a blind
 * "UserOp Hash" pair when no callData was provided or the selector didn't
 * match.
 *
 * @return 0 if success, negative integer otherwise.
 */
int ui_display_hybrid_sign_userop(void);
