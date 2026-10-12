#pragma once
#include "status_words.h"

/**
 * Status word for dynamic token TLV parsing/validation failed.
 */
#define SW_INVALID_DYNAMIC_TOKEN 0xB009
/**
 * Status word for a blind-signing operation refused because the user has not
 * enabled blind signing in Settings. Fail closed: the device never downgrades
 * to a blind review on its own.
 */
#define SW_BLIND_SIGNING_DISABLED 0xB00A
