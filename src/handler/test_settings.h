#pragma once

#ifdef HAVE_TEST_INS

#include <stdint.h>

/**
 * SET_SETTING (INS 0x0D) — test-only write access to the NVM settings.
 *
 * Exists so the functional tests can put the device in a known settings state
 * without driving the Settings UI, which differs per device. Compiled out of
 * production builds along with the other test-only instructions; see
 * HAVE_TEST_INS in the Makefile.
 *
 *   P1 = setting id   0x00 = blind signing
 *   P2 = value        0x00 = off, 0x01 = on
 *   Lc = 0
 *
 * Unknown P1 or a P2 outside {0, 1} returns SWO_INCORRECT_P1_P2.
 *
 * The user-facing path (Settings switch with its confirmation screen) is a
 * separate code path in src/ui/menu_nbgl.c and is covered by its own test; this
 * instruction deliberately bypasses it.
 */
int handler_set_setting(uint8_t p1, uint8_t p2);

#endif  // HAVE_TEST_INS
