// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Z-bit Systems, LLC

/* Unit tests for the core LED state resolver (osdp_led_state).
 *
 * These exercise the pure timer/flash math directly with explicit
 * timestamps — no PD/ACU, no wire — so the temporary-timer expiry and the
 * flash on/off phase are fully deterministic. The PD↔ACU integration of
 * the same resolver (driven by a real osdp_LED command over a loopback
 * wire) lives in test_loopback.c. */

#include "osdp/osdp_commands.h"
#include "osdp/osdp_led_state.h"
#include "unity.h"

void setUp(void) {}
void tearDown(void) {}

/* A steady single-colour permanent record (on_time == off_time == 0). */
static osdp_led_record_t perm_steady(uint8_t color)
{
    osdp_led_record_t r = {0};
    r.temp_control_code = OSDP_LED_TEMP_NOP;
    r.perm_control_code = OSDP_LED_PERM_SET;
    r.perm_on_color     = color;
    r.perm_off_color    = color;
    r.perm_on_time      = 0;
    r.perm_off_time     = 0;
    return r;
}

static void test_default_is_black(void)
{
    osdp_led_t led;
    osdp_led_init(&led);
    TEST_ASSERT_EQUAL_HEX8(OSDP_LED_BLACK, osdp_led_color(&led, 0));
    TEST_ASSERT_EQUAL_HEX8(OSDP_LED_BLACK, osdp_led_color(&led, 1000000));
}

static void test_permanent_steady_colour(void)
{
    osdp_led_t led;
    osdp_led_init(&led);
    const osdp_led_record_t rec = perm_steady(OSDP_LED_GREEN);
    osdp_led_apply(&led, &rec, 0);

    /* Steady — colour is time-invariant. */
    TEST_ASSERT_EQUAL_HEX8(OSDP_LED_GREEN, osdp_led_color(&led, 0));
    TEST_ASSERT_EQUAL_HEX8(OSDP_LED_GREEN, osdp_led_color(&led, 50));
    TEST_ASSERT_EQUAL_HEX8(OSDP_LED_GREEN, osdp_led_color(&led, 99999));
}

static void test_permanent_flash_phases(void)
{
    osdp_led_t led;
    osdp_led_init(&led);
    /* 500 ms red on, 500 ms black off. */
    osdp_led_record_t rec = {0};
    rec.temp_control_code = OSDP_LED_TEMP_NOP;
    rec.perm_control_code = OSDP_LED_PERM_SET;
    rec.perm_on_color     = OSDP_LED_RED;
    rec.perm_off_color    = OSDP_LED_BLACK;
    rec.perm_on_time      = 5;  /* 500 ms */
    rec.perm_off_time     = 5;  /* 500 ms */
    osdp_led_apply(&led, &rec, 0);

    TEST_ASSERT_EQUAL_HEX8(OSDP_LED_RED,   osdp_led_color(&led, 0));
    TEST_ASSERT_EQUAL_HEX8(OSDP_LED_RED,   osdp_led_color(&led, 499));
    TEST_ASSERT_EQUAL_HEX8(OSDP_LED_BLACK, osdp_led_color(&led, 500));
    TEST_ASSERT_EQUAL_HEX8(OSDP_LED_BLACK, osdp_led_color(&led, 999));
    TEST_ASSERT_EQUAL_HEX8(OSDP_LED_RED,   osdp_led_color(&led, 1000));  /* wraps */
    TEST_ASSERT_EQUAL_HEX8(OSDP_LED_BLACK, osdp_led_color(&led, 1500));
}

static void test_temporary_overrides_then_expires(void)
{
    osdp_led_t led;
    osdp_led_init(&led);

    /* One record: steady-red permanent AND a 1 s steady-green temporary.
     * The ACU armed it at t = 1000 ms. */
    osdp_led_record_t rec = perm_steady(OSDP_LED_RED);
    rec.temp_control_code = OSDP_LED_TEMP_SET;
    rec.temp_on_color     = OSDP_LED_GREEN;
    rec.temp_off_color    = OSDP_LED_GREEN;
    rec.temp_on_time      = 0;
    rec.temp_off_time     = 0;
    rec.temp_timer_100ms  = 10;  /* 10 × 100 ms = 1000 ms */
    osdp_led_apply(&led, &rec, 1000);

    /* While the timer runs: temporary (green) wins. */
    TEST_ASSERT_EQUAL_HEX8(OSDP_LED_GREEN, osdp_led_color(&led, 1000));
    TEST_ASSERT_EQUAL_HEX8(OSDP_LED_GREEN, osdp_led_color(&led, 1500));
    TEST_ASSERT_EQUAL_HEX8(OSDP_LED_GREEN, osdp_led_color(&led, 1999));
    /* At expiry (elapsed == duration) and after: permanent (red). */
    TEST_ASSERT_EQUAL_HEX8(OSDP_LED_RED,   osdp_led_color(&led, 2000));
    TEST_ASSERT_EQUAL_HEX8(OSDP_LED_RED,   osdp_led_color(&led, 5000));
}

static void test_temporary_cancel_reverts_immediately(void)
{
    osdp_led_t led;
    osdp_led_init(&led);

    osdp_led_record_t rec = perm_steady(OSDP_LED_RED);
    rec.temp_control_code = OSDP_LED_TEMP_SET;
    rec.temp_on_color     = OSDP_LED_GREEN;
    rec.temp_off_color    = OSDP_LED_GREEN;
    rec.temp_timer_100ms  = 100;  /* 10 s — plenty */
    osdp_led_apply(&led, &rec, 0);
    TEST_ASSERT_EQUAL_HEX8(OSDP_LED_GREEN, osdp_led_color(&led, 100));

    /* CANCEL drops the temporary even though its timer hasn't elapsed. */
    osdp_led_record_t cancel = {0};
    cancel.temp_control_code = OSDP_LED_TEMP_CANCEL;
    cancel.perm_control_code = OSDP_LED_PERM_NOP;  /* leave permanent red */
    osdp_led_apply(&led, &cancel, 200);
    TEST_ASSERT_EQUAL_HEX8(OSDP_LED_RED, osdp_led_color(&led, 200));
}

static void test_temp_timer_zero_expires_immediately(void)
{
    osdp_led_t led;
    osdp_led_init(&led);

    osdp_led_record_t rec = perm_steady(OSDP_LED_RED);
    rec.temp_control_code = OSDP_LED_TEMP_SET;
    rec.temp_on_color     = OSDP_LED_GREEN;
    rec.temp_off_color    = OSDP_LED_GREEN;
    rec.temp_timer_100ms  = 0;  /* already expired — never masks permanent */
    osdp_led_apply(&led, &rec, 500);

    TEST_ASSERT_EQUAL_HEX8(OSDP_LED_RED, osdp_led_color(&led, 500));
}

static void test_perm_nop_leaves_permanent_untouched(void)
{
    osdp_led_t led;
    osdp_led_init(&led);
    const osdp_led_record_t set_blue = perm_steady(OSDP_LED_BLUE);
    osdp_led_apply(&led, &set_blue, 0);

    /* A temp-only command (perm NOP) must not disturb the blue permanent. */
    osdp_led_record_t temp_only = {0};
    temp_only.perm_control_code = OSDP_LED_PERM_NOP;
    temp_only.temp_control_code = OSDP_LED_TEMP_SET;
    temp_only.temp_on_color     = OSDP_LED_AMBER;
    temp_only.temp_off_color    = OSDP_LED_AMBER;
    temp_only.temp_timer_100ms  = 5;  /* 500 ms */
    osdp_led_apply(&led, &temp_only, 0);

    TEST_ASSERT_EQUAL_HEX8(OSDP_LED_AMBER, osdp_led_color(&led, 100));
    TEST_ASSERT_EQUAL_HEX8(OSDP_LED_BLUE,  osdp_led_color(&led, 600));
}

static void test_clock_wraparound(void)
{
    osdp_led_t led;
    osdp_led_init(&led);

    osdp_led_record_t rec = perm_steady(OSDP_LED_RED);
    rec.temp_control_code = OSDP_LED_TEMP_SET;
    rec.temp_on_color     = OSDP_LED_GREEN;
    rec.temp_off_color    = OSDP_LED_GREEN;
    rec.temp_timer_100ms  = 10;  /* 1000 ms */
    /* Arm just before the 32-bit clock rolls over. */
    const uint32_t start = 0xFFFFFF00u;
    osdp_led_apply(&led, &rec, start);

    /* now = start + 500, which has wrapped past 0; unsigned subtraction
     * still yields elapsed = 500 < 1000, so the temporary is live. */
    TEST_ASSERT_EQUAL_HEX8(OSDP_LED_GREEN,
                           osdp_led_color(&led, (uint32_t)(start + 500u)));
    /* now = start + 1200 → elapsed 1200 ≥ 1000 → expired → permanent. */
    TEST_ASSERT_EQUAL_HEX8(OSDP_LED_RED,
                           osdp_led_color(&led, (uint32_t)(start + 1200u)));
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_default_is_black);
    RUN_TEST(test_permanent_steady_colour);
    RUN_TEST(test_permanent_flash_phases);
    RUN_TEST(test_temporary_overrides_then_expires);
    RUN_TEST(test_temporary_cancel_reverts_immediately);
    RUN_TEST(test_temp_timer_zero_expires_immediately);
    RUN_TEST(test_perm_nop_leaves_permanent_untouched);
    RUN_TEST(test_clock_wraparound);
    return UNITY_END();
}
