// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Z-bit Systems, LLC

#include "osdp/osdp_commands.h"
#include "osdp/osdp_dispatch.h"
#include "osdp/osdp_replies.h"
#include "unity.h"

#include <string.h>

void setUp(void) {}
void tearDown(void) {}

static osdp_message_kind_t classify(uint8_t code, bool reply)
{
    osdp_frame_t f = {0};
    f.code = code;
    f.reply = reply;
    return osdp_dispatch_classify(&f);
}

static void test_classify_handles_null(void)
{
    TEST_ASSERT_EQUAL(OSDP_MSG_UNKNOWN_COMMAND, osdp_dispatch_classify(NULL));
}

static void test_classify_baseline_commands(void)
{
    static const struct { uint8_t code; osdp_message_kind_t kind; } cases[] = {
        { OSDP_CMD_POLL,    OSDP_MSG_CMD_POLL    },
        { OSDP_CMD_ID,      OSDP_MSG_CMD_ID      },
        { OSDP_CMD_CAP,     OSDP_MSG_CMD_CAP     },
        { OSDP_CMD_LSTAT,   OSDP_MSG_CMD_LSTAT   },
        { OSDP_CMD_ISTAT,   OSDP_MSG_CMD_ISTAT   },
        { OSDP_CMD_OSTAT,   OSDP_MSG_CMD_OSTAT   },
        { OSDP_CMD_RSTAT,   OSDP_MSG_CMD_RSTAT   },
        { OSDP_CMD_OUT,     OSDP_MSG_CMD_OUT     },
        { OSDP_CMD_LED,     OSDP_MSG_CMD_LED     },
        { OSDP_CMD_BUZ,     OSDP_MSG_CMD_BUZ     },
        { OSDP_CMD_TEXT,    OSDP_MSG_CMD_TEXT    },
        { OSDP_CMD_COMSET,  OSDP_MSG_CMD_COMSET  },
        { OSDP_CMD_KEYSET,  OSDP_MSG_CMD_KEYSET  },
        { OSDP_CMD_CHLNG,   OSDP_MSG_CMD_CHLNG   },
        { OSDP_CMD_SCRYPT,  OSDP_MSG_CMD_SCRYPT  },
        { OSDP_CMD_MFG,     OSDP_MSG_CMD_MFG     },
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        TEST_ASSERT_EQUAL(cases[i].kind, classify(cases[i].code, false));
    }
}

static void test_classify_baseline_replies(void)
{
    static const struct { uint8_t code; osdp_message_kind_t kind; } cases[] = {
        { OSDP_REPLY_ACK,     OSDP_MSG_REPLY_ACK     },
        { OSDP_REPLY_NAK,     OSDP_MSG_REPLY_NAK     },
        { OSDP_REPLY_PDID,    OSDP_MSG_REPLY_PDID    },
        { OSDP_REPLY_PDCAP,   OSDP_MSG_REPLY_PDCAP   },
        { OSDP_REPLY_LSTATR,  OSDP_MSG_REPLY_LSTATR  },
        { OSDP_REPLY_ISTATR,  OSDP_MSG_REPLY_ISTATR  },
        { OSDP_REPLY_OSTATR,  OSDP_MSG_REPLY_OSTATR  },
        { OSDP_REPLY_RSTATR,  OSDP_MSG_REPLY_RSTATR  },
        { OSDP_REPLY_RAW,     OSDP_MSG_REPLY_RAW     },
        { OSDP_REPLY_FMT,     OSDP_MSG_REPLY_FMT     },
        { OSDP_REPLY_KEYPAD,  OSDP_MSG_REPLY_KEYPAD  },
        { OSDP_REPLY_COM,     OSDP_MSG_REPLY_COM     },
        { OSDP_REPLY_CCRYPT,  OSDP_MSG_REPLY_CCRYPT  },
        { OSDP_REPLY_BUSY,    OSDP_MSG_REPLY_BUSY    },
        { OSDP_REPLY_FTSTAT,  OSDP_MSG_REPLY_FTSTAT  },
        { OSDP_REPLY_MFGREP,  OSDP_MSG_REPLY_MFGREP  },
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        TEST_ASSERT_EQUAL(cases[i].kind, classify(cases[i].code, true));
    }
}

static void test_classify_unknown_command_returns_unknown(void)
{
    TEST_ASSERT_EQUAL(OSDP_MSG_UNKNOWN_COMMAND, classify(0x00, false));
    TEST_ASSERT_EQUAL(OSDP_MSG_UNKNOWN_COMMAND, classify(0xFF, false));
    TEST_ASSERT_EQUAL(OSDP_MSG_UNKNOWN_COMMAND, classify(0x53, false));
}

static void test_classify_unknown_reply_returns_unknown(void)
{
    TEST_ASSERT_EQUAL(OSDP_MSG_UNKNOWN_REPLY, classify(0x00, true));
    TEST_ASSERT_EQUAL(OSDP_MSG_UNKNOWN_REPLY, classify(0xFE, true));
    TEST_ASSERT_EQUAL(OSDP_MSG_UNKNOWN_REPLY, classify(0x60, true));
}

static void test_classify_disambiguates_by_reply_flag(void)
{
    /* 0x76: command osdp_CHLNG vs reply osdp_CCRYPT — same code byte,
     * different direction. Classifier must use the frame's reply flag
     * to decide. */
    TEST_ASSERT_EQUAL(OSDP_MSG_CMD_CHLNG,    classify(0x76, false));
    TEST_ASSERT_EQUAL(OSDP_MSG_REPLY_CCRYPT, classify(0x76, true));

    /* 0x80: command osdp_MFG vs reply osdp_PIVDATAR (not in our
     * baseline, classifies as UNKNOWN_REPLY). */
    TEST_ASSERT_EQUAL(OSDP_MSG_CMD_MFG,        classify(0x80, false));
    TEST_ASSERT_EQUAL(OSDP_MSG_UNKNOWN_REPLY,  classify(0x80, true));
}

static void test_dispatch_name_returns_non_null_for_every_kind(void)
{
    /* Walk every enumerator we explicitly named. The cast safety here
     * relies on the enum being dense; compilers happily walk the int
     * range and the function returns "unknown" for anything off-list. */
    static const osdp_message_kind_t kinds[] = {
        OSDP_MSG_UNKNOWN_COMMAND, OSDP_MSG_UNKNOWN_REPLY,
        OSDP_MSG_CMD_POLL, OSDP_MSG_CMD_ID, OSDP_MSG_CMD_CAP,
        OSDP_MSG_CMD_LSTAT, OSDP_MSG_CMD_ISTAT, OSDP_MSG_CMD_OSTAT,
        OSDP_MSG_CMD_RSTAT, OSDP_MSG_CMD_OUT, OSDP_MSG_CMD_LED,
        OSDP_MSG_CMD_BUZ, OSDP_MSG_CMD_TEXT, OSDP_MSG_CMD_COMSET,
        OSDP_MSG_CMD_BIOREAD, OSDP_MSG_CMD_BIOMATCH,
        OSDP_MSG_CMD_KEYSET, OSDP_MSG_CMD_CHLNG, OSDP_MSG_CMD_SCRYPT,
        OSDP_MSG_CMD_MFG,
        OSDP_MSG_REPLY_ACK, OSDP_MSG_REPLY_NAK, OSDP_MSG_REPLY_PDID,
        OSDP_MSG_REPLY_PDCAP, OSDP_MSG_REPLY_LSTATR,
        OSDP_MSG_REPLY_ISTATR, OSDP_MSG_REPLY_OSTATR,
        OSDP_MSG_REPLY_RSTATR, OSDP_MSG_REPLY_RAW, OSDP_MSG_REPLY_FMT,
        OSDP_MSG_REPLY_KEYPAD, OSDP_MSG_REPLY_COM,
        OSDP_MSG_REPLY_BIOREADR, OSDP_MSG_REPLY_BIOMATCHR,
        OSDP_MSG_REPLY_CCRYPT, OSDP_MSG_REPLY_RMAC_I,
        OSDP_MSG_REPLY_BUSY, OSDP_MSG_REPLY_FTSTAT,
        OSDP_MSG_REPLY_MFGREP,
    };
    for (size_t i = 0; i < sizeof(kinds) / sizeof(kinds[0]); i++) {
        const char *name = osdp_dispatch_name(kinds[i]);
        TEST_ASSERT_NOT_NULL(name);
        TEST_ASSERT_TRUE(strlen(name) > 0);
    }
}

static void test_dispatch_name_specific_strings(void)
{
    TEST_ASSERT_EQUAL_STRING("osdp_POLL",
                             osdp_dispatch_name(OSDP_MSG_CMD_POLL));
    TEST_ASSERT_EQUAL_STRING("osdp_LED",
                             osdp_dispatch_name(OSDP_MSG_CMD_LED));
    TEST_ASSERT_EQUAL_STRING("osdp_PDID",
                             osdp_dispatch_name(OSDP_MSG_REPLY_PDID));
    TEST_ASSERT_EQUAL_STRING("unknown command",
                             osdp_dispatch_name(OSDP_MSG_UNKNOWN_COMMAND));
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_classify_handles_null);
    RUN_TEST(test_classify_baseline_commands);
    RUN_TEST(test_classify_baseline_replies);
    RUN_TEST(test_classify_unknown_command_returns_unknown);
    RUN_TEST(test_classify_unknown_reply_returns_unknown);
    RUN_TEST(test_classify_disambiguates_by_reply_flag);
    RUN_TEST(test_dispatch_name_returns_non_null_for_every_kind);
    RUN_TEST(test_dispatch_name_specific_strings);
    return UNITY_END();
}
