# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Z-bit Systems, LLC

# osdp::core — framing primitives, integrity (CRC-16, checksum), and the
# stream/frame decoders. Always required by any consumer.
add_library(osdp_core STATIC
    src/shared/crc16.c
    src/shared/checksum.c
    src/shared/frame.c
    src/shared/stream.c
    src/shared/led_state.c
    src/shared/buz_state.c
    src/sc/cbc.c
    src/sc/keys.c
    src/sc/mac.c
    src/sc/payload.c
    src/sc/session.c
    src/sc/wrap.c
)

target_include_directories(osdp_core
    PUBLIC  $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src
)

target_compile_features(osdp_core PUBLIC c_std_11)

add_library(osdp::core ALIAS osdp_core)

# osdp::messages — per-message codecs (model + decoder + builder per
# command/reply). One translation unit per message so unused codecs are
# garbage-collected by the linker (-ffunction-sections / --gc-sections).
# Independent of osdp::core: a consumer can link either, both, or just
# include the headers.
add_library(osdp_messages STATIC
    # Commands (ACU → PD)
    src/commands/cmd_poll.c
    src/commands/cmd_id.c
    src/commands/cmd_cap.c
    src/commands/cmd_out.c
    src/commands/cmd_led.c
    src/commands/cmd_buz.c
    src/commands/cmd_text.c
    src/commands/cmd_comset.c
    src/commands/cmd_keyset.c
    src/commands/cmd_filetransfer.c
    # Replies (PD → ACU)
    src/replies/reply_ack.c
    src/replies/reply_nak.c
    src/replies/reply_pdid.c
    src/replies/reply_pdcap.c
    src/replies/reply_lstatr.c
    src/replies/reply_istatr.c
    src/replies/reply_ostatr.c
    src/replies/reply_rstatr.c
    src/replies/reply_raw.c
    src/replies/reply_keypad.c
    src/replies/reply_com.c
    src/replies/reply_ftstat.c
)

target_include_directories(osdp_messages
    PUBLIC  $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src
)

target_compile_features(osdp_messages PUBLIC c_std_11)

add_library(osdp::messages ALIAS osdp_messages)

# osdp::dispatch — optional bulk-routing helpers. Iteration 1 ships a
# pure classifier (no per-message decoder references) so consumers can
# link this without dragging every codec into the binary; richer routing
# helpers may follow in later iterations.
add_library(osdp_dispatch STATIC
    src/dispatch/dispatch_classify.c
)

target_include_directories(osdp_dispatch
    PUBLIC  $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src
)

target_compile_features(osdp_dispatch PUBLIC c_std_11)

add_library(osdp::dispatch ALIAS osdp_dispatch)
