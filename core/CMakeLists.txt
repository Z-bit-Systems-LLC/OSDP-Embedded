# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Z-bit Systems, LLC

# osdp::core — framing primitives, integrity (CRC-16, checksum), and the
# stream/frame decoders. Always required by any consumer.
add_library(osdp_core STATIC
    src/shared/crc16.c
    src/shared/checksum.c
)

target_include_directories(osdp_core
    PUBLIC  $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src
)

target_compile_features(osdp_core PUBLIC c_std_11)

add_library(osdp::core ALIAS osdp_core)

# osdp::messages and osdp::dispatch will be added in subsequent phases as
# the per-message codecs and bulk-routing helpers come online.
