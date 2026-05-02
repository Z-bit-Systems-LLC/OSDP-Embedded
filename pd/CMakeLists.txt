# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Z-bit Systems, LLC

# osdp::pd — peripheral-device-side state machine. Sits on top of
# osdp::core (for framing/integrity/streaming) and osdp::messages
# (the consumer needs per-message decoders/builders to assemble its
# own replies). No new dependencies on the rest of the system.
add_library(osdp_pd STATIC
    src/pd.c
)

target_include_directories(osdp_pd
    PUBLIC  $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src
)

target_link_libraries(osdp_pd PUBLIC
    osdp_core
    osdp_messages
)

target_compile_features(osdp_pd PUBLIC c_std_11)

add_library(osdp::pd ALIAS osdp_pd)
