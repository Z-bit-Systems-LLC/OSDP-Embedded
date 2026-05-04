# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Z-bit Systems, LLC

# osdp::acu — controller-side state machine. Sits on top of osdp::core
# (framing, integrity, streaming) and osdp::messages (the consumer
# decodes/builds typed payloads in its reply handler). No new
# dependencies on the rest of the system.
add_library(osdp_acu STATIC
    src/acu.c
    src/acu_sc.c
)

target_include_directories(osdp_acu
    PUBLIC  $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src
)

target_link_libraries(osdp_acu PUBLIC
    osdp_core
    osdp_messages
)

target_compile_features(osdp_acu PUBLIC c_std_11)

add_library(osdp::acu ALIAS osdp_acu)
