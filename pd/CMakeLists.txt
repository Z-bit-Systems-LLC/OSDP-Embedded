# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Z-bit Systems, LLC

# osdp::pd — peripheral-device-side state machine. Sits on top of
# osdp::core (for framing/integrity/streaming) and osdp::messages
# (the consumer needs per-message decoders/builders to assemble its
# own replies). No new dependencies on the rest of the system.
add_library(osdp_pd STATIC
    src/pd.c
    src/pd_sc.c
    src/pd_sc2.c
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

# osdp::pd_pair — opt-in PD-side driver for SC2 asymmetric device pairing.
# Links osdp::pair (the transport-free handshake) on top of osdp::pd. A PD
# app links this ONLY if it calls osdp_pd_attach_pair; pd.c dispatches to it
# through a hook pointer and names no symbol here, so a non-pairing PD never
# pulls in this target or its PQC-adjacent dependencies.
add_library(osdp_pd_pair STATIC
    src/pd_pair.c
)

target_include_directories(osdp_pd_pair
    PUBLIC  $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src
)

target_link_libraries(osdp_pd_pair PUBLIC
    osdp_pd
    osdp_pair
)

target_compile_features(osdp_pd_pair PUBLIC c_std_11)

add_library(osdp::pd_pair ALIAS osdp_pd_pair)
