# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Z-bit Systems, LLC

# osdp-pd-mock — host CLI that runs an OSDP PD on a real (or virtual)
# serial port. Intended as a manual interop validation tool: pair it
# with an independent ACU (e.g. OSDP.Net's ACUConsole) over a
# null-modem cable or a virtual COM-port pair (com0com on Windows).
#
# The serial transport is platform-specific. CMake picks exactly one of
# serial_win.c or serial_posix.c based on the host OS. The PD library
# itself stays freestanding — only this tool depends on the OS.

# SC2 crypto backend, deliberately compiled as its OWN static library.
#
# tiny_aes256 publishes AES256=1 plus the AES_* -> AES256_* renames as PUBLIC
# usage requirements, and tiny_gcm links it PUBLIC, so anything that links
# tiny_gcm directly gets those defines applied to ALL of its own sources. That
# would silently recompile aes_adapter.c — the SC1 AES-128 backend — against
# the 256-bit key schedule: struct AES_ctx grows to the 240-byte schedule and
# AES_init_ctx reads 32 bytes from a 16-byte SCBK, so every SC1 cryptogram and
# MAC comes out wrong and the SCS_11..14 handshake never completes against a
# real ACU. Keeping the SC2 adapter in its own target, linking tiny_gcm /
# tiny_kmac PRIVATE, stops those usage requirements here.
add_library(pd_mock_sc2 STATIC sc2_adapter.c)
target_include_directories(pd_mock_sc2 PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(pd_mock_sc2 PRIVATE osdp_core tiny_gcm tiny_kmac)
target_compile_features(pd_mock_sc2 PRIVATE c_std_11)
if(MSVC)
    target_compile_definitions(pd_mock_sc2 PRIVATE _CRT_SECURE_NO_WARNINGS)
endif()

# SC2 asymmetric pairing credential, issued at build time rather than checked
# in. Keeping it generated means it cannot drift from the PQClean port that
# issued it, and no key material — not even demonstration key material — sits
# in the source tree waiting to be mistaken for the real thing.
set(PD_MOCK_PAIR_CREDS ${CMAKE_CURRENT_BINARY_DIR}/pair_credentials.h)
add_custom_command(
    OUTPUT  ${PD_MOCK_PAIR_CREDS}
    COMMAND osdp-pair-provision
            --out    ${PD_MOCK_PAIR_CREDS}
            --model  osdp-pd-mock
            --serial PD-MOCK-0001
    DEPENDS osdp-pair-provision
    COMMENT "Issuing osdp-pd-mock pairing credential (demo CA)"
    VERBATIM
)
add_custom_target(osdp-pd-mock-creds DEPENDS ${PD_MOCK_PAIR_CREDS})

add_executable(osdp-pd-mock
    main.c
    aes_adapter.c
    pair_adapter.c
)
add_dependencies(osdp-pd-mock osdp-pd-mock-creds)

if(WIN32)
    target_sources(osdp-pd-mock PRIVATE serial_win.c)
elseif(UNIX)
    target_sources(osdp-pd-mock PRIVATE serial_posix.c)
else()
    message(FATAL_ERROR "osdp-pd-mock: no serial adapter for this platform")
endif()

# The SC1 AES primitives come from ports/tiny; aes_adapter.c keeps only this
# tool's RNG policy. tiny_aes is reached through the port rather than linked
# here, so the vendored headers stay out of this tool's include path.
#
# NOTE: tiny_gcm / tiny_kmac are likewise reached only through pd_mock_sc2
# (PRIVATE), never linked here directly — see the comment above. That
# isolation is the same idea the port applies to tiny_aes, and it is load
# bearing here: tiny_aes256's PUBLIC defines would otherwise recompile
# aes_adapter.c against the 256-bit key schedule and corrupt every SC1 key.
# osdp_port_pair_pqclean is the PLAIN variant, not _kat: this tool pairs on a
# real wire, so its entropy comes from the OS CSPRNG installed in
# pair_adapter.c. Linking the KAT variant would give it a seedable RNG and a
# predictable SCBK.
target_link_libraries(osdp-pd-mock PRIVATE
    osdp_core
    osdp_messages
    osdp_pd
    osdp_pd_pair
    osdp_port_sc_tiny
    osdp_port_pair_pqclean
    pd_mock_sc2
)

target_include_directories(osdp-pd-mock PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_BINARY_DIR}   # generated pair_credentials.h
)

target_compile_features(osdp-pd-mock PRIVATE c_std_11)

if(MSVC)
    target_compile_definitions(osdp-pd-mock PRIVATE _CRT_SECURE_NO_WARNINGS)
endif()
