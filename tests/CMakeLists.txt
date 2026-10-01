# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Z-bit Systems, LLC

# Vendored Unity test framework (MIT-licensed; see vendor/unity/LICENSE.txt).
add_library(unity STATIC vendor/unity/unity.c)
target_include_directories(unity PUBLIC vendor/unity)

# Unity emits some warnings that aren't worth fighting — silence them on
# the vendored target only.
if(NOT MSVC)
    target_compile_options(unity PRIVATE -w)
endif()

# Helper: declare an OSDP unit test executable from a single .c file.
# Tests can include private core headers via the PRIVATE include path.
function(osdp_add_test test_name)
    add_executable(${test_name} ${test_name}.c)
    target_link_libraries(${test_name} PRIVATE
        osdp_core osdp_messages osdp_dispatch unity)
    target_include_directories(${test_name} PRIVATE
        ${CMAKE_SOURCE_DIR}/core/src
    )
    add_test(NAME ${test_name} COMMAND ${test_name})
endfunction()

osdp_add_test(test_crc)
osdp_add_test(test_checksum)
osdp_add_test(test_frame)
osdp_add_test(test_commands)
osdp_add_test(test_replies)
osdp_add_test(test_stream)
osdp_add_test(test_dispatch)
osdp_add_test(test_led_state)

# Multi-part message transport (spec 5.10): fragment codec, reassembly and
# fragmentation. Named for pairing because that was the first consumer and
# where this code was written; the transport now lives in osdp_core and is
# shared with every multi-part message, so this links osdp_core too.
add_executable(test_pair_transport test_pair_transport.c)
target_link_libraries(test_pair_transport PRIVATE osdp_core osdp_pair unity)
add_test(NAME test_pair_transport COMMAND test_pair_transport)

# SC2 asymmetric pairing — Phase 1 canonical-CBOR codec. No crypto.
add_executable(test_pair_cbor test_pair_cbor.c)
target_link_libraries(test_pair_cbor PRIVATE osdp_pair unity)
add_test(NAME test_pair_cbor COMMAND test_pair_cbor)

# SC2 asymmetric pairing — Phase 1 C509 cert encode/decode (structure only,
# no crypto). Thumbprint/verify KATs land with the crypto backend.
add_executable(test_pair_cert test_pair_cert.c)
target_link_libraries(test_pair_cert PRIVATE osdp_pair unity)
add_test(NAME test_pair_cert COMMAND test_pair_cert)

# SC2 asymmetric pairing — Phase 3 message codecs (Msg1/2/3/Result CBOR
# encode/parse). No crypto.
add_executable(test_pair_messages test_pair_messages.c)
target_link_libraries(test_pair_messages PRIVATE osdp_pair unity)
add_test(NAME test_pair_messages COMMAND test_pair_messages)

# The pairing crypto backend moved to ports/pqclean so the interop tools can
# link it too. Tests use the _kat variant, which adds the seed queue and the
# reproducible PRNG the fixed-seed vectors depend on.
add_library(pair_test_crypto INTERFACE)
target_link_libraries(pair_test_crypto INTERFACE osdp_port_pair_pqclean_kat)

# Cross-implementation vector: a certificate OSDP.Net actually emitted,
# decoded and verified against the demo CA regenerated from the published
# seed. Needs the KAT backend for that seed.
add_executable(test_pair_interop test_pair_interop.c)
target_link_libraries(test_pair_interop PRIVATE pair_test_crypto unity)
target_include_directories(test_pair_interop PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
add_test(NAME test_pair_interop COMMAND test_pair_interop)

# The port's entropy contract, against the PLAIN target — the variant a tool
# links. Deliberately NOT pair_test_crypto: with the seed queue compiled in
# there is always a fallback, so the "no source installed" case it asserts
# could not exist.
add_executable(test_pair_pqclean_rng test_pair_pqclean_rng.c)
target_link_libraries(test_pair_pqclean_rng PRIVATE
    osdp_port_pair_pqclean unity)
add_test(NAME test_pair_pqclean_rng COMMAND test_pair_pqclean_rng)

# SC2 asymmetric pairing — Phase 1 crypto KATs (thumbprint, cert verify,
# SHA-256/HKDF vectors, ML-KEM/ML-DSA fixed-seed pubkey cross-checks).
add_executable(test_pair_crypto test_pair_crypto.c)
target_link_libraries(test_pair_crypto PRIVATE pair_test_crypto unity)
add_test(NAME test_pair_crypto COMMAND test_pair_crypto)

# SC2 asymmetric pairing — Phase 4/5 pure session loopback (both real
# handshake state machines derive an identical SCBK), over PQClean.
add_executable(test_pair_session test_pair_session.c)
target_link_libraries(test_pair_session PRIVATE pair_test_crypto unity)
add_test(NAME test_pair_session COMMAND test_pair_session)

# SC2 asymmetric pairing — PD driver integration: a real osdp_pd + pairing
# driver on an in-memory wire, ACU simulated with the pure session.
add_executable(test_pd_pair test_pd_pair.c)
target_link_libraries(test_pd_pair PRIVATE
    osdp_core osdp_messages osdp_pd osdp_pd_pair pair_test_crypto unity)
add_test(NAME test_pd_pair COMMAND test_pd_pair)

# PD-side tests need the osdp_pd library in addition to the core.
add_executable(test_pd test_pd.c)
target_link_libraries(test_pd PRIVATE
    osdp_core osdp_messages osdp_pd unity)
add_test(NAME test_pd COMMAND test_pd)

# Multi-part message transport (spec 5.10) — core-only, no PD needed.
add_executable(test_multipart test_multipart.c)
target_link_libraries(test_multipart PRIVATE osdp_core unity)
add_test(NAME test_multipart COMMAND test_multipart)

# Caller-supplied working buffers (osdp_pd_set_buffers).
add_executable(test_pd_buffers test_pd_buffers.c)
target_link_libraries(test_pd_buffers PRIVATE
    osdp_core osdp_messages osdp_pd unity)
add_test(NAME test_pd_buffers COMMAND test_pd_buffers)

# Advisory PDCAP consistency check.
add_executable(test_pd_pdcap test_pd_pdcap.c)
target_link_libraries(test_pd_pdcap PRIVATE
    osdp_core osdp_messages osdp_pd unity)
add_test(NAME test_pd_pdcap COMMAND test_pd_pdcap)

# Status providers (osdp_LSTAT / ISTAT / OSTAT / RSTAT).
add_executable(test_pd_status test_pd_status.c)
target_link_libraries(test_pd_status PRIVATE
    osdp_core osdp_messages osdp_pd unity)
add_test(NAME test_pd_status COMMAND test_pd_status)

# Poll-response event queue, osdp_BUSY, the Table 47 NAK mapping, and
# multi-part osdp_MFG.
add_executable(test_pd_events test_pd_events.c)
target_link_libraries(test_pd_events PRIVATE
    osdp_core osdp_messages osdp_pd unity)
add_test(NAME test_pd_events COMMAND test_pd_events)

# ACU-side tests need the osdp_acu library in addition to the core.
add_executable(test_acu test_acu.c)
target_link_libraries(test_acu PRIVATE
    osdp_core osdp_messages osdp_acu unity)
add_test(NAME test_acu COMMAND test_acu)

# PD↔ACU loopback integration: both real state machines, shared wire
# buffer between them. Strongest correctness check for iteration 2.
add_executable(test_loopback test_loopback.c)
target_link_libraries(test_loopback PRIVATE
    osdp_core osdp_messages osdp_pd osdp_acu unity)
add_test(NAME test_loopback COMMAND test_loopback)

# ---- Secure Channel tests --------------------------------------------------
# A small test-side adapter exposes an AES port as osdp_sc_crypto_t, paired
# with a deterministic RNG (see sc_test_aes.c). The default backend is
# ports/tiny over the vendored tiny-AES-c, which is shared with osdp-pd-mock so
# aes.c is compiled once per build.
#
# With OSDP_PORT_WOLFCRYPT=ON the adapter is built a second time over
# ports/wolfcrypt and the whole SC suite below is registered again with a
# _wolfcrypt suffix. Every KAT, the PD/ACU handshakes, the loopback and the
# capture replay then pass or fail on wolfCrypt's AES exactly as on tiny-AES.
function(osdp_add_sc_adapter lib_name port_lib)
    add_library(${lib_name} STATIC sc_test_aes.c)
    target_include_directories(${lib_name}
        PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}
    )
    # The AES primitives come from the port; only the deterministic test RNG
    # lives in sc_test_aes.c. tiny_aes is reached through its port rather than
    # linked here, so the vendored headers stay out of the tests' include path.
    target_link_libraries(${lib_name} PUBLIC osdp_core ${port_lib})
endfunction()

# osdp_add_sc_suite(<suffix> <adapter>) — one CTest entry per SC test,
# named <test><suffix>, each linked against <adapter>.
function(osdp_add_sc_suite suffix adapter)
    # Primitive-level tests: core SC only.
    foreach(_t test_sc_aes test_sc_keys test_sc_cbc test_sc_mac
               test_sc_payload test_sc_wrap)
        add_executable(${_t}${suffix} ${_t}.c)
        target_link_libraries(${_t}${suffix} PRIVATE
            osdp_core ${adapter} unity)
        add_test(NAME ${_t}${suffix} COMMAND ${_t}${suffix})
    endforeach()

    # PD-side SC handshake test needs both osdp_pd and the SC test
    # crypto adapter.
    add_executable(test_pd_sc${suffix} test_pd_sc.c)
    target_link_libraries(test_pd_sc${suffix} PRIVATE
        osdp_core osdp_messages osdp_pd ${adapter} unity)
    add_test(NAME test_pd_sc${suffix} COMMAND test_pd_sc${suffix})

    # ACU-side SC handshake test (phase 5a). Mirrors test_pd_sc but
    # drives the ACU state machine.
    add_executable(test_acu_sc${suffix} test_acu_sc.c)
    target_link_libraries(test_acu_sc${suffix} PRIVATE
        osdp_core osdp_messages osdp_acu ${adapter} unity)
    add_test(NAME test_acu_sc${suffix} COMMAND test_acu_sc${suffix})

    # PD↔ACU SC loopback (phase 6). Both real state machines wired through
    # a shared in-memory wire, full handshake plus operational SCS_15..18
    # traffic in-process. Strongest correctness check we have for SC: any
    # disagreement on cryptogram inputs, key derivation, frame layout or
    # MAC chain advancement shows up here.
    add_executable(test_loopback_sc${suffix} test_loopback_sc.c)
    target_link_libraries(test_loopback_sc${suffix} PRIVATE
        osdp_core osdp_messages osdp_pd osdp_acu ${adapter} unity)
    add_test(NAME test_loopback_sc${suffix} COMMAND test_loopback_sc${suffix})

    # Capture-replay regression: drive our PD with frames extracted from a
    # real RS-485 SC capture (libosdp-conformance 1.38-4) and require
    # byte-identical responses. Independent-implementation cross-check.
    add_executable(test_capture_replay${suffix} test_capture_replay.c)
    target_link_libraries(test_capture_replay${suffix} PRIVATE
        osdp_core osdp_messages osdp_pd ${adapter} unity)
    add_test(NAME test_capture_replay${suffix}
             COMMAND test_capture_replay${suffix})
endfunction()

osdp_add_sc_adapter(sc_test_aes osdp_port_sc_tiny)
osdp_add_sc_suite("" sc_test_aes)

if(TARGET osdp_port_sc_wolfcrypt)
    osdp_add_sc_adapter(sc_test_aes_wolfcrypt osdp_port_sc_wolfcrypt)
    target_compile_definitions(sc_test_aes_wolfcrypt
        PRIVATE OSDP_SC_TEST_WOLFCRYPT)
    osdp_add_sc_suite("_wolfcrypt" sc_test_aes_wolfcrypt)

    # The port's own contract: FIPS-197 / SP 800-38A vectors, in-place
    # operation, setter composition, and the opt-in DRBG.
    add_executable(test_port_wolfcrypt test_port_wolfcrypt.c)
    target_link_libraries(test_port_wolfcrypt PRIVATE
        osdp_core osdp_port_sc_wolfcrypt unity)
    add_test(NAME test_port_wolfcrypt COMMAND test_port_wolfcrypt)
endif()

# ---- Secure Channel 2 tests ------------------------------------------------
# SC2 needs AES-256 + AES-256-GCM + KMAC256, none of which the AES-128
# tiny_aes lib provides. The crypto backends live under the shared
# vendor/ tree (tiny_gcm = AES-256-GCM over tiny_aes256; tiny_kmac =
# Keccak/KMAC256) so tests and the SC2 interop tools use identical code.
# sc2_test_crypto wires them into an osdp_sc2_crypto_t. The AES256 symbol
# renames on tiny_aes256 let a binary link both AES-128 and AES-256 builds.
add_library(sc2_test_crypto STATIC
    sc2_test_crypto.c
)
target_include_directories(sc2_test_crypto
    PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}
)
target_link_libraries(sc2_test_crypto PUBLIC osdp_core tiny_gcm tiny_kmac)

function(osdp_add_sc2_test test_name)
    add_executable(${test_name} ${test_name}.c)
    target_link_libraries(${test_name} PRIVATE
        osdp_core sc2_test_crypto unity)
    add_test(NAME ${test_name} COMMAND ${test_name})
endfunction()

osdp_add_sc2_test(test_sc2_primitives)
osdp_add_sc2_test(test_sc2_wrap)

# PD-side SC2 handshake + operational test needs osdp_pd and the SC2
# crypto backend.
add_executable(test_pd_sc2 test_pd_sc2.c)
target_link_libraries(test_pd_sc2 PRIVATE
    osdp_core osdp_messages osdp_pd sc2_test_crypto unity)
add_test(NAME test_pd_sc2 COMMAND test_pd_sc2)

# PD↔ACU SC2 loopback: both real state machines through a shared wire,
# full handshake + operational SCS_25..28 + session-loss.
add_executable(test_loopback_sc2 test_loopback_sc2.c)
target_link_libraries(test_loopback_sc2 PRIVATE
    osdp_core osdp_messages osdp_pd osdp_acu sc2_test_crypto unity)
add_test(NAME test_loopback_sc2 COMMAND test_loopback_sc2)

# OSDPCAP-format reader tests. Requires OSDP_BUILD_TOOLS so the
# osdpcap_reader library exists; skip silently otherwise.
if(TARGET osdpcap_reader)
    add_executable(test_osdpcap test_osdpcap.c)
    target_link_libraries(test_osdpcap PRIVATE osdpcap_reader unity)
    add_test(NAME test_osdpcap COMMAND test_osdpcap)

    # Capture-driven integration tests. CMake globs every *.osdpcap
    # under tests/captures/ at configure time and registers one CTest
    # entry per file, all backed by the same test_captures executable.
    add_executable(test_captures test_captures.c)
    target_link_libraries(test_captures PRIVATE
        osdp_core osdp_messages osdp_dispatch osdpcap_reader unity)
    target_include_directories(test_captures PRIVATE
        ${CMAKE_SOURCE_DIR}/core/src
    )

    file(GLOB OSDP_CAPTURE_FILES
         "${CMAKE_CURRENT_SOURCE_DIR}/captures/*.osdpcap")
    foreach(_capture ${OSDP_CAPTURE_FILES})
        get_filename_component(_capture_name "${_capture}" NAME_WE)
        add_test(NAME capture_${_capture_name}
                 COMMAND test_captures "${_capture}")
    endforeach()
endif()
