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

# PD-side tests need the osdp_pd library in addition to the core.
add_executable(test_pd test_pd.c)
target_link_libraries(test_pd PRIVATE
    osdp_core osdp_messages osdp_pd unity)
add_test(NAME test_pd COMMAND test_pd)

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
# A small test-side AES adapter wraps tiny-AES-c (vendored at the
# top-level vendor/tiny-aes/) and exposes it as osdp_sc_crypto_t.
# The same tiny_aes static lib is shared with osdp-pd-mock so we don't
# compile aes.c twice into the same build.
add_library(sc_test_aes STATIC
    sc_test_aes.c
)
target_include_directories(sc_test_aes
    PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}
)
target_link_libraries(sc_test_aes PUBLIC osdp_core tiny_aes)

function(osdp_add_sc_test test_name)
    add_executable(${test_name} ${test_name}.c)
    target_link_libraries(${test_name} PRIVATE
        osdp_core sc_test_aes unity)
    add_test(NAME ${test_name} COMMAND ${test_name})
endfunction()

osdp_add_sc_test(test_sc_aes)
osdp_add_sc_test(test_sc_keys)
osdp_add_sc_test(test_sc_cbc)
osdp_add_sc_test(test_sc_mac)
osdp_add_sc_test(test_sc_payload)
osdp_add_sc_test(test_sc_wrap)

# PD-side SC handshake test needs both osdp_pd and the SC test
# crypto adapter.
add_executable(test_pd_sc test_pd_sc.c)
target_link_libraries(test_pd_sc PRIVATE
    osdp_core osdp_messages osdp_pd sc_test_aes unity)
add_test(NAME test_pd_sc COMMAND test_pd_sc)

# ACU-side SC handshake test (phase 5a). Mirrors test_pd_sc but
# drives the ACU state machine.
add_executable(test_acu_sc test_acu_sc.c)
target_link_libraries(test_acu_sc PRIVATE
    osdp_core osdp_messages osdp_acu sc_test_aes unity)
add_test(NAME test_acu_sc COMMAND test_acu_sc)

# Capture-replay regression: drive our PD with frames extracted from a
# real RS-485 SC capture (libosdp-conformance 1.38-4) and require
# byte-identical responses. Independent-implementation cross-check.
add_executable(test_capture_replay test_capture_replay.c)
target_link_libraries(test_capture_replay PRIVATE
    osdp_core osdp_messages osdp_pd sc_test_aes unity)
add_test(NAME test_capture_replay COMMAND test_capture_replay)

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
