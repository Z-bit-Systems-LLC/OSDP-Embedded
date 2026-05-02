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
