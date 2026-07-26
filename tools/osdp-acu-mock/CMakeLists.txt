# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Z-bit Systems, LLC

# osdp-acu-mock — host CLI that runs an OSDP ACU on a real (or virtual)
# serial port. Mirror of osdp-pd-mock pointing the other way: pair it
# with an independent PD (OSDP.Net's PDConsole, a hardware PD, or our
# own osdp-pd-mock over a com0com pair) to validate end-to-end interop
# of the ACU side of this stack.
#
# The serial transport is platform-specific. CMake picks exactly one
# of serial_win.c or serial_posix.c based on the host OS. The ACU
# library itself stays freestanding — only this tool depends on the
# OS.

# SC2 crypto backend in its own static library — same reasoning as
# tools/osdp-pd-mock/CMakeLists.txt: tiny_aes256's PUBLIC AES256=1 and
# AES_* -> AES256_* renames reach every source of any target that links
# tiny_gcm directly, which would silently recompile aes_adapter.c (the SC1
# AES-128 backend) against the 256-bit key schedule and corrupt every SC1
# cryptogram. Linking tiny_gcm / tiny_kmac PRIVATE here contains them.
add_library(acu_mock_sc2 STATIC sc2_adapter.c)
target_include_directories(acu_mock_sc2 PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(acu_mock_sc2 PRIVATE osdp_core tiny_gcm tiny_kmac)
target_compile_features(acu_mock_sc2 PRIVATE c_std_11)
if(MSVC)
    target_compile_definitions(acu_mock_sc2 PRIVATE _CRT_SECURE_NO_WARNINGS)
endif()

add_executable(osdp-acu-mock
    main.c
    aes_adapter.c
)

if(WIN32)
    target_sources(osdp-acu-mock PRIVATE serial_win.c)
elseif(UNIX)
    target_sources(osdp-acu-mock PRIVATE serial_posix.c)
else()
    message(FATAL_ERROR "osdp-acu-mock: no serial adapter for this platform")
endif()

# NOTE: tiny_gcm / tiny_kmac are reached only through acu_mock_sc2 (PRIVATE).
target_link_libraries(osdp-acu-mock PRIVATE
    osdp_core
    osdp_messages
    osdp_acu
    tiny_aes
    acu_mock_sc2
)

target_include_directories(osdp-acu-mock PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
)

target_compile_features(osdp-acu-mock PRIVATE c_std_11)

if(MSVC)
    target_compile_definitions(osdp-acu-mock PRIVATE _CRT_SECURE_NO_WARNINGS)
endif()
