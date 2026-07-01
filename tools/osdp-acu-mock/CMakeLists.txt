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

add_executable(osdp-acu-mock
    main.c
    aes_adapter.c
    sc2_adapter.c
)

if(WIN32)
    target_sources(osdp-acu-mock PRIVATE serial_win.c)
elseif(UNIX)
    target_sources(osdp-acu-mock PRIVATE serial_posix.c)
else()
    message(FATAL_ERROR "osdp-acu-mock: no serial adapter for this platform")
endif()

target_link_libraries(osdp-acu-mock PRIVATE
    osdp_core
    osdp_messages
    osdp_acu
    tiny_aes
    tiny_gcm
    tiny_kmac
)

target_include_directories(osdp-acu-mock PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
)

target_compile_features(osdp-acu-mock PRIVATE c_std_11)

if(MSVC)
    target_compile_definitions(osdp-acu-mock PRIVATE _CRT_SECURE_NO_WARNINGS)
endif()
