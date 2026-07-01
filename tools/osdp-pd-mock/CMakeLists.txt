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

add_executable(osdp-pd-mock
    main.c
    aes_adapter.c
    sc2_adapter.c
)

if(WIN32)
    target_sources(osdp-pd-mock PRIVATE serial_win.c)
elseif(UNIX)
    target_sources(osdp-pd-mock PRIVATE serial_posix.c)
else()
    message(FATAL_ERROR "osdp-pd-mock: no serial adapter for this platform")
endif()

target_link_libraries(osdp-pd-mock PRIVATE
    osdp_core
    osdp_messages
    osdp_pd
    tiny_aes
    tiny_gcm
    tiny_kmac
)

target_include_directories(osdp-pd-mock PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
)

target_compile_features(osdp-pd-mock PRIVATE c_std_11)

if(MSVC)
    target_compile_definitions(osdp-pd-mock PRIVATE _CRT_SECURE_NO_WARNINGS)
endif()
