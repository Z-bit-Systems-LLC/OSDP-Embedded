# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Z-bit Systems, LLC

# osdp-parser — host-side CLI that reads an OSDPCAP capture and prints
# decoded OSDP frames. Acts as both a developer tool and the canonical
# end-to-end Monitor consumer of osdp::core + osdp::messages +
# osdp::dispatch.
add_executable(osdp-parser
    osdpcap.c
    main.c
)

target_link_libraries(osdp-parser PRIVATE
    osdp_core
    osdp_messages
    osdp_dispatch
)

target_include_directories(osdp-parser PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
)

target_compile_features(osdp-parser PRIVATE c_std_11)

# MSVC's CRT marks fopen/strerror et al. as deprecated; the safer _s
# variants are non-portable. Silence on this host-only tool target.
if(MSVC)
    target_compile_definitions(osdp-parser PRIVATE _CRT_SECURE_NO_WARNINGS)
endif()

# Re-export the OSDPCAP reader as a small static library so the test
# suite can include it without rebuilding osdpcap.c via a different
# target.
add_library(osdpcap_reader STATIC
    osdpcap.c
)

target_include_directories(osdpcap_reader
    PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}
)

target_compile_features(osdpcap_reader PUBLIC c_std_11)
