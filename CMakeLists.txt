# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Z-bit Systems, LLC

cmake_minimum_required(VERSION 3.16)

project(osdp-embedded
    VERSION 0.1.5
    DESCRIPTION "Portable C11 SIA OSDP v2.2.2 implementation"
    LANGUAGES C
)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

option(OSDP_BUILD_TESTS "Build unit tests" ON)
option(OSDP_BUILD_TOOLS "Build host-side developer tools (osdp-parser, ...)" ON)
option(OSDP_SANITIZE    "Build with AddressSanitizer (and UBSan on GCC/Clang)" OFF)

# Strict warnings + per-function/data sections so consumers can use
# --gc-sections to drop any unused per-message codecs.
if(MSVC)
    add_compile_options(/W4 /permissive-)
    # MSVC equivalent of function/data sections is on by default for /O*; nothing to add.
else()
    add_compile_options(
        -Wall
        -Wextra
        -Wpedantic
        -Wshadow
        -Wconversion
        -Wsign-conversion
        -Wstrict-prototypes
        -Wmissing-prototypes
        -Wpointer-arith
        -Wcast-align
        -Wcast-qual
        -ffunction-sections
        -fdata-sections
    )
endif()

# AddressSanitizer (+ UBSan on GCC/Clang) for catching memory bugs
# during iterative debugging. Off by default; flip on with
# `-DOSDP_SANITIZE=ON` and rebuild from scratch — sanitizers don't
# mix well with non-sanitised cached object files.
if(OSDP_SANITIZE)
    if(MSVC)
        # MSVC 16.9+ supports /fsanitize=address. Sanitiser-instrumented
        # code requires the dynamic CRT (default for Debug is /MDd, so
        # this just works) and full debug info (/Zi, also default).
        add_compile_options(/fsanitize=address)
        # Disable optimisations that fight ASan diagnostics; harmless
        # for Debug, helpful when someone flips ASan on with Release.
        add_compile_options(/Od)
        # Editing-and-continuing breaks ASan link-time instrumentation;
        # CMake injects /ZI for Debug by default — replace with /Zi.
        string(REPLACE "/ZI" "/Zi" CMAKE_C_FLAGS_DEBUG
               "${CMAKE_C_FLAGS_DEBUG}")
        string(REPLACE "/RTC1" "" CMAKE_C_FLAGS_DEBUG
               "${CMAKE_C_FLAGS_DEBUG}")
    else()
        add_compile_options(-fsanitize=address,undefined
                            -fno-omit-frame-pointer)
        add_link_options   (-fsanitize=address,undefined)
    endif()
    message(STATUS "OSDP: AddressSanitizer build enabled")
endif()

add_subdirectory(core)
add_subdirectory(pd)
add_subdirectory(acu)

# Vendored 3rd-party code shared between tools and tests. Currently
# just tiny-AES-c (Unlicense / public domain), used as the AES-128 ECB
# primitive behind osdp_sc_crypto_t for both the SC unit tests and the
# osdp-pd-mock interop tool. Skipped when neither tests nor tools are
# being built; embedded targets that bring their own AES never see it.
if(OSDP_BUILD_TESTS OR OSDP_BUILD_TOOLS)
    add_subdirectory(vendor)
endif()

if(OSDP_BUILD_TOOLS)
    add_subdirectory(tools)
endif()

if(OSDP_BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()
