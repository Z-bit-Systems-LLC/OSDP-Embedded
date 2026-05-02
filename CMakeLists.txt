# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Z-bit Systems, LLC

cmake_minimum_required(VERSION 3.16)

project(osdp-embedded
    VERSION 0.1.0
    DESCRIPTION "Portable C11 SIA OSDP v2.2.2 implementation"
    LANGUAGES C
)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

option(OSDP_BUILD_TESTS "Build unit tests" ON)
option(OSDP_BUILD_TOOLS "Build host-side developer tools (osdp-parser, ...)" ON)

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

add_subdirectory(core)
add_subdirectory(pd)

if(OSDP_BUILD_TOOLS)
    add_subdirectory(tools)
endif()

if(OSDP_BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()
