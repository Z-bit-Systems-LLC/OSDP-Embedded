# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Z-bit Systems, LLC

# Top-level vendored 3rd-party code, shared by both tools and tests so
# we don't end up with two compiled copies of the same upstream source
# in the same build tree. Each consumer pulls in a target by name.

# tiny-AES-c (https://github.com/kokke/tiny-AES-c) — Unlicense /
# public domain. Single .c, no allocations, no globals, perfect for
# wedging behind osdp_sc_crypto_t. Used by:
#   - tests/sc_test_aes.c (the test SC crypto adapter)
#   - tools/osdp-pd-mock  (live interop with --sc=scbkd / --sc=scbk:HEX)
add_library(tiny_aes STATIC
    tiny-aes/aes.c
)

target_include_directories(tiny_aes
    PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/tiny-aes
)

# Upstream emits a few -Wconversion / -Wsign-conversion warnings;
# silence them on the vendored target only — we don't modify the
# upstream source.
if(NOT MSVC)
    target_compile_options(tiny_aes PRIVATE -w)
endif()
