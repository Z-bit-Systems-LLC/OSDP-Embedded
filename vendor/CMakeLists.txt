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

# AES-256 build of the same vendored source, for OSDP-SC2 (which uses
# AES-256-GCM and a raw AES-256 block). tiny-AES selects the key length
# by the AES256 macro at compile time, and struct AES_ctx's size depends
# on it — so AES256=1 is PUBLIC: every target that links tiny_aes256 (the
# SC2 test/tool crypto backend) compiles its own aes.h include with the
# matching 240-byte key schedule. Kept separate from tiny_aes (AES-128)
# so the two never collide in one translation unit; a given executable
# links one or the other, never both.
add_library(tiny_aes256 STATIC
    tiny-aes/aes.c
)

target_include_directories(tiny_aes256
    PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/tiny-aes
)

# AES256=1 selects the 256-bit key schedule. The AES_* → AES256_* renames
# are PUBLIC so every translation unit that links tiny_aes256 both selects
# AES-256 AND references the renamed symbols — letting a single binary
# link BOTH tiny_aes (AES-128, for SC1) and tiny_aes256 (for SC2) without
# a duplicate-symbol clash. Source keeps calling AES_init_ctx / etc.; the
# preprocessor rewrites the names consistently in declarations and defs.
target_compile_definitions(tiny_aes256 PUBLIC
    AES256=1
    AES_init_ctx=AES256_init_ctx
    AES_init_ctx_iv=AES256_init_ctx_iv
    AES_ctx_set_iv=AES256_ctx_set_iv
    AES_ECB_encrypt=AES256_ECB_encrypt
    AES_ECB_decrypt=AES256_ECB_decrypt
    AES_CBC_encrypt_buffer=AES256_CBC_encrypt_buffer
    AES_CBC_decrypt_buffer=AES256_CBC_decrypt_buffer
    AES_CTR_xcrypt_buffer=AES256_CTR_xcrypt_buffer
)

if(NOT MSVC)
    target_compile_options(tiny_aes256 PRIVATE -w)
endif()

# tiny_kmac — self-contained Keccak-f[1600] + cSHAKE256 + KMAC256, for
# OSDP-SC2 session-key derivation in tests and tools. Never in core.
add_library(tiny_kmac STATIC
    tiny-kmac/kmac.c
)
target_include_directories(tiny_kmac
    PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/tiny-kmac
)

# tiny_gcm — AES-256-GCM (CTR + GHASH) over tiny_aes256, for OSDP-SC2
# message protection in tests and tools. Links tiny_aes256 PUBLIC so its
# AES256 rename/config propagates. Never in core.
add_library(tiny_gcm STATIC
    tiny-gcm/gcm.c
)
target_include_directories(tiny_gcm
    PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/tiny-gcm
)
target_link_libraries(tiny_gcm PUBLIC tiny_aes256)
