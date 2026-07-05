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

# ---- PQClean: post-quantum primitives for OSDP-SC2 asymmetric pairing ----
#
# The "clean" reference C implementations of ML-KEM-768 (FIPS 203) and
# ML-DSA-44 (FIPS 204) from https://github.com/PQClean/PQClean (Public
# Domain / CC0), plus their shared Keccak (fips202) and a SHA-256 (sha2).
# Self-contained, vendored exactly like tiny-* so the pairing KATs run
# hermetically on CI with no external package. Never linked into a
# production core — a firmware/host integrator binds its own PQC backend
# (WolfSSL, mbedTLS+liboqs, OpenSSL 3.5+, hardware) behind
# osdp_pair_crypto_t. Used by tests/pair_test_crypto.c.
#
# Symbols are namespaced (PQCLEAN_MLKEM768_CLEAN_* / PQCLEAN_MLDSA44_CLEAN_*)
# so the two schemes' identically-named TUs (poly.c, ntt.c, ...) never
# collide. randombytes() is intentionally NOT vendored here; the test
# binding supplies PQCLEAN_randombytes so KATs can inject fixed seeds.

# Shared: Keccak-f[1600]/SHAKE (used by both schemes) + SHA-256 (used by the
# pairing key schedule and C509 thumbprint).
add_library(pqclean_common STATIC
    pqclean/common/fips202.c
    pqclean/common/sha2.c
)
target_include_directories(pqclean_common
    PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/pqclean/common
)

add_library(pqclean_mlkem768 STATIC
    pqclean/mlkem768/cbd.c
    pqclean/mlkem768/indcpa.c
    pqclean/mlkem768/kem.c
    pqclean/mlkem768/ntt.c
    pqclean/mlkem768/poly.c
    pqclean/mlkem768/polyvec.c
    pqclean/mlkem768/reduce.c
    pqclean/mlkem768/symmetric-shake.c
    pqclean/mlkem768/verify.c
)
target_include_directories(pqclean_mlkem768
    PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/pqclean/mlkem768
    PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/pqclean/common
)
target_link_libraries(pqclean_mlkem768 PUBLIC pqclean_common)

add_library(pqclean_mldsa44 STATIC
    pqclean/mldsa44/ntt.c
    pqclean/mldsa44/packing.c
    pqclean/mldsa44/poly.c
    pqclean/mldsa44/polyvec.c
    pqclean/mldsa44/reduce.c
    pqclean/mldsa44/rounding.c
    pqclean/mldsa44/sign.c
    pqclean/mldsa44/symmetric-shake.c
)
target_include_directories(pqclean_mldsa44
    PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/pqclean/mldsa44
    PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/pqclean/common
)
target_link_libraries(pqclean_mldsa44 PUBLIC pqclean_common)

# Upstream reference code is not warning-clean under this project's strict
# flags; silence warnings on the vendored targets only (we don't modify the
# upstream source), mirroring tiny-*.
foreach(_pqc pqclean_common pqclean_mlkem768 pqclean_mldsa44)
    if(MSVC)
        target_compile_options(${_pqc} PRIVATE /w)
    else()
        target_compile_options(${_pqc} PRIVATE -w)
    endif()
endforeach()
