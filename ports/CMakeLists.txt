# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Z-bit Systems, LLC

# ports/ — reference bindings of the library's crypto HALs to concrete
# implementations.
#
# The freestanding core deliberately vendors no crypto: osdp_sc_crypto_t (and
# on the SC2 line its siblings) are contracts the consumer fills in. That is
# right for a product, and awkward for everything else — every test suite and
# host tool then needs the same handful of primitives, and they drifted into
# private copies of identical code.
#
# These targets are that shared reference implementation. They are host-side
# code with the same standing as vendor/: built only when tests or tools are,
# never linked into osdp_core / osdp_pd / osdp_acu, and not what a shipping
# device is expected to use. A product binds mbedTLS, a hardware AES block, or
# its vendor PQC library to the same vtables instead.
#
# Deliberately excluded from every port: the RNG. rand_bytes is the one member
# whose correct implementation is different for a KAT, an interop tool and a
# product, so each consumer supplies its own rather than inheriting a default
# that is wrong for it in a way nothing detects.

# osdp_port_sc_tiny — AES-128 ECB for Secure Channel, over tiny-AES-c.
add_library(osdp_port_sc_tiny STATIC
    tiny/osdp_sc_tiny.c
)

target_include_directories(osdp_port_sc_tiny
    PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/tiny
)

# tiny_aes stays PRIVATE: nothing that links this target should inherit the
# vendored AES headers, and on the SC2 line the 256-bit sibling publishes
# PUBLIC defines that would recompile a dependent's own sources against the
# wrong key schedule. Keeping the linkage private here is what stops that
# spreading.
target_link_libraries(osdp_port_sc_tiny
    PUBLIC  osdp_core
    PRIVATE tiny_aes
)

target_compile_features(osdp_port_sc_tiny PUBLIC c_std_11)

add_library(osdp::port_sc_tiny ALIAS osdp_port_sc_tiny)

# osdp_port_pair_pqclean — ML-KEM-768 / ML-DSA-44 / SHA-256 for SC2 asymmetric
# pairing, over the vendored PQClean. Shared by the pairing KATs and the
# interop tools; a product binds WolfSSL or another PQC library instead.
#
# Note this one links its vendored dependencies PUBLIC rather than PRIVATE.
# PQClean leaves PQCLEAN_randombytes for the integrator to define and this
# port defines it, so the symbol has to stay resolvable to whatever links the
# schemes — making them private here would leave that hook dangling.
add_library(osdp_port_pair_pqclean STATIC
    pqclean/osdp_pair_pqclean.c
)

target_include_directories(osdp_port_pair_pqclean
    PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/pqclean
)

target_link_libraries(osdp_port_pair_pqclean
    PUBLIC osdp_core osdp_pair pqclean_mlkem768 pqclean_mldsa44
)

target_compile_features(osdp_port_pair_pqclean PUBLIC c_std_11)

add_library(osdp::port_pair_pqclean ALIAS osdp_port_pair_pqclean)

# Deterministic variant for the KATs: same sources, plus the seed queue and
# the reproducible PRNG fallback. A separate target rather than a switch on
# the one above, so a tool linking the plain target cannot pick up a seedable
# RNG through a transitive dependency.
add_library(osdp_port_pair_pqclean_kat STATIC
    pqclean/osdp_pair_pqclean.c
)

target_include_directories(osdp_port_pair_pqclean_kat
    PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/pqclean
)

target_compile_definitions(osdp_port_pair_pqclean_kat
    PUBLIC OSDP_PAIR_PQCLEAN_DETERMINISTIC=1
)

target_link_libraries(osdp_port_pair_pqclean_kat
    PUBLIC osdp_core osdp_pair pqclean_mlkem768 pqclean_mldsa44
)

target_compile_features(osdp_port_pair_pqclean_kat PUBLIC c_std_11)
