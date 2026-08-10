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
