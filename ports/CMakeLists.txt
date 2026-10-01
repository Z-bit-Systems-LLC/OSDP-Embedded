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
# code with the same standing as vendor/: never linked into osdp_core /
# osdp_pd / osdp_acu. ports/tiny is built only when tests or tools are and is
# not what a shipping device is expected to use. ports/wolfcrypt is the
# exception on the second count — wolfCrypt is a production crypto library —
# and is opt-in behind OSDP_PORT_WOLFCRYPT because it needs an installed
# wolfSSL.
#
# No port installs an RNG as a side effect. rand_bytes is the one member
# whose correct implementation is different for a KAT, an interop tool and a
# product, so each consumer supplies its own rather than inheriting a default
# that is wrong for it in a way nothing detects. ports/tiny has no RNG at all;
# ports/wolfcrypt offers wolfCrypt's DRBG only through a separate, explicit
# osdp_sc_wolfcrypt_rng() call.

# osdp_port_sc_tiny — AES-128 ECB for Secure Channel, over tiny-AES-c.
# tiny_aes comes from vendor/, which only exists when tests or tools are on.
if(TARGET tiny_aes)
    add_library(osdp_port_sc_tiny STATIC
        tiny/osdp_sc_tiny.c
    )

    target_include_directories(osdp_port_sc_tiny
        PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/tiny
    )

    # tiny_aes stays PRIVATE: nothing that links this target should inherit
    # the vendored AES headers, and on the SC2 line the 256-bit sibling
    # publishes PUBLIC defines that would recompile a dependent's own sources
    # against the wrong key schedule. Keeping the linkage private here is what
    # stops that spreading.
    target_link_libraries(osdp_port_sc_tiny
        PUBLIC  osdp_core
        PRIVATE tiny_aes
    )

    target_compile_features(osdp_port_sc_tiny PUBLIC c_std_11)

    add_library(osdp::port_sc_tiny ALIAS osdp_port_sc_tiny)
endif()

# osdp_port_pair_pqclean — ML-KEM-768 / ML-DSA-44 / SHA-256 for SC2 asymmetric
# pairing, over the vendored PQClean. Shared by the pairing KATs and the
# interop tools; a product binds WolfSSL or another PQC library instead.
# PQClean, like tiny_aes, comes from vendor/ and exists only with tests or
# tools on.
#
# Note this one links its vendored dependencies PUBLIC rather than PRIVATE.
# PQClean leaves PQCLEAN_randombytes for the integrator to define and this
# port defines it, so the symbol has to stay resolvable to whatever links the
# schemes — making them private here would leave that hook dangling.
if(TARGET pqclean_mlkem768 AND TARGET pqclean_mldsa44)
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

    # Deterministic variant for the KATs: same sources, plus the seed queue
    # and the reproducible PRNG fallback. A separate target rather than a
    # switch on the one above, so a tool linking the plain target cannot pick
    # up a seedable RNG through a transitive dependency.
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
endif()

# osdp_port_sc_wolfcrypt — AES-128 ECB (+ optional DRBG) over wolfCrypt.
# Point CMAKE_PREFIX_PATH (or wolfssl_DIR) at a wolfSSL install built with
# -DWOLFSSL_AESECB=yes; the port refuses to compile without HAVE_AES_ECB.
# The SC2 and pairing ports below share the option and the wolfSSL install.
if(OSDP_PORT_WOLFCRYPT)
    find_package(wolfssl CONFIG REQUIRED)

    add_library(osdp_port_sc_wolfcrypt STATIC
        wolfcrypt/osdp_sc_wolfcrypt.c
    )

    target_include_directories(osdp_port_sc_wolfcrypt
        PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/wolfcrypt
    )

    # PUBLIC, unlike tiny_aes above: osdp_sc_wolfcrypt.h embeds wolfCrypt's
    # Aes and WC_RNG by value, so every includer needs wolfSSL's headers and
    # the same options.h the library was built with.
    target_link_libraries(osdp_port_sc_wolfcrypt
        PUBLIC osdp_core wolfssl::wolfssl
    )

    target_compile_features(osdp_port_sc_wolfcrypt PUBLIC c_std_11)

    add_library(osdp::port_sc_wolfcrypt ALIAS osdp_port_sc_wolfcrypt)

    # osdp_port_sc2_wolfcrypt — AES-256-GCM + AES-256 block (+ optional DRBG)
    # for SC2. kmac256 is the caller's: wolfCrypt has no cSHAKE/KMAC. Needs
    # HAVE_AESGCM, on in wolfSSL's default build.
    add_library(osdp_port_sc2_wolfcrypt STATIC
        wolfcrypt/osdp_sc2_wolfcrypt.c
    )

    target_include_directories(osdp_port_sc2_wolfcrypt
        PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/wolfcrypt
    )

    target_link_libraries(osdp_port_sc2_wolfcrypt
        PUBLIC osdp_core wolfssl::wolfssl
    )

    target_compile_features(osdp_port_sc2_wolfcrypt PUBLIC c_std_11)

    add_library(osdp::port_sc2_wolfcrypt ALIAS osdp_port_sc2_wolfcrypt)

    # osdp_port_pair_wolfcrypt — ML-KEM-768 / ML-DSA-44 / SHA-256 / HMAC /
    # HKDF for SC2 pairing. Only when the installed wolfSSL was built with
    # the PQC schemes (CMake: -DWOLFSSL_MLKEM=yes -DWOLFSSL_MLDSA=yes, plus
    # -DWOLFSSL_HKDF=yes), so a wolfSSL built for the SC1 port alone keeps
    # configuring. Probed from its options.h rather than assumed.
    include(CheckSymbolExists)
    get_target_property(_osdp_wolfssl_inc wolfssl::wolfssl
                        INTERFACE_INCLUDE_DIRECTORIES)
    set(CMAKE_REQUIRED_INCLUDES ${_osdp_wolfssl_inc})
    set(_osdp_wolfssl_hdrs "wolfssl/options.h;wolfssl/wolfcrypt/settings.h")
    check_symbol_exists(WOLFSSL_HAVE_MLKEM "${_osdp_wolfssl_hdrs}"
                        OSDP_WOLFSSL_HAS_MLKEM)
    check_symbol_exists(HAVE_DILITHIUM "${_osdp_wolfssl_hdrs}"
                        OSDP_WOLFSSL_HAS_MLDSA)
    check_symbol_exists(HAVE_HKDF "${_osdp_wolfssl_hdrs}"
                        OSDP_WOLFSSL_HAS_HKDF)
    unset(CMAKE_REQUIRED_INCLUDES)

    if(OSDP_WOLFSSL_HAS_MLKEM AND OSDP_WOLFSSL_HAS_MLDSA AND
       OSDP_WOLFSSL_HAS_HKDF)
        add_library(osdp_port_pair_wolfcrypt STATIC
            wolfcrypt/osdp_pair_wolfcrypt.c
        )

        target_include_directories(osdp_port_pair_wolfcrypt
            PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/wolfcrypt
        )

        # PUBLIC for the same reason as the SC port: the context embeds
        # wolfCrypt's key objects by value.
        target_link_libraries(osdp_port_pair_wolfcrypt
            PUBLIC osdp_core osdp_pair wolfssl::wolfssl
        )

        target_compile_features(osdp_port_pair_wolfcrypt PUBLIC c_std_11)

        add_library(osdp::port_pair_wolfcrypt ALIAS osdp_port_pair_wolfcrypt)
    else()
        message(STATUS "wolfSSL lacks ML-KEM / ML-DSA / HKDF: "
                       "osdp_port_pair_wolfcrypt not built")
    endif()
endif()
