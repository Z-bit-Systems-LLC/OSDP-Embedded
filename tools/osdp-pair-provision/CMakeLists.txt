# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Z-bit Systems, LLC

# osdp-pair-provision — offline issuer of PD pairing credentials.
#
# Links the _kat variant of the PQClean port on purpose: regenerating the
# OSDP.Net demo CA means seeding the RNG with its published fixed seed, and
# that seed queue exists only in that target. This is the right place for it —
# an offline issuer is exactly the deterministic-by-design case, whereas the
# PD that consumes its output links the plain target and binds a real CSPRNG.
add_executable(osdp-pair-provision main.c)

target_link_libraries(osdp-pair-provision PRIVATE
    osdp_core
    osdp_pair
    osdp_port_pair_pqclean_kat
)

target_compile_features(osdp-pair-provision PRIVATE c_std_11)

if(MSVC)
    target_compile_definitions(osdp-pair-provision PRIVATE _CRT_SECURE_NO_WARNINGS)
endif()
