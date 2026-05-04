# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Z-bit Systems, LLC

# Top-level umbrella for host-side developer tools. Each tool lives in
# its own subdirectory and is built only when OSDP_BUILD_TOOLS is ON.
add_subdirectory(osdp-parser)
add_subdirectory(osdp-pd-mock)
add_subdirectory(osdp-acu-mock)
