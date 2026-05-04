# Test captures

OSDPCAP-format (JSON-Lines) captures of real OSDP traffic, used by the
`test_captures` integration test.

For every `*.osdpcap` file dropped into this directory, CMake (when
re-run) generates a CTest entry that:

1. Parses every line via the in-tree OSDPCAP reader
   (`tools/osdp-parser/osdpcap.{c,h}`).
2. Feeds each record's bytes through `osdp_stream_feed` /
   `osdp_stream_next`.
3. Asserts every non-blank line was a valid OSDPCAP record. Frame-level
   decode errors (bad CRC, malformed frames) are allowed and reported
   in the output — real captures legitimately contain them.

To add a capture: drop the `.osdpcap` file in this directory and re-run
CMake. The new CTest entry will be picked up automatically.

The OSDPCAP format is documented at:
<https://github.com/Security-Industry-Association/libosdp-conformance/blob/master/doc/doc-src/osdpcap-format.md>

## Captures in this directory

### `sc-monitor-current.osdpcap`

Bus-monitor trace of a live OSDP session captured by `libosdp-conformance
1.38-4`, exercising Secure Channel from cold start through steady-state
polling. 592 records / 592 frames covering:

- Boot retries (4 × `osdp_ID` until the PD answers with `osdp_PDID`).
- Initial SC handshake: `osdp_CHLNG` → `osdp_CCRYPT` → `osdp_SCRYPT` →
  `osdp_RMAC_I` (SCB types 0x11–0x14).
- Key install (`osdp_KEYSET` / `osdp_ACK`) followed by a second SC
  handshake.
- Operational setup: `osdp_CAP`/`osdp_PDCAP`, `osdp_LED`, `osdp_TEXT`,
  `osdp_LSTAT`/`osdp_LSTATR`, `osdp_RSTAT`/`osdp_RSTATR`,
  `osdp_ACURXSIZE` — all under SCB types 0x17/0x18 (encrypted + MAC).
- 284 `osdp_POLL` / `osdp_ACK` heartbeat pairs under SCB types 0x15/0x16
  (plain + MAC).

All 16 distinct OSDP message kinds present in the capture classify with
known names; every frame validates its CRC. Useful as a regression test
that the framing layer continues to handle real-world traffic without
errors as the codebase evolves.

### `acuconsole-poll-id-cap.osdpcap`

Live recording of `osdp-pd-mock` (this repo's tool) running on COM3
talking to OSDP.Net's `ACUConsole` on COM4 over a com0com pair, no
Secure Channel. The capture covers the steady-state insecure protocol:

- `osdp_POLL` / `osdp_ACK` loop with proper SQN progression (0 → 1 → 2
  → 3 → 1 → ...).
- `osdp_CAP` / `osdp_PDCAP` exchange: `ACUConsole` requests capabilities
  with `62 00`; the mock responds with its 7-record default cap set
  (contact monitor, output, card data, LED, audible, text, CRC).
- `osdp_ID` / `osdp_PDID` exchange: `ACUConsole` requests with `61 00`;
  the mock responds with its default PDID (vendor "ZBC", model 1,
  serial 1, firmware 0.1.0).

Recorded by `ACUConsole` 's built-in OSDPCAP writer, so the file uses
the dash-separated hex dialect (`53-80-08-00-...`) rather than the
libosdp-conformance space-separated convention. Both dialects parse
through `tools/osdp-parser/osdpcap.c`.

### `acuconsole-sc-no-key.osdpcap`

Same `osdp-pd-mock` ↔ `ACUConsole` setup, but with `ACUConsole`
configured to attempt Secure Channel using SCBK-D, while the PD was
launched WITHOUT `--sc=scbkd`. The capture documents the
spec-mandated NAK 0x05 ("unsupported SCB") rejection path:

- Bare `osdp_POLL` / `osdp_ACK` warm-up.
- `osdp_CHLNG` (SCS_11) sent by `ACUConsole`; PD replies with
  `osdp_NAK` payload `0x05`.
- `ACUConsole` retries CHLNG several times; PD keeps NAKing.

Useful as a regression test that an SC-unconfigured PD continues to
refuse SCB-bearing frames cleanly when paired with an independent ACU.
