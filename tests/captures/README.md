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
