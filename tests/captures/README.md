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
