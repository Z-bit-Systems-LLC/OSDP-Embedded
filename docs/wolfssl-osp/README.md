# OSDP-Embedded with wolfCrypt

This directory explains how to use [wolfCrypt](https://www.wolfssl.com/products/wolfcrypt/)
as the crypto provider for [OSDP-Embedded](https://github.com/Z-bit-Systems-LLC/OSDP-Embedded).
OSDP-Embedded is a C11 implementation of the SIA Open Supervised Device Protocol
(OSDP) v2.2.2, for access-control readers (PDs) and panels (ACUs).

OSDP-Embedded needs **no patch**. The library ships no crypto of its own. OSDP
Secure Channel (spec Annex D) calls AES and the RNG through a three-function
vtable, `osdp_sc_crypto_t`, and the application fills it in. The wolfCrypt
binding for that vtable ships in the OSDP-Embedded repository as
[`ports/wolfcrypt`](https://github.com/Z-bit-Systems-LLC/OSDP-Embedded/tree/main/ports/wolfcrypt).
The OSDP-Embedded test suite builds and tests it against wolfSSL.

| | |
| --- | --- |
| Project | OSDP-Embedded |
| Tested version | 1.0.1 (`main`) |
| wolfSSL version | 5.9.2 |
| Integration type | Crypto HAL binding (no source changes) |
| Project license | GPL-3.0-or-later, or commercial |
| Home page | <https://github.com/Z-bit-Systems-LLC/OSDP-Embedded> |

## What OSDP Secure Channel needs from wolfCrypt

The whole Secure Channel layer reduces to single-block AES-128 plus random
bytes:

| Vtable member | Used for | wolfCrypt API |
| --- | --- | --- |
| `aes128_ecb_encrypt` | Session-key derivation, client/server cryptograms, the custom CBC-MAC, and CBC payload encryption (the chaining is done by OSDP-Embedded) | `wc_AesSetKey` + `wc_AesEcbEncrypt` |
| `aes128_ecb_decrypt` | Decrypting SCS_17 / SCS_18 message payloads | `wc_AesSetKey` + `wc_AesEcbDecrypt` |
| `rand_bytes` | The 8-byte handshake challenge (RND.A on the ACU, RND.B on the PD) | `wc_RNG_GenerateBlock` (Hash-DRBG) |

OSDP-Embedded does no TLS, uses no public-key crypto, does no hashing and does
no certificate handling. A wolfCrypt-only build is enough.

## Building wolfSSL

The port needs `HAVE_AES_ECB` and AES decryption. It stops the compile with an
`#error` if either one is missing.

**AES-ECB defaults differ between wolfSSL's two build systems.** `./configure`
turns it on by default. wolfSSL's CMake build turns it **off** by default and
needs `-DWOLFSSL_AESECB=yes`.

### CMake

```sh
git clone --branch v5.9.2-stable https://github.com/wolfSSL/wolfssl.git
cmake -S wolfssl -B wolfssl-build -DWOLFSSL_CRYPT_ONLY=yes -DWOLFSSL_AESECB=yes \
      -DWOLFSSL_EXAMPLES=no -DWOLFSSL_CRYPT_TESTS=no -DBUILD_SHARED_LIBS=OFF \
      -DCMAKE_INSTALL_PREFIX=/opt/wolfssl
cmake --build wolfssl-build --target install
```

On Windows, add `-c core.longpaths=true` to the `git clone`, because some of
wolfSSL's IDE project paths are longer than `MAX_PATH`.

### Autotools

```sh
./autogen.sh
./configure --enable-cryptonly
make && sudo make install
```

### Embedded (`user_settings.h`)

Build with `-DWOLFSSL_USER_SETTINGS`, and include at least:

```c
#define WOLFCRYPT_ONLY
#define HAVE_AES_ECB        /* wc_AesEcbEncrypt / wc_AesEcbDecrypt */
/* AES decryption is on unless NO_AES_DECRYPT is defined; don't define it. */
#define NO_AES_192          /* optional: OSDP uses AES-128 only */
#define NO_AES_256          /* optional */
/* The DRBG needs a seed source. On bare metal, provide one, for example: */
/* #define CUSTOM_RAND_GENERATE_BLOCK  my_hw_trng_generate_block       */
```

Any hardware AES acceleration that wolfCrypt supports on your target, such as
STM32 CRYP, ESP32, NXP LTC/DCP or Microchip, is used transparently through the
same `wc_Aes*` calls.

## Building OSDP-Embedded with the port

The CMake target is opt-in:

```sh
cmake -S OSDP-Embedded -B build -DOSDP_PORT_WOLFCRYPT=ON -DCMAKE_PREFIX_PATH=/opt/wolfssl
```

This adds `osdp::port_sc_wolfcrypt`, which links `wolfssl::wolfssl` publicly:

```cmake
target_link_libraries(my_reader PRIVATE
    osdp::core osdp::messages osdp::pd osdp::port_sc_wolfcrypt)
```

A build system other than CMake (PlatformIO, vendor IDEs) can compile the two
files `ports/wolfcrypt/osdp_sc_wolfcrypt.{h,c}` directly.

## Using it

The port has two setters. That follows OSDP-Embedded's rule that a port never
installs an RNG as a side effect:

- `osdp_sc_wolfcrypt_aes128(ctx, &crypto)` fills in AES encrypt and decrypt,
  and always has to be called.
- `osdp_sc_wolfcrypt_rng(ctx, &crypto)` adds wolfCrypt's Hash-DRBG as
  `rand_bytes`. It's opt-in: call it when that DRBG is the RNG you want. On
  bare metal, that means wolfSSL has a real seed source configured.

```c
#include "osdp_sc_wolfcrypt.h"

static osdp_sc_wolfcrypt_t wc_ctx;   /* must outlive the PD/ACU instance */
osdp_sc_crypto_t crypto = {0};

if (osdp_sc_wolfcrypt_aes128(&wc_ctx, &crypto) != OSDP_OK ||
    osdp_sc_wolfcrypt_rng(&wc_ctx, &crypto)    != OSDP_OK) {
    /* wolfCrypt could not initialise (for example, no seed source) */
}

/* PD */
osdp_pd_set_sc_crypto(&pd, &crypto);
osdp_pd_set_sc_scbk(&pd, my_scbk);

/* ...or ACU */
osdp_acu_set_sc_crypto(&acu, &crypto);
osdp_acu_set_pd_scbk(&acu, pd_address, pd_scbk);
osdp_acu_start_sc_handshake(&acu, pd_address, false);

/* at shutdown */
osdp_sc_wolfcrypt_free(&wc_ctx);
```

Design notes:

- **One context per OSDP instance.** The context holds the wolfCrypt `Aes`
  object, so no block operation needs the roughly 850-byte key-schedule struct
  on the stack. Every call changes that object, so each `osdp_pd_t` gets its
  own context. An `osdp_acu_t` shares one context across all its PDs.
- **`wolfCrypt_Init()` is handled.** Each context takes one `wolfCrypt_Init()`
  reference and `free` drops it. wolfCrypt counts these references, so an
  application that initialises wolfCrypt itself is unaffected. This matters
  because `wc_InitRng` faulted without a prior `wolfCrypt_Init()` in our
  Windows test build, even though AES worked.
- **Key per call.** The OSDP HAL gives the key with every block, and Secure
  Channel switches between S-ENC, S-MAC1, S-MAC2 and the SCBK inside a single
  message. The port therefore expands the key every time and keeps no cache,
  since a cache would keep missing.
- **In-place safe.** OSDP-Embedded may pass the same buffer as input and
  output. The port writes each block through a local buffer, which stays safe
  on hardware AES engines that read the input by DMA, and wipes that buffer
  afterwards.
- **Errors.** A wolfCrypt failure returns `OSDP_ERR_INVALID_ARG`, and
  OSDP-Embedded abandons that handshake or message. After
  `osdp_sc_wolfcrypt_free`, the callbacks refuse to run rather than touch
  freed state.
- **Crypto callbacks (`WOLF_CRYPTO_CB`)** currently use `INVALID_DEVID`.
  Sending AES to a secure element would need a device-ID parameter, which is
  easy to add.

## Testing

Configuring OSDP-Embedded with `-DOSDP_PORT_WOLFCRYPT=ON` (and the default
`OSDP_BUILD_TESTS=ON`) adds two kinds of tests:

- **The whole Secure Channel suite, re-run on wolfCrypt.** That means the
  AES/key/CBC/MAC/payload/wrap known-answer tests, the PD and ACU handshake
  tests, the in-process PD↔ACU SCS_11 to SCS_18 loopback, and a byte-exact
  replay of a libosdp-conformance RS-485 capture. These run as
  `test_*_wolfcrypt` next to the tiny-AES originals.
- **`test_port_wolfcrypt`,** which tests the port itself: the NIST SP 800-38A
  ECB vectors in both directions, in-place operation, switching keys between
  blocks, how the setters combine, the DRBG, and refusal of bad arguments or
  use after free.

```sh
ctest --test-dir build -C Debug
```

Verified on 2026-09-24 against wolfSSL v5.9.2-stable (CMake, crypto-only,
static, MSVC 19.37 x64): 42 of 42 tests passed, including all 11
wolfCrypt-specific ones.

## Licensing

OSDP-Embedded is available under GPL-3.0-or-later or a commercial license from
Z-bit Systems, LLC. wolfSSL is available under GPLv3 or a commercial license
from wolfSSL Inc. The two GPL options are compatible. A closed-source product
needs a commercial license for each library.

## Support

- OSDP-Embedded: <https://github.com/Z-bit-Systems-LLC/OSDP-Embedded/issues>
- wolfSSL: support@wolfssl.com
