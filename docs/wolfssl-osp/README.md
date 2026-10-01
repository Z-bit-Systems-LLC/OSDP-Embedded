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
#define NO_AES_256          /* optional — but NOT with SC2, which is AES-256 */
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

## SC2 and asymmetric pairing

On the SC2 line (`feature/osdp-sc2`), `ports/wolfcrypt` also binds the two
newer HALs: `osdp_sc2_crypto_t` for Secure Channel 2 (the quantum-resistant
channel) and `osdp_pair_crypto_t` for certificate-based pairing, which derives
the SC2 key (see [`../pairing-design.md`](../pairing-design.md)).

| Port | Vtable members | wolfCrypt API |
| --- | --- | --- |
| `osdp_sc2_wolfcrypt` | `aes256_gcm_encrypt` / `_decrypt` | `wc_AesGcmSetKey` + `wc_AesGcmEncrypt` / `wc_AesGcmDecrypt` |
| | `aes256_ecb_encrypt` | `wc_AesEcbEncrypt`, or `wc_AesEncryptDirect` without `HAVE_AES_ECB` |
| | `rand_bytes` (opt-in) | `wc_RNG_GenerateBlock` |
| | `kmac256` | **not supplied** — see below |
| `osdp_pair_wolfcrypt` | `ml_kem768_keygen` / `_encaps` / `_decaps` | `wc_MlKemKey_MakeKeyWithRandom` / `EncapsulateWithRandom` / `Decapsulate` |
| | `ml_dsa44_sign` / `_verify` | `wc_dilithium_sign_ctx_msg_with_seed` / `wc_dilithium_verify_ctx_msg` |
| | `sha256`, `hmac_sha256`, `hkdf_sha256` | `wc_Sha256Hash`, `wc_Hmac*`, `wc_HKDF` |
| | `rand_bytes` | the context's entropy source (below) |

**KMAC256 is not in wolfCrypt.** It has SHA-3 and SHAKE but no cSHAKE, and its
Keccak permutation is internal, so the SC2 port leaves `kmac256` for the
caller to bind after the setter. The tests use `vendor/tiny-kmac`.

### wolfSSL build for SC2 + pairing

wolfSSL 5.9 (CMake):

```sh
cmake -S wolfssl -B wolfssl-build -DWOLFSSL_AESECB=yes -DWOLFSSL_AESGCM=yes \
      -DWOLFSSL_HKDF=yes -DWOLFSSL_SHA3=yes -DWOLFSSL_SHAKE256=yes \
      -DWOLFSSL_MLKEM=yes -DWOLFSSL_MLDSA=yes \
      -DWOLFSSL_EXAMPLES=no -DWOLFSSL_CRYPT_TESTS=no -DBUILD_SHARED_LIBS=OFF \
      -DCMAKE_INSTALL_PREFIX=/opt/wolfssl
```

Leave out `-DWOLFSSL_CRYPT_ONLY=yes` here. With ML-DSA enabled, 5.9.2's
crypto-only library fails to link into anything that uses it: `asn.c`
references `GetCA` / `GetCAByName`, which live in the TLS layer that
crypto-only drops. This was seen with both MSVC and GNU ld. wolfSSL 5.8's
CMake build has no ML-DSA switch at all, so use `user_settings.h` there.

`user_settings.h` (for example, the ESP-IDF component), in addition to the SC1
settings above:

```c
#define WOLFSSL_HAVE_MLKEM
#define WOLFSSL_WC_MLKEM
#define HAVE_DILITHIUM
#define WOLFSSL_WC_DILITHIUM
#define WOLFSSL_SHA3
#define WOLFSSL_SHAKE128
#define WOLFSSL_SHAKE256
#define HAVE_AESGCM
#define HAVE_HKDF
/* Optional, recommended on an MCU — see the memory table below: */
#define WOLFSSL_NO_ML_DSA_65
#define WOLFSSL_NO_ML_DSA_87
#define WOLFSSL_DILITHIUM_SIGN_SMALL_MEM
#define WOLFSSL_DILITHIUM_VERIFY_SMALL_MEM
#define WOLFSSL_DILITHIUM_MAKE_KEY_SMALL_MEM
#define WOLFSSL_SMALL_STACK
/* A PD-only build may also drop the ACU half of ML-KEM; the matching
 * callbacks then report OSDP_ERR_NOT_SUPPORTED: */
/* #define WOLFSSL_MLKEM_NO_MAKE_KEY    */
/* #define WOLFSSL_MLKEM_NO_DECAPSULATE */
```

The port stops the compile with an `#error` naming whichever of ML-KEM-768,
ML-DSA-44 signing and verification, HKDF or AES-GCM is missing. Tested
against wolfSSL 5.8.2 (`user_settings.h`) and 5.9.2 (CMake).

CMake targets: `osdp::port_sc2_wolfcrypt` always builds with the option.
`osdp::port_pair_wolfcrypt` builds only when the installed wolfSSL's
`options.h` shows ML-KEM, ML-DSA and HKDF. Otherwise configure says so and
skips it. Other build systems compile the `.c` files in `ports/wolfcrypt`
directly.

### Using the SC2 and pairing ports

```c
#include "osdp_sc2_wolfcrypt.h"
#include "osdp_pair_wolfcrypt.h"

static osdp_sc2_wolfcrypt_t  wc2;   /* each must outlive its PD/ACU */
static osdp_pair_wolfcrypt_t wcp;   /* ~21 KB: give it static storage */
osdp_sc2_crypto_t  crypto2 = {0};
osdp_pair_crypto_t pair    = {0};

/* SC2: AES from wolfCrypt, KMAC from elsewhere, RNG opt-in. */
osdp_sc2_wolfcrypt_aes256(&wc2, &crypto2);
osdp_sc2_wolfcrypt_rng(&wc2, &crypto2);      /* or bind your own */
crypto2.kmac256 = my_kmac256;

/* Pairing: one entropy source for everything, then the device key exactly
 * as tools/osdp-pair-provision wrote it (1312-byte pk, 2560-byte sk). */
osdp_pair_wolfcrypt_init(&wcp, &pair);
osdp_pair_wolfcrypt_rng(&wcp);               /* or _set_rand(&wcp, fn, user) */
osdp_pair_wolfcrypt_set_dsa(&wcp, DEVICE_PK, DEVICE_SK, sizeof DEVICE_SK);
```

Design notes:

- **Drop-in for `ports/pqclean`.** Both ports draw random bytes in the same
  sizes and order as PQClean's `randombytes()` calls: 64 bytes for an ML-KEM
  key, 32 for encapsulation, 32 for an ML-DSA seed and 32 per signature. Fed
  the same bytes, both ports produce byte-identical keys, ciphertexts, shared
  secrets and signatures. The ML-DSA-44 private key is the same 2560-byte
  FIPS 204 encoding, so a provisioned credential loads unchanged.
- **No default entropy source.** Pairing draws all of its randomness from one
  source in the context: wolfCrypt's DRBG (`osdp_pair_wolfcrypt_rng`) or the
  caller's (`osdp_pair_wolfcrypt_set_rand`, which takes precedence). With
  neither installed, key generation, encapsulation, signing and `rand_bytes`
  fail with `OSDP_ERR_NOT_SUPPORTED` instead of using predictable bytes.
- **Hedged signing.** ML-DSA-44 signs in FIPS 204 hedged mode with an empty
  context string, as PQClean does. Every signature needs 32 fresh bytes, so a
  PD with a provisioned key still needs an entropy source.
- **GCM decrypt wipes on a bad tag.** wolfCrypt's software GCM writes
  plaintext before it compares the tag. The HAL promises output only for a
  valid tag, so on a mismatch the port zeroes the output and returns
  `OSDP_ERR_BAD_CRC`.
- **One context per role.** The pairing context's single ML-KEM key object
  holds the ACU's ephemeral key between keygen and decaps. A PD's encaps
  loads the peer's key into the same object and discards any stashed one.

### Memory (PD side, wolfSSL 5.8.2)

Peak stack and peak wolfSSL heap. Measured on x86-64 gcc `-O2` with a
painted thread stack and a counting allocator, with a `user_settings.h`
matching the ESP-IDF settings above. Expect RISC-V32 and Xtensa frames to
differ somewhat, so check with `uxTaskGetStackHighWaterMark()` on the
target.

| Operation | Small-mem settings | wolfSSL defaults | PQClean port (stack only) |
| --- | --- | --- | --- |
| ML-DSA-44 sign (3 KB message) | 2.0 KB / 16.2 KB | 2.9 KB / 50.2 KB | 52 KB |
| ML-DSA-44 verify | 1.0 KB / 8.8 KB | 1.9 KB / 29.7 KB | 36 KB |
| ML-KEM-768 encaps | 1.3 KB / 11.3 KB | 1.4 KB / 10.8 KB | 14 KB |
| `osdp_pair_pd_process_msg1` (cert verify + encaps + sign) | 8.0 KB / 16.2 KB | 8.2 KB / 50.2 KB | — |
| `osdp_pair_pd_process_msg3` | 3.2 KB / 8.8 KB | 3.3 KB / 29.7 KB | — |

"Small-mem" means the `SIGN/VERIFY/MAKE_KEY_SMALL_MEM` defines plus
`WOLFSSL_SMALL_STACK`. wolfCrypt keeps the large ML-DSA buffers on the heap
even with its default settings. The small-mem defines are what cut that peak
from about 50 KB to about 16 KB. Static storage is `sizeof(osdp_pair_wolfcrypt_t)`
≈ 21 KB (two ML-DSA key objects and one ML-KEM key object) plus the
library's `osdp_pair_pd_session_t` ≈ 4.3 KB.

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

On the SC2 line the same switch also adds:

- **The SC2 suite, re-run on wolfCrypt** (`test_sc2_primitives`,
  `test_sc2_wrap`, `test_pd_sc2` and `test_loopback_sc2`, each with the
  `_wolfcrypt` suffix). In these runs KMAC stays on tiny-kmac.
- **`test_port_sc2_wolfcrypt`:** the FIPS-197 AES-256 vector, the GCM spec's
  test cases 13 and 16, in-place operation, the output wipe on a bad tag or
  tampered AAD, setter composition, the DRBG, and refusals.
- **`test_port_pair_wolfcrypt`:** SHA-256, HMAC (RFC 4231) and HKDF
  (RFC 5869) vectors; the pairing-design §9 key schedule and the demo-CA and
  ML-KEM fixed-seed public-key hashes; byte-for-byte agreement with the
  PQClean port on the same random stream; loading a provisioned PQClean
  ML-DSA key and cross-verifying signatures; full pairing handshakes with
  wolfCrypt against PQClean in both directions and wolfCrypt against itself
  on the real DRBG; and the entropy-source contract.

Verified on 2026-10-01: 61 of 61 tests passed against wolfSSL v5.9.2-stable
(CMake, full static library) with both MSVC 19.37 x64 and GCC 13 on Linux. The
two port test suites also passed against wolfSSL 5.8.2 built from a
`user_settings.h`, with and without the small-memory options.

## Licensing

OSDP-Embedded is available under GPL-3.0-or-later or a commercial license from
Z-bit Systems, LLC. wolfSSL is available under GPLv3 or a commercial license
from wolfSSL Inc. The two GPL options are compatible. A closed-source product
needs a commercial license for each library.

## Support

- OSDP-Embedded: <https://github.com/Z-bit-Systems-LLC/OSDP-Embedded/issues>
- wolfSSL: support@wolfssl.com
