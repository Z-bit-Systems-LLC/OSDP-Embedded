// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Z-bit Systems, LLC

#ifndef OSDP_PD_H
#define OSDP_PD_H

#include "osdp/osdp_buz_state.h"
#include "osdp/osdp_frame.h"
#include "osdp/osdp_led_state.h"
#include "osdp/osdp_multipart.h"
#include "osdp/osdp_replies.h"
#include "osdp/osdp_sc.h"
#include "osdp/osdp_sc2.h"
#include "osdp/osdp_sc2_crypto.h"
#include "osdp/osdp_sc_crypto.h"
#include "osdp/osdp_stream.h"
#include "osdp/osdp_types.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Opt-in extension hook for SC2 asymmetric pairing (osdp::pd_pair). When a
 * pairing driver is attached (`pd->pair != NULL`, via osdp_pd_attach_pair),
 * the PD routes cleartext osdp_PAIR — and POLL while a multi-fragment Msg2
 * is being delivered — through this vtable, which is the first member of the
 * caller-owned pairing state. pd.c dispatches through the pointer and never
 * names a pairing symbol, so the pairing driver and its PQC-adjacent
 * dependencies are linked only into a PD that actually attaches one. */
struct osdp_pd;
typedef struct osdp_pd_pair_hook {
    /* True if the pairing driver should handle this command. */
    bool   (*wants)(struct osdp_pd *pd, const osdp_frame_t *cmd);
    /* Build the reply into pd->tx_buf; return its length (0 = no reply). */
    size_t (*handle)(struct osdp_pd *pd, const osdp_frame_t *cmd);
    /* Invoked right after the reply is transmitted, for the deterministic
     * post-Result cleartext->SC2 handoff (apply SCBK strictly after send). */
    void   (*post_send)(struct osdp_pd *pd);
} osdp_pd_pair_hook_t;

/* osdp_pd — Peripheral Device-side state machine and reply pipeline.
 *
 * This is the role-specific layer that sits on top of `osdp::core`.
 * The library remains freestanding: no malloc, no globals, no I/O of
 * its own. The consumer supplies a transport (RS-485 UART, TCP socket,
 * test loopback, ...) via a callback vtable, and an application-level
 * command handler that turns inbound commands into outbound replies.
 *
 * Lifecycle:
 *
 *     osdp_pd_t pd;
 *     osdp_pd_init(&pd, my_address);
 *     osdp_pd_set_transport(&pd, &my_transport);
 *     osdp_pd_set_command_handler(&pd, my_handler, my_user_ptr);
 *     for (;;) {
 *         osdp_pd_tick(&pd);
 *         // ... cooperative scheduling / sleep / wfi
 *     }
 *
 * Capabilities:
 *   - Address filtering (accept own address + broadcast 0x7F).
 *   - Stream-decoder integration (auto-resync, CRC/checksum validation).
 *   - Application command handler invoked on each accepted command;
 *     reply is built and emitted via transport.write().
 *   - Echoes inbound sequence number / address / integrity mode in
 *     the reply, per spec section 5.9.
 *   - Sequence number policing per spec 5.9 Table 2: a frame BYTE-
 *     IDENTICAL to the previous accepted command is treated as a
 *     retransmit and the cached reply is replayed without re-invoking
 *     the application handler. SQN-only matching is insufficient
 *     because of OSDP's 1→2→3→1 cyclic counter; comparing wire bytes
 *     handles wraparound and the OSDP.Net-style "ACU resets state but
 *     reuses SQN" edge case correctly.
 *   - Online / offline state tracking per spec 5.7: the PD considers
 *     itself offline after OSDP_PD_OFFLINE_TIMEOUT_MS without a
 *     successfully transmitted reply. On the offline transition the
 *     sequence-number cache is cleared so a reconnect begins cleanly.
 *     Requires the transport to provide a `now_ms` callback; without
 *     one the timeout is disabled and the PD is "online" after first
 *     successful reply.
 *   - Optional Secure Channel: when the application supplies a crypto
 *     vtable, an SCBK and/or SCBK-D, and a cUID via osdp_pd_set_sc_*,
 *     the PD accepts inbound CHLNG / SCRYPT and drives the SCS_11..14
 *     handshake. After SCS_14 the session struct's `established` flag
 *     flips true and both MAC chain entries are seeded with the
 *     Initial R-MAC. SCS_15 and SCS_17 commands are then unwrapped
 *     (MAC verified, payload decrypted for SCS_17) and dispatched
 *     through the same osdp_pd_command_cb the non-SC path uses — the
 *     application sees plaintext command codes and payload bytes
 *     either way. Replies are wrapped under SCS_16 by default,
 *     SCS_18 when the reply has a non-empty payload (the encryption
 *     decision is keyed off payload length per spec D.1.4 and is
 *     enforced inside osdp_sc_wrap_frame). Without SC configuration
 *     the PD continues to NAK SCB-bearing frames with code 0x05.
 *
 * Deferred for subsequent commits:
 *   - Inter-character timeout policing.
 *   - Multi-record reply convenience helpers (currently the app
 *     flat-buffers).
 *   - PD-side session-loss tracking (the ACU side handles spec D.1.4
 *     conditions today; the PD currently relies on the offline
 *     timeout to notice when something went wrong). */

/* ---- Transport HAL ------------------------------------------------------*/

/* User-supplied I/O callbacks. All are non-blocking; PD will call them
 * repeatedly from osdp_pd_tick(). */
typedef struct osdp_pd_transport {
    /* Read up to `cap` bytes into `buf`. Returns the number of bytes
     * actually read (0 if no data is available right now). Negative
     * return values are reserved for future error reporting; for now,
     * implementations should return 0 on idle and never negative. */
    int (*read)(void *user, uint8_t *buf, size_t cap);

    /* Write all `len` bytes from `buf`. Implementations may block
     * briefly to enqueue into a UART driver, but should not stall the
     * caller indefinitely. Returns the number of bytes accepted; the
     * PD treats a short write as a transmission error. */
    int (*write)(void *user, const uint8_t *buf, size_t len);

    /* Monotonic millisecond clock. Optional; if NULL, online/offline
     * timeout tracking is disabled (the PD is considered "online" as
     * soon as it has sent a reply, and stays so forever). 32-bit wrap
     * (every ~49.7 days) is handled via unsigned subtraction. */
    uint32_t (*now_ms)(void *user);

    /* Opaque pointer threaded back into every callback. */
    void *user;
} osdp_pd_transport_t;

/* ---- Application handler ------------------------------------------------*/

/* The reply produced by an application-level command handler. The
 * application sets `code` to the desired osdp_REPLY_* value (e.g.
 * OSDP_REPLY_ACK, OSDP_REPLY_PDID) and points `payload` at a buffer of
 * `payload_len` bytes containing the body of that reply. The buffer
 * must remain valid until the handler returns; the PD copies the bytes
 * into its own TX scratch before transport.write() is called. */
typedef struct osdp_pd_reply {
    uint8_t        code;
    const uint8_t *payload;
    size_t         payload_len;
} osdp_pd_reply_t;

/* Command handler. The PD has already validated the inbound frame
 * (CRC/checksum, address match, length sanity) before invoking this.
 *
 * The handler may inspect `cmd_code` and `payload` and produce a reply. The
 * return value selects what goes on the wire, mapped onto spec Table 47:
 *
 *   - OSDP_OK                  fill in *reply; the PD frames and sends it.
 *   - OSDP_ERR_NOT_SUPPORTED   osdp_NAK 0x03 (Unknown Command Code). Use
 *                              this for command codes you don't implement.
 *   - OSDP_ERR_BAD_PAYLOAD     osdp_NAK 0x02 (bad command length) — the
 *     OSDP_ERR_BAD_LENGTH      command is recognised but its payload is
 *                              malformed or the wrong size.
 *   - OSDP_ERR_INVALID_ARG     osdp_NAK 0x09 (unable to process command
 *                              record) — well-formed but unusable content,
 *                              e.g. a reader number this PD doesn't have.
 *   - OSDP_ERR_BUSY            osdp_BUSY (spec 7.19): not ready yet, ask
 *                              again. The PD sends it at sequence 0, in the
 *                              clear even under Secure Channel, and does not
 *                              cache it — the ACU repeats the command
 *                              unchanged until it gets something else.
 *   - any other osdp_status_t  treated as an unrecognised internal error;
 *                              the command is dropped with no reply at all.
 *
 * Answering nothing is a deliberate last resort: the ACU waits out its reply
 * timeout, which is slower for it than being told no. Prefer one of the
 * mapped codes above wherever the situation fits one.
 */
typedef osdp_status_t (*osdp_pd_command_cb)(
    void           *user,
    uint8_t         cmd_code,
    const uint8_t  *payload,
    size_t          payload_len,
    osdp_pd_reply_t *reply);

/* ---- Reader LED observation --------------------------------------------
 *
 * The PD transparently decodes inbound osdp_LED (0x69) commands and folds
 * each record into an internal bank of osdp_led_t resolvers, so the
 * application never has to parse the LED command itself: it just registers
 * a callback and/or queries the current colour. This runs alongside the
 * normal command handler — the LED command still flows to cmd_cb (which
 * typically ACKs it) and the wire behaviour is unchanged. */

/* Fired whenever a reader LED's *displayed* colour changes — on a new LED
 * command, when a temporary override's timer expires, and on each flash
 * on/off transition. `color` is an osdp_led_color_t value (0x00 black/off
 * .. 0x07 white). Time-driven transitions (timer expiry, flashing) are
 * detected inside osdp_pd_tick(), so they only fire if the transport
 * supplies a now_ms clock; a command-driven change fires immediately
 * regardless. The callback must not re-enter the PD API. */
typedef void (*osdp_pd_led_cb)(void   *user,
                               uint8_t reader_no,
                               uint8_t led_no,
                               uint8_t color);

/* ---- Reader buzzer observation -----------------------------------------
 *
 * The PD decodes inbound osdp_BUZ (0x6A) commands and folds each into a
 * resolver (osdp_buz_t) keyed by reader, so — exactly like the LED — the
 * application just registers a change callback and/or queries the current
 * state instead of parsing the command. The buzzer's `on_time`/`off_time`/
 * `count` pattern is resolved over time: the callback fires when the buzzer
 * starts sounding, on each beep/silence edge of the pattern, and once more
 * when the pattern finishes (a final "silent"). */

/* Fired whenever a reader buzzer's *sounding* state changes — when a
 * command starts it, on each on/off edge of the pattern, and when the
 * pattern (count cycles) completes. `sounding` is true while the buzzer is
 * making sound, false in the gaps and once it's done. `tone` is the
 * tone_code from the driving command (0x01 off / 0x02 default tone). The
 * time-driven edges are detected inside osdp_pd_tick(), so they need the
 * transport's now_ms clock; the initial start fires immediately. Must not
 * re-enter the PD API. */
typedef void (*osdp_pd_buzzer_cb)(void   *user,
                                  uint8_t reader_no,
                                  bool    sounding,
                                  uint8_t tone);

/* ---- Communication configuration (osdp_COMSET) -------------------------
 *
 * osdp_COMSET (0x6E) asks the PD to adopt a new address and/or baud rate.
 * Per spec 6.13 the change takes effect only AFTER the PD has finished
 * replying, and the reply (osdp_COM, 0x54) reports the values the PD will
 * actually use. The PD state machine owns the 7-bit address (it filters
 * inbound frames on it and stamps it into every reply), so COMSET is
 * handled inside the library rather than by the application command
 * handler — analogous to how osdp_KEYSET rotates the stored SCBK.
 *
 * Two optional application hooks bracket the exchange:
 *
 *   - `decide`  runs BEFORE the osdp_COM reply is built. `eff_*` are
 *     pre-seeded with the ACU's requested values; the handler may lower or
 *     replace them if the PD cannot comply (spec 6.13: "it will return the
 *     values that it will use"). Leave them untouched to accept the request.
 *     If no handler is registered the request is accepted verbatim. An
 *     effective address above 0x7E is rejected and the current address is
 *     kept instead.
 *
 *   - `applied` runs AFTER the osdp_COM reply has been handed to the
 *     transport and the PD has adopted the new address. The application MUST
 *     now reconfigure its transport to `baud` and SHOULD persist
 *     (address, baud) to non-volatile storage. Reconfiguring the UART any
 *     earlier would corrupt the in-flight reply. NOTE: the transport's
 *     write() returning does not guarantee the bytes are physically on the
 *     wire (most drivers only queue them), so `applied` must DRAIN the
 *     transmitter before changing the baud — otherwise the tail of the
 *     osdp_COM reply clocks out at the new rate and the ACU never follows.
 *     tcdrain() on POSIX; FlushFileBuffers plus a wait on Windows (USB
 *     adapters hold bytes in a chip FIFO past FlushFileBuffers).
 *
 * A malformed COMSET payload (not exactly 5 bytes) is answered with
 * NAK 0x02 (bad command length) and neither hook fires. */

/* Decide the effective comms parameters for an inbound COMSET. `eff_*`
 * arrive holding the requested values; write the values the PD will use. */
typedef void (*osdp_pd_comset_cb)(void     *user,
                                  uint8_t   req_address,
                                  uint32_t  req_baud,
                                  uint8_t  *eff_address,
                                  uint32_t *eff_baud);

/* Notify that the COMSET reply has been sent and the new address is now
 * live. Switch the transport to `baud` here and persist to NVM. */
typedef void (*osdp_pd_comset_applied_cb)(void    *user,
                                          uint8_t  address,
                                          uint32_t baud);

/* ---- File transfer (osdp_FILETRANSFER) ---------------------------------
 *
 * osdp_FILETRANSFER (0x7C) streams a file (firmware image, config blob, ...)
 * ACU → PD as a sequence of fragments at monotonically increasing offsets,
 * each answered with an osdp_FTSTAT (0x7A) status. Like osdp_COMSET the
 * command is handled inside the library rather than by the app command
 * handler: the PD decodes each fragment, REASSEMBLES it into a caller-owned
 * buffer, tracks the running offset, and builds/sends the FTSTAT — the
 * application never parses the wire message. It only *evaluates* the bytes
 * through a per-fragment callback whose verdict drives the reported status.
 *
 * Two receiver modes, both driving the same per-fragment callback:
 *   - REASSEMBLY (osdp_pd_set_file_receiver): supply a buffer + capacity
 *     (caller-owned — the freestanding core allocates nothing). The core
 *     copies each fragment into it and hands the whole accumulated file to
 *     the callback (info->data). A transfer larger than the buffer is
 *     aborted. Best for small config/display blobs, or targets with room to
 *     hold the whole file.
 *   - STREAMING (osdp_pd_set_file_stream): no buffer. The core hands each
 *     fragment to the callback as it arrives (info->fragment) without
 *     accumulating — info->data is NULL — and there is no size ceiling. Best
 *     for RAM-constrained targets that persist each fragment to flash as it
 *     comes in (firmware update). The app owns storage entirely.
 * Without a registered receiver the PD NAKs osdp_FILETRANSFER with code 0x03
 * (does not support file transfer).
 *
 * Reassembly invariants the core enforces (any violation aborts the
 * transfer with FtStatusDetail = -1 and resets state, so the ACU may
 * restart at offset 0):
 *   - the first fragment of a transfer has offset 0;
 *   - total_size fits within the receiver buffer capacity;
 *   - offsets are contiguous (each fragment's offset equals the number of
 *     bytes already received) and the fragment stays within total_size;
 *   - the FtType / total_size do not change mid-transfer.
 * A byte-identical retransmit of the previous fragment is replayed from the
 * SQN cache (spec 5.9) BEFORE reassembly runs, so a lost FTSTAT never
 * corrupts the running offset.
 *
 * Deferred (not needed while the evaluation callback is synchronous): the
 * "finishing" (FtStatusDetail = 3) idle-fragment protocol and FtUpdateMsgMax
 * fragment-size throttling. The PD always reports update_msg_max = 0. */

/* Snapshot of an accepted osdp_FILETRANSFER fragment handed to the
 * evaluation callback. `fragment` / `fragment_len` are THIS message's bytes;
 * `received` is the contiguous byte count so far (including this fragment).
 * `data` is the accumulated reassembly buffer in REASSEMBLY mode, or NULL in
 * STREAMING mode (where only `fragment` is available). `complete` is true on
 * the final fragment (received == total_size). Every pointer is valid only
 * for the duration of the callback. */
typedef struct osdp_pd_file_info {
    uint8_t        ft_type;       /* FtType (see osdp_ft_type_t)            */
    uint32_t       total_size;    /* full declared file size               */
    uint32_t       offset;        /* offset of this fragment               */
    const uint8_t *fragment;      /* this fragment's bytes (NULL if empty) */
    size_t         fragment_len;  /* length of this fragment               */
    const uint8_t *data;          /* reassembly buffer base, or NULL when
                                   * streaming (use `fragment` instead)     */
    uint32_t       received;      /* contiguous bytes so far, incl. this   */
    bool           complete;      /* received == total_size                */
} osdp_pd_file_info_t;

/* Per-fragment file evaluation callback. Return an osdp_status_t that the
 * core maps into the outgoing osdp_FTSTAT.FtStatusDetail:
 *   OSDP_OK                -> proceed (0) mid-file; processed (1) when complete
 *   OSDP_ERR_BAD_PAYLOAD   -> malformed (-3), transfer aborted
 *   OSDP_ERR_NOT_SUPPORTED -> unrecognized (-2), transfer aborted
 *   any other              -> abort (-1), transfer aborted
 * The callback must not re-enter the PD API. */
typedef osdp_status_t (*osdp_pd_file_cb)(void *user,
                                         const osdp_pd_file_info_t *info);

/* ---- Status providers ---------------------------------------------------
 *
 * osdp_LSTAT / osdp_ISTAT / osdp_OSTAT / osdp_RSTAT ask the PD to report
 * device state. The reply layout is fixed by the spec, so the library builds
 * it; only the values are the application's business. Bind a provider and the
 * four status commands stop reaching the command handler entirely.
 *
 * Every member is optional. A NULL member (or no provider at all) leaves that
 * command falling through to `cmd_cb` exactly as before, so an existing
 * application that hand-builds its own osdp_LSTATR keeps working.
 *
 * The three array-valued members write up to `cap` status bytes into `out`
 * and return how many they wrote; `cap` is OSDP_PD_REPLY_SCRATCH_LEN. A
 * return above `cap` is clamped. Returning 0 is legal and produces an empty
 * report — a PD with no inputs genuinely has nothing to say. */
typedef struct osdp_pd_status_provider {
    /* osdp_LSTAT -> osdp_LSTATR. Write the tamper and power bytes
     * (OSDP_LSTATR_NORMAL / _TAMPER / _POWER_FAILURE). */
    void   (*local)  (void *user, uint8_t *tamper, uint8_t *power);
    /* osdp_ISTAT -> osdp_ISTATR, one OSDP_ISTATR_* byte per input. */
    size_t (*inputs) (void *user, uint8_t *out, size_t cap);
    /* osdp_OSTAT -> osdp_OSTATR, one OSDP_OSTATR_* byte per output. */
    size_t (*outputs)(void *user, uint8_t *out, size_t cap);
    /* osdp_RSTAT -> osdp_RSTATR, one OSDP_RSTATR_* byte per reader. */
    size_t (*readers)(void *user, uint8_t *out, size_t cap);
} osdp_pd_status_provider_t;

/* ---- Miscellaneous command hooks ----------------------------------------*/

/* osdp_ABORT (spec 6.22). The library has already torn down any in-flight
 * file transfer and multi-part reassembly before this runs; the hook exists
 * for application-side work the core cannot know about.
 *
 * Return OSDP_OK to ACK. Any other status produces osdp_NAK 0x03, the spec's
 * "PD unable to abort" case — a firmware update past the point of no return
 * being the example it gives. With no hook bound the PD always ACKs. */
typedef osdp_status_t (*osdp_pd_abort_cb)(void *user);

/* osdp_ACURXSIZE (spec 6.20): the ACU has declared how large a reply it can
 * receive. The library stores the value (see osdp_pd_acu_rx_size) and ACKs
 * regardless; this hook is a notification, not a veto. */
typedef void (*osdp_pd_acurxsize_cb)(void *user, uint16_t max_size);

/* osdp_KEEPACTIVE (spec 6.21): hold reader operations open for `time_ms`
 * milliseconds. Zero cancels a previous extension.
 *
 * Return OSDP_OK to ACK. Any other status produces osdp_NAK 0x03. Unlike the
 * hooks above, with NO handler bound the PD NAKs 0x03 — keeping a reader
 * powered is a physical capability the core cannot fake. */
typedef osdp_status_t (*osdp_pd_keepactive_cb)(void *user, uint16_t time_ms);

/* Called once per reassembled multi-part osdp_MFG. `data` / `data_len` are
 * the whole vendor message with the multi-part headers removed; `vendor_code`
 * is the 3 bytes that prefixed every fragment.
 *
 * Return OSDP_OK to ACK, or any status from the command-handler mapping
 * (OSDP_ERR_NOT_SUPPORTED -> NAK 0x03, OSDP_ERR_INVALID_ARG -> NAK 0x09, and
 * so on). To answer with an osdp_MFGREP instead, fill in *reply as a command
 * handler would. */
typedef osdp_status_t (*osdp_pd_mfg_cb)(void *user,
                                        const uint8_t *vendor_code,
                                        const uint8_t *data, size_t data_len,
                                        osdp_pd_reply_t *reply);


/* ---- Context ------------------------------------------------------------*/

/* Reader LED bank capacity: the number of distinct (reader_no, led_no)
 * LEDs the PD tracks. Records beyond this (after all slots are claimed by
 * earlier addresses) are still ACK'd on the wire but not reflected in the
 * bank. Sized for the common case (one or two LEDs on a handful of
 * readers); bump if a deployment needs more. */
#define OSDP_PD_MAX_LEDS 8U

/* One tracked physical LED: its (reader_no, led_no) identity, the resolved
 * timer/flash state, and the last colour reported through the callback (so
 * the PD can fire only on an actual change). */
typedef struct osdp_pd_led_slot {
    bool       used;
    uint8_t    reader_no;
    uint8_t    led_no;
    uint8_t    last_color;   /* osdp_led_color_t last handed to led_cb */
    osdp_led_t state;
} osdp_pd_led_slot_t;

/* Reader buzzer bank capacity: the number of distinct readers whose buzzer
 * the PD tracks. One buzzer per reader. */
#define OSDP_PD_MAX_BUZZERS 4U

/* One tracked reader buzzer: its reader identity, the resolved on/off
 * pattern state, and the last sounding flag reported (so the PD fires only
 * on an actual change). */
typedef struct osdp_pd_buz_slot {
    bool       used;
    uint8_t    reader_no;
    bool       last_sounding;  /* last value handed to buzzer_cb */
    osdp_buz_t state;
} osdp_pd_buz_slot_t;

/* The PD's maximum message size, and the size of every working buffer
 * embedded in osdp_pd_t: the outbound frame, the Secure Channel plaintext
 * scratch, and the two spec-5.9 retransmit caches.
 *
 * Override at build time (-DOSDP_PD_BUF_LEN=..., or CMake
 * target_compile_definitions) to trade RAM against the largest message the
 * PD can handle. This one number is also what the application should report
 * as PDCAP function code 10 ("Receive BufferSize", spec B.11) — deriving the
 * advertised capability from the same constant that sizes the buffers means
 * a PD cannot promise the ACU more than it can actually hold.
 *
 * A device is a PD or an ACU, rarely both; the ACU has its own
 * OSDP_ACU_BUF_LEN, which is the value it declares in osdp_ACURXSIZE.
 *
 * Independently of this, osdp_pd_set_buffers rebinds the working regions at
 * caller-owned storage at run time — use the constant to set what every PD
 * context costs, and the setter when one particular PD needs something
 * different. */
#ifndef OSDP_PD_BUF_LEN
#define OSDP_PD_BUF_LEN 512U
#endif

/* Smallest buffer that can ever hold a complete frame: header + code + CRC
 * (spec 5.6). osdp_pd_set_buffers rejects anything below this so a mis-sized
 * binding fails loudly at configuration time rather than silently truncating
 * every reply at run time. */
#define OSDP_PD_BUF_MIN_LEN OSDP_FRAME_MIN_LEN_CRC

/* Scratch for reply payloads the LIBRARY builds (as opposed to those the
 * application hands back from its command handler). The unified command
 * dispatch returns a reply whose payload may point here, so the buffer must
 * outlive the dispatch call and live until the caller has framed the reply.
 *
 * The fixed-size library replies are small (osdp_FTSTAT 7 bytes, osdp_COM 5,
 * osdp_NAK 1). The size driver is the status reports: osdp_ISTATR, _OSTATR
 * and _RSTATR carry one byte per input / output / reader, so this constant
 * is also the ceiling on how many items a status provider can report in one
 * reply. 64 covers any realistic reader panel; override it for a PD with
 * more points than that. */
#ifndef OSDP_PD_REPLY_SCRATCH_LEN
#define OSDP_PD_REPLY_SCRATCH_LEN 64U
#endif

/* Largest reply the PD assumes an ACU can receive before any osdp_ACURXSIZE
 * says otherwise (spec 6.26). Deliberately conservative — an ACU that can
 * take more will tell the PD. */
#define OSDP_PD_DEFAULT_ACU_RX_SIZE 128U

/* Spec 5.7: PD considers itself offline if the gap between messages
 * to which it responds exceeds 8 seconds. */
#define OSDP_PD_OFFLINE_TIMEOUT_MS 8000U

/* ---- Secure Channel state (embedded in osdp_pd_t) ----------------------
 *
 * The PD treats SC as fully optional: leave the fields below at their
 * zeroed defaults and the PD continues to refuse SCB-bearing frames
 * with NAK 0x05 exactly as before. Configure them via the
 * osdp_pd_set_sc_* setters and the PD will accept the SCS_11..14
 * handshake and (in subsequent commits) SCS_15..18 operational
 * traffic. The crypto callbacks remain caller-supplied — `osdp::core`
 * never vendors a crypto implementation. */
typedef struct osdp_pd_sc {
    osdp_sc_crypto_t       crypto;
    bool                   crypto_set;

    uint8_t                scbk  [OSDP_SC_KEY_LEN];
    bool                   scbk_set;
    uint8_t                scbk_d[OSDP_SC_KEY_LEN];
    bool                   scbk_d_set;
    uint8_t                cuid  [OSDP_SC_CUID_LEN];
    bool                   cuid_set;

    osdp_sc_session_t      session;

    /* Mid-handshake state: populated by SCS_11 (CHLNG) handler and
     * consumed by SCS_13 (SCRYPT) handler. */
    bool                   got_chlng;
    uint8_t                rnd_a       [OSDP_SC_RND_LEN];
    uint8_t                rnd_b       [OSDP_SC_RND_LEN];
    uint8_t                key_selector; /* 0 = SCBK-D, 1 = SCBK */
} osdp_pd_sc_t;

/* ---- Secure Channel 2 state (embedded in osdp_pd_t) --------------------
 *
 * Parallel to osdp_pd_sc_t but for OSDP-SC2 (AES-256-GCM / KMAC256).
 * SC2 is device-specific-key only — there is no SCBK-D install mode —
 * so the PD needs just the 32-byte SCBK, the cUID, and a crypto vtable.
 * Left zeroed, the PD refuses SC2 SCB frames (SCS_21..28) with NAK 0x05
 * exactly as before. Opt in via the osdp_pd_set_sc2_* setters. */
typedef struct osdp_pd_sc2 {
    osdp_sc2_crypto_t      crypto;
    bool                   crypto_set;

    uint8_t                scbk[OSDP_SC2_KEY_LEN];
    bool                   scbk_set;
    uint8_t                cuid[OSDP_SC2_CUID_LEN];
    bool                   cuid_set;

    osdp_sc2_session_t     session;

    /* Mid-handshake state: RND.A from SCS_21 (CHLNG), RND.B generated
     * for SCS_22 (CCRYPT), consumed by SCS_23 (SCRYPT). */
    bool                   got_chlng;
    uint8_t                rnd_a[OSDP_SC2_RND_LEN];
    uint8_t                rnd_b[OSDP_SC2_RND_LEN];
} osdp_pd_sc2_t;

/* ---- Caller-owned working storage --------------------------------------
 *
 * The PD needs four scratch regions, all sized OSDP_PD_BUF_LEN by default
 * and embedded directly in osdp_pd_t so a PD works with no configuration at
 * all. Bind bigger (or smaller, or shared) caller-owned storage with
 * osdp_pd_set_buffers when the defaults don't fit:
 *
 *   tx        — the outbound frame under construction, and the bytes handed
 *               to transport.write(). Must hold the largest reply the PD
 *               will ever send, framed: payload + header + CRC (+ security
 *               block, MAC and cipher padding under SC/SC2).
 *   rx_plain  — the decrypted plaintext of an inbound SCS_17 / SCS_27
 *               command. Only used on the Secure Channel paths; a clear-text
 *               PD may point it at a 8-byte stub. Must not alias `tx`.
 *   rpl_cache — a verbatim copy of the last reply sent, replayed on a
 *               byte-identical retransmit (spec 5.9). Sized like `tx`; a
 *               reply too big to cache is simply not cached, and the next
 *               retransmit is processed fresh instead of replayed.
 *   cmd_cache — the last accepted command's wire bytes, the discriminator
 *               that identifies a retransmit. Sized for the largest command
 *               the ACU will send.
 *
 * Regions may not overlap; the library does not check for aliasing beyond
 * the tx/rx_plain pair it depends on, so keep them distinct. */
typedef struct osdp_pd_buffers {
    uint8_t *tx;         size_t tx_cap;
    uint8_t *rx_plain;   size_t rx_plain_cap;
    uint8_t *rpl_cache;  size_t rpl_cache_cap;
    uint8_t *cmd_cache;  size_t cmd_cache_cap;
} osdp_pd_buffers_t;

typedef struct osdp_pd {
    uint8_t                    address;     /* this PD's 7-bit addr  */
    osdp_stream_t              rx;          /* inbound byte buffer   */
    osdp_pd_transport_t        transport;   /* I/O callbacks         */
    osdp_pd_command_cb         cmd_cb;      /* app command handler   */
    void                      *cmd_user;
    uint8_t                    tx_buf[OSDP_PD_BUF_LEN];

    /* Payload scratch for library-built replies (osdp_COM, osdp_FTSTAT,
     * osdp_NAK, ...). osdp_pd_internal_dispatch returns a reply that may
     * point in here, so it must outlive that call — hence a context field
     * rather than a local in the dispatch function. */
    uint8_t                    reply_scratch[OSDP_PD_REPLY_SCRATCH_LEN];

    /* Working buffer for the plaintext of an inbound Secure Channel command
     * (SCS_17 / SCS_27 decrypt output). Must NOT alias the TX buffer: the
     * reply the application hands back may point into this plaintext, and the
     * SC wrap then reads it while writing the outbound frame. */
    uint8_t                    rx_plain_buf[OSDP_PD_BUF_LEN];

    /* Sequence-number policing cache (spec 5.9 Table 2). When a
     * retransmit arrives — defined by the spec as a frame BYTE-
     * IDENTICAL to the previous accepted command — the PD resends
     * `last_reply[0..last_reply_len]` without invoking cmd_cb.
     *
     * SQN ALONE is not a sufficient discriminator: the cyclic
     * progression 1→2→3→1 plus certain ACU error-recovery paths
     * (observed in OSDP.Net's ACUConsole on a SC MAC-validation
     * failure) can re-use the same SQN for a NEW command. We
     * therefore also cache the previous command's wire bytes and
     * memcmp them on every incoming frame. */
    uint8_t                    last_reply[OSDP_PD_BUF_LEN];
    size_t                     last_reply_len;
    uint8_t                    last_cmd  [OSDP_PD_BUF_LEN];
    size_t                     last_cmd_len;
    uint8_t                    last_seq;     /* 0..3 */
    bool                       have_last;

    /* Active bindings for the four working regions above. osdp_pd_init points
     * each at its embedded array; osdp_pd_set_buffers re-points any subset at
     * caller-owned storage. Every internal user goes through these — never
     * through the arrays or sizeof() — so a rebound region takes effect
     * everywhere at once. */
    uint8_t                   *tx;
    size_t                     tx_cap;
    uint8_t                   *rx_plain;
    size_t                     rx_plain_cap;
    uint8_t                   *rpl_cache;
    size_t                     rpl_cache_cap;
    uint8_t                   *cmd_cache;
    size_t                     cmd_cache_cap;

    /* Online/offline tracking (spec 5.7). `online` flips false when
     * `now_ms - last_comm_ms` exceeds OSDP_PD_OFFLINE_TIMEOUT_MS, and
     * back true on the next successful reply. */
    bool                       online;
    uint32_t                   last_comm_ms;

    /* Secure Channel state (optional; opt-in via the set_sc_* APIs). */
    osdp_pd_sc_t               sc;

    /* Secure Channel 2 state (optional; opt-in via the set_sc2_* APIs). */
    osdp_pd_sc2_t              sc2;

    /* Reader LED bank (populated transparently from inbound osdp_LED
     * commands) plus the optional change callback. */
    osdp_pd_led_slot_t         leds[OSDP_PD_MAX_LEDS];
    osdp_pd_led_cb             led_cb;
    void                      *led_user;

    /* Reader buzzer bank (populated from inbound osdp_BUZ commands) plus
     * the optional sounding-change callback. */
    osdp_pd_buz_slot_t         buzzers[OSDP_PD_MAX_BUZZERS];
    osdp_pd_buzzer_cb          buzzer_cb;
    void                      *buzzer_user;

    /* Communication configuration (osdp_COMSET) hooks and the deferred
     * change staged by the current tick. `comset_pending` is set once the
     * osdp_COM reply is built; process_frame adopts the new address and
     * fires `comset_applied_cb` after the reply has been transmitted. */
    osdp_pd_comset_cb          comset_cb;
    osdp_pd_comset_applied_cb  comset_applied_cb;
    void                      *comset_user;
    bool                       comset_pending;
    uint8_t                    comset_new_address;
    uint32_t                   comset_new_baud;

    /* File transfer (osdp_FILETRANSFER) receiver: caller-owned reassembly
     * buffer + evaluation callback, and the running transfer bookkeeping.
     * `ft_active` is true between the offset-0 fragment and completion/abort;
     * `ft_received` is the count of contiguous bytes assembled so far. */
    uint8_t                   *file_buf;
    size_t                     file_cap;
    osdp_pd_file_cb            file_cb;
    void                      *file_user;
    bool                       ft_active;
    uint8_t                    ft_type;
    uint32_t                   ft_total;
    uint32_t                   ft_received;

    /* Status providers for osdp_LSTAT / ISTAT / OSTAT / RSTAT. A NULL member
     * leaves that command falling through to cmd_cb. */
    osdp_pd_status_provider_t  status;
    void                      *status_user;

    /* Poll-response event queue (osdp_RAW, osdp_KEYPAD, osdp_FMT,
     * osdp_MFGREP). Caller-owned storage holding length-prefixed records;
     * `event_len` is the number of bytes currently occupied, always starting
     * at offset 0 — a dequeue compacts what remains down to the front rather
     * than wrapping, which keeps every payload contiguous so it can be handed
     * to the framer as a slice. */
    uint8_t                   *event_buf;
    size_t                     event_cap;
    size_t                     event_len;

    /* osdp_ACURXSIZE: the largest reply the ACU says it can receive. Seeded
     * to OSDP_PD_DEFAULT_ACU_RX_SIZE (spec 6.26) until an ACU says otherwise. */
    uint16_t                   acu_rx_size;
    osdp_pd_acurxsize_cb       acurxsize_cb;
    void                      *acurxsize_user;

    /* osdp_ABORT / osdp_KEEPACTIVE application hooks. */
    osdp_pd_abort_cb           abort_cb;
    void                      *abort_user;
    osdp_pd_keepactive_cb      keepactive_cb;
    void                      *keepactive_user;

    /* Multi-part osdp_MFG reassembly. `mfg_cb == NULL` means the application
     * has not declared its vendor protocol multi-part, so osdp_MFG payloads
     * stay opaque and go to cmd_cb — see osdp_pd_set_mfg_receiver. */
    osdp_mp_reasm_t            mfg_reasm;
    osdp_pd_mfg_cb             mfg_cb;
    void                      *mfg_user;
    /* Vendor code from the transfer in progress, so a mid-transfer switch to
     * a different vendor can be rejected rather than silently interleaved. */
    uint8_t                    mfg_vendor[3];

    /* Cleared for the current tick when the reply must NOT be cached as the
     * spec-5.9 retransmit answer. Only osdp_BUSY sets it: the ACU repeats the
     * command in its original form, so replaying a cached BUSY would answer a
     * command the PD is by then ready to handle. Transient per-tick state,
     * not configuration. */
    bool                       reply_cacheable;

    /* Optional SC2 asymmetric-pairing driver (osdp::pd_pair). NULL unless a
     * caller-owned osdp_pd_pair_t is attached via osdp_pd_attach_pair; its
     * first member is an osdp_pd_pair_hook_t through which pd.c dispatches.
     * Kept last so growing the pairing state never shifts existing fields. */
    void                      *pair;
} osdp_pd_t;

/* ---- API ----------------------------------------------------------------*/

/* Initialize a PD context. `address` is the 7-bit physical address
 * (0x00..0x7E) the PD should respond to. The broadcast address 0x7F is
 * always accepted in addition. */
void osdp_pd_init(osdp_pd_t *pd, uint8_t address);

/* Bind a transport. The supplied vtable is copied into the context;
 * the source may be on the stack or read-only. */
void osdp_pd_set_transport(osdp_pd_t *pd,
                           const osdp_pd_transport_t *transport);

/* Re-point any subset of the PD's four working regions at caller-owned
 * storage (see osdp_pd_buffers_t). Optional: a PD that never calls this uses
 * its embedded OSDP_PD_BUF_LEN arrays and behaves exactly as before.
 *
 * A member left NULL (with any capacity) keeps that region's current binding,
 * so callers can enlarge just the TX path and leave the rest alone. The
 * buffers are borrowed, not copied — they must stay valid for as long as the
 * PD is in use, and must not overlap each other.
 *
 * Returns OSDP_ERR_INVALID_ARG for a NULL pd/bufs, and OSDP_ERR_BUFFER_TOO_SMALL
 * if any supplied region is under OSDP_PD_BUF_MIN_LEN — no binding is applied
 * in either case, so a rejected call leaves the PD on its previous buffers.
 * Safe to call at any time; rebinding either retransmit cache also clears it,
 * since its recorded lengths describe bytes in storage the PD has just
 * stopped reading. Clearing costs at most one replayed retransmit — the next
 * repeat of that command is processed fresh, which is always correct. */
osdp_status_t osdp_pd_set_buffers(osdp_pd_t *pd,
                                  const osdp_pd_buffers_t *bufs);

/* Bind the application's command handler. May be called with cb=NULL
 * to detach (every command will then NAK with code 0x03). */
void osdp_pd_set_command_handler(osdp_pd_t *pd,
                                 osdp_pd_command_cb cb, void *user);

/* Largest reply payload this PD can transmit right now, in bytes.
 *
 * Answers the question an application has to answer before splitting a large
 * response across several polls: how much fits in one packet. It resolves
 * against the PD's *live* state — the currently bound TX capacity, and which
 * channel is actually established — so the number shrinks automatically once
 * Secure Channel comes up and its framing and padding start costing bytes.
 * Deriving it by hand means re-deriving it every time a security block, a
 * MAC, or a pad rule changes.
 *
 * Returns 0 for a NULL pd, or if the bound TX buffer cannot hold even an
 * empty reply. The value is a ceiling for a single message: honouring an
 * `osdp_ACURXSIZE` the ACU has declared is a separate constraint on top,
 * since that is the *peer's* limit rather than this PD's. */
size_t osdp_pd_max_reply_payload(const osdp_pd_t *pd);

/* Pump the PD state machine: read available bytes, process any complete
 * frames addressed to this PD or to the broadcast, dispatch to the
 * command handler, and send any reply. Idempotent and non-blocking;
 * call from your main loop. */
void osdp_pd_tick(osdp_pd_t *pd);

/* True iff the PD has successfully replied within the past
 * OSDP_PD_OFFLINE_TIMEOUT_MS. Always false for a freshly-initialized
 * PD; flips true after the first reply is transmitted. If the
 * transport doesn't supply a now_ms callback, the timeout is disabled
 * and the PD remains online once it has sent a reply. */
bool osdp_pd_is_online(const osdp_pd_t *pd);

/* ---- Reader LED observation --------------------------------------------*/

/* Bind the reader-LED change handler. `cb` fires whenever a tracked LED's
 * displayed colour changes (see osdp_pd_led_cb). Pass cb=NULL to detach.
 * Registering a handler does not retroactively replay current colours —
 * it reports changes from this point on. */
void osdp_pd_set_led_handler(osdp_pd_t *pd, osdp_pd_led_cb cb, void *user);

/* Current displayed colour of the given reader LED as an osdp_led_color_t
 * (0x00 black/off .. 0x07 white). Returns OSDP_LED_BLACK for an LED that
 * has never been addressed by an osdp_LED command. Resolved against the
 * transport's now_ms clock (or time 0 if none), so flashing LEDs return
 * whichever phase is current. */
uint8_t osdp_pd_led_color(const osdp_pd_t *pd,
                          uint8_t reader_no, uint8_t led_no);

/* Bind the reader-buzzer handler. `cb` fires whenever a tracked buzzer's
 * sounding state changes (see osdp_pd_buzzer_cb). Pass cb=NULL to detach. */
void osdp_pd_set_buzzer_handler(osdp_pd_t *pd, osdp_pd_buzzer_cb cb,
                                void *user);

/* True iff the given reader's buzzer is sounding right now. Resolved
 * against the transport's now_ms clock (or time 0 if none). Returns false
 * for a reader no osdp_BUZ command has addressed. */
bool osdp_pd_buzzer_sounding(const osdp_pd_t *pd, uint8_t reader_no);

/* ---- Communication configuration ---------------------------------------*/

/* Bind the osdp_COMSET hooks (see osdp_pd_comset_cb / _applied_cb). Either
 * callback may be NULL. With no `decide` handler the PD accepts the ACU's
 * requested address/baud verbatim; with no `applied` handler the PD still
 * switches its own address but the application gets no signal to change its
 * transport baud — pass an `applied` handler if the baud can actually
 * change. `user` is threaded into both. */
void osdp_pd_set_comset_handler(osdp_pd_t                *pd,
                                osdp_pd_comset_cb         decide,
                                osdp_pd_comset_applied_cb applied,
                                void                     *user);

/* ---- File transfer -----------------------------------------------------*/

/* Bind a file-transfer receiver. `buf` (capacity `cap` bytes) is the
 * caller-owned buffer the core reassembles inbound osdp_FILETRANSFER data
 * into; `cb` evaluates each accepted fragment (see osdp_pd_file_cb). `buf`
 * must be large enough for the biggest file the ACU will send (a transfer
 * whose total_size exceeds `cap` is aborted) and must stay valid for as long
 * as it is registered — outliving any in-flight transfer. Pass cb=NULL and
 * buf=NULL to detach, after which the PD NAKs file transfers with 0x03.
 * `user` is threaded into the callback. */
void osdp_pd_set_file_receiver(osdp_pd_t *pd, uint8_t *buf, size_t cap,
                               osdp_pd_file_cb cb, void *user);

/* Bind a STREAMING file-transfer receiver: no reassembly buffer. The core
 * hands each osdp_FILETRANSFER fragment to `cb` as it arrives (read
 * `info->fragment` / `fragment_len` / `offset`; `info->data` is NULL) without
 * accumulating, so RAM usage is independent of the file size — the app
 * persists each fragment (e.g. to flash) itself. There is no total-size
 * ceiling. The offset-monotonicity invariants and the verdict → FtStatusDetail
 * mapping are identical to osdp_pd_set_file_receiver. Pass cb=NULL to detach
 * (the PD then NAKs file transfers with 0x03). Registering either receiver
 * replaces the other. */
void osdp_pd_set_file_stream(osdp_pd_t *pd, osdp_pd_file_cb cb, void *user);

/* ---- Status reporting --------------------------------------------------*/

/* Bind the status providers for osdp_LSTAT / ISTAT / OSTAT / RSTAT (see
 * osdp_pd_status_provider_t). The vtable is copied into the context; the
 * source may be on the stack. Pass p=NULL to detach, after which all four
 * commands go back to `cmd_cb`.
 *
 * Each member is independent: bind only `local` and the PD answers
 * osdp_LSTAT itself while osdp_ISTAT still reaches the application. */
void osdp_pd_set_status_provider(osdp_pd_t *pd,
                                 const osdp_pd_status_provider_t *p,
                                 void *user);

/* ---- Multi-part osdp_MFG ------------------------------------------------
 *
 * osdp_MFG carries vendor-defined data, and that data can exceed one frame.
 * Spec 5.10 provides the standard multi-part format for exactly this, so a
 * fragmented osdp_MFG payload is:
 *
 *     vendor_code[3] || MpSizeTotal,MpOffset,MpFragmentSize[6] || fragment
 *
 * The vendor code stays outside the fragmentation and repeats on every
 * fragment. That is what lets a PD decide whether a transfer is even
 * addressed to it before committing buffer to reassembling it, and it means
 * a PD that does not recognise the vendor can refuse the first fragment
 * rather than the last.
 *
 * **Whether the data is fragmented is the manufacturer's choice, and nothing
 * on the wire distinguishes a 6-byte multi-part header from six bytes of
 * ordinary vendor data.** The spec's Table 27 defines no multi-part fields
 * for osdp_MFG, so this cannot be auto-detected and must not be guessed.
 * Binding a receiver here IS the declaration that this PD's vendor protocol
 * uses the standard format; leave it unbound and osdp_MFG payloads stay
 * opaque and reach the command handler exactly as they do today. */

/* Bind a reassembly buffer and completion callback for multi-part osdp_MFG.
 *
 * `buf` (capacity `cap`) is caller-owned and must be large enough for the
 * biggest vendor message expected — a transfer declaring more than `cap` is
 * refused with osdp_NAK 0x09, which spec 5.10.2 says aborts the sender's
 * sequence. It must stay valid for as long as it is registered.
 *
 * Intermediate fragments are ACKed; `cb` fires once on the last one. An
 * early-termination marker (5.10.2) discards the partial message and ACKs.
 * Any sequencing violation — a gap, a changed total, a continuation with
 * nothing in progress — is answered NAK 0x09 and resets the reassembler so
 * the sender can restart at offset 0.
 *
 * Pass cb=NULL to detach. */
void osdp_pd_set_mfg_receiver(osdp_pd_t *pd, uint8_t *buf, size_t cap,
                              osdp_pd_mfg_cb cb, void *user);

/* ---- PDCAP consistency (advisory) --------------------------------------*/

/* Check an application's osdp_PDCAP records against what this PD can
 * actually honour. Call it once at start-up with the same records the
 * command handler will return for osdp_CAP.
 *
 * PDCAP is a set of promises the ACU acts on — spec §6 has it bound osdp_LED
 * record counts by function code 10, and an ACU told the PD accepts
 * 1440-byte messages will send them. Over-advertising does not fail loudly;
 * the PD drops frames the ACU believes were delivered, and it surfaces later
 * as unexplained retries.
 *
 * Only the records describing the LIBRARY's limits are checked, because they
 * are the only ones whose truth the library knows — how many inputs the
 * device has is the application's business:
 *
 *   fn 9  Communication Security   claims AES128 with no crypto vtable and
 *                                  key bound  -> OSDP_ERR_NOT_SUPPORTED
 *   fn 10 Receive BufferSize       exceeds the stream buffer, or (with SC
 *                                  configured) implies a plaintext larger
 *                                  than the bound rx_plain region
 *                                  -> OSDP_ERR_BUFFER_TOO_SMALL
 *   fn 11 Largest Combined Msg     non-zero while multi-part messages are
 *                                  unimplemented -> OSDP_ERR_NOT_SUPPORTED
 *
 * Returns OSDP_OK when nothing is inconsistent. On any other result
 * `*bad_index` (when non-NULL) receives the index of the first offending
 * record, so the caller can report which one rather than just that
 * something is wrong.
 *
 * Purely advisory: no wire behaviour changes, nothing calls this
 * automatically, and a PD that never calls it does not link it. */
osdp_status_t osdp_pd_check_pdcap(const osdp_pd_t           *pd,
                                  const osdp_pdcap_record_t *records,
                                  size_t                     count,
                                  size_t                    *bad_index);

/* ---- Poll-response events ----------------------------------------------
 *
 * The spec's "sent as a poll response" replies — osdp_RAW (7.10), osdp_FMT
 * (7.11), osdp_KEYPAD (7.12), osdp_MFGREP (7.18) — are generated by physical
 * events, not by a command. The PD holds them until the ACU next polls.
 *
 * Without this queue every consumer reimplements it. With it, the application
 * calls osdp_pd_enqueue_event from wherever the card read or keypress is
 * detected, and the library answers the next osdp_POLL with the head of the
 * queue instead of calling `cmd_cb`. An empty queue falls through to `cmd_cb`
 * exactly as before, so this is opt-in and additive. */

/* Bind caller-owned storage for the event queue. Records are stored
 * length-prefixed; a rough guide is (payload + 3) bytes per queued event.
 * The buffer must stay valid for as long as it is registered. Pass buf=NULL,
 * cap=0 to detach, which also discards anything queued. */
void osdp_pd_set_event_queue(osdp_pd_t *pd, uint8_t *buf, size_t cap);

/* Queue one reply to be sent in answer to the next osdp_POLL.
 *
 * `reply_code` is the osdp_REPLY_* value (OSDP_REPLY_RAW, _KEYPAD, _FMT,
 * _MFGREP); `payload` / `len` are its body, already encoded with the matching
 * osdp::messages builder.
 *
 * Returns OSDP_ERR_BUFFER_TOO_SMALL when the queue is full — the application
 * decides whether to drop the event or retry later, since only it knows
 * whether a missed card read matters. OSDP_ERR_INVALID_ARG for a NULL pd, a
 * payload/length mismatch, or no bound queue.
 *
 * Per spec 7.11/7.12 unreported data is discarded on a communication loss, so
 * the queue is emptied when the PD goes offline; a queued credential is never
 * delivered minutes late to an ACU that has since reconnected. */
osdp_status_t osdp_pd_enqueue_event(osdp_pd_t *pd, uint8_t reply_code,
                                    const uint8_t *payload, size_t len);

/* True while at least one event is waiting for the next poll. */
bool osdp_pd_event_pending(const osdp_pd_t *pd);

/* Discard every queued event. Called automatically on the offline transition;
 * exposed so an application can drop stale events itself (e.g. on a
 * deliberate reconnect). */
void osdp_pd_clear_events(osdp_pd_t *pd);

/* ---- Miscellaneous command hooks ---------------------------------------*/

/* Bind the osdp_ABORT hook (see osdp_pd_abort_cb). Optional: with no hook the
 * PD tears down its own transfer state and ACKs. */
void osdp_pd_set_abort_handler(osdp_pd_t *pd, osdp_pd_abort_cb cb, void *user);

/* Bind the osdp_ACURXSIZE notification (see osdp_pd_acurxsize_cb). Optional;
 * the library stores the value either way. */
void osdp_pd_set_acurxsize_handler(osdp_pd_t *pd, osdp_pd_acurxsize_cb cb,
                                   void *user);

/* The largest reply the ACU has said it can receive, or
 * OSDP_PD_DEFAULT_ACU_RX_SIZE if it has not said. This is the PEER's limit;
 * combine it with osdp_pd_max_reply_payload (this PD's own limit) and honour
 * the smaller of the two. */
uint16_t osdp_pd_acu_rx_size(const osdp_pd_t *pd);

/* Bind the osdp_KEEPACTIVE handler (see osdp_pd_keepactive_cb). Without one
 * the PD NAKs 0x03, since holding a reader active is a physical capability
 * the core cannot fake. */
void osdp_pd_set_keepactive_handler(osdp_pd_t *pd, osdp_pd_keepactive_cb cb,
                                    void *user);

/* ---- Secure Channel configuration --------------------------------------
 *
 * All four setters are independent and opt-in. The PD only accepts
 * SCB-bearing frames once the crypto vtable has been bound AND at
 * least one of (SCBK, SCBK-D) has been set AND the cUID is known. */

/* Bind the crypto HAL the PD will use for AES + RNG during SC. */
void osdp_pd_set_sc_crypto(osdp_pd_t              *pd,
                           const osdp_sc_crypto_t *crypto);

/* Set the per-PD Secure Channel Base Key (SCBK), used when the ACU
 * requests SCS_11 with the SCBK selector (1). */
void osdp_pd_set_sc_scbk(osdp_pd_t       *pd,
                         const uint8_t    scbk[OSDP_SC_KEY_LEN]);

/* Set the default install key (SCBK-D), used when the ACU requests
 * SCS_11 with the SCBK-D selector (0). */
void osdp_pd_set_sc_scbk_d(osdp_pd_t     *pd,
                           const uint8_t  scbk_d[OSDP_SC_KEY_LEN]);

/* Set the PD's cUID — the first 8 bytes of the PDID byte stream
 * (vendor[3] + model + version + serial[0..2]) per spec D.4.3. */
void osdp_pd_set_sc_cuid(osdp_pd_t     *pd,
                         const uint8_t  cuid[OSDP_SC_CUID_LEN]);

/* True iff the SCS_11..14 handshake has completed successfully and
 * the PD is ready to handle SCS_15..18 operational traffic. */
bool osdp_pd_sc_established(const osdp_pd_t *pd);

/* ---- Secure Channel 2 configuration ------------------------------------
 *
 * Opt-in, independent of the SC1 setters. The PD accepts SC2 SCB frames
 * (SCS_21..28) once the SC2 crypto vtable is bound AND the 32-byte SCBK
 * is set AND the cUID is known. SC2 has no install-key mode. */

/* Bind the SC2 crypto HAL (KMAC256 + AES-256-GCM + AES-256 block + RNG). */
void osdp_pd_set_sc2_crypto(osdp_pd_t               *pd,
                            const osdp_sc2_crypto_t *crypto);

/* Set the per-PD 32-byte AES-256 Secure Channel Base Key. */
void osdp_pd_set_sc2_scbk(osdp_pd_t     *pd,
                          const uint8_t  scbk[OSDP_SC2_KEY_LEN]);

/* Set the PD's 8-byte cUID (part of every SC2 message nonce). */
void osdp_pd_set_sc2_cuid(osdp_pd_t     *pd,
                          const uint8_t  cuid[OSDP_SC2_CUID_LEN]);

/* True iff the SCS_21..24 handshake has completed and the PD is ready
 * to handle SCS_25..28 operational traffic. */
bool osdp_pd_sc2_established(const osdp_pd_t *pd);

#ifdef __cplusplus
}
#endif

#endif /* OSDP_PD_H */
