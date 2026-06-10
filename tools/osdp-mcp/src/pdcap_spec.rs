// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Z-bit Systems, LLC

//! OSDP v2.2.2 capability catalog and validation, derived from spec
//! Annex B ("Function Code Definitions List").
//!
//! `osdp_PDCAP` (0x46) reports a list of 3-byte records — function
//! code, compliance level, and "number of objects". Annex B assigns a
//! distinct meaning to every byte of every function code: some
//! compliance levels are enumerated (0..N with named tiers), some are
//! bitmaps, some carry the LSB/MSB of a 16-bit size; likewise the
//! object-count byte is sometimes a count, sometimes a bitmap, and is
//! often required to be zero.
//!
//! This module turns that prose into machine-checkable rules so the
//! `pd_set_capability` tool can (a) reject records the spec forbids and
//! (b) annotate each record with what its bytes mean. It is a host-only
//! helper for the MCP tool surface — nothing in `core/`/`pd/`/`acu/`
//! depends on it.

/// How a single capability byte (compliance level or object count) is
/// interpreted and validated for one function code.
enum FieldRule {
    /// Enumerated values, each with a human meaning. Anything not in
    /// the list is rejected.
    Enum(&'static [(u8, &'static str)]),
    /// Like [`FieldRule::Enum`], but values at or above the second
    /// field are additionally accepted as "private use" (spec leaves
    /// that band to the manufacturer). Values between the highest named
    /// entry and the private threshold are "reserved" and rejected.
    EnumPrivate(&'static [(u8, &'static str)], u8),
    /// Must be exactly 0x00 per spec ("Number of: Must be 0x00", etc.).
    Zero(&'static str),
    /// Any 0..=255 value is legal; the string explains what it encodes
    /// (e.g. a count of inputs, or the LSB of a buffer size).
    Any(&'static str),
    /// Bitmap: only the bits set in `mask` may be 1; the string names
    /// the bits.
    Bitmap(u8, &'static str),
}

impl FieldRule {
    /// Human-readable meaning of `val` under this rule, for the view
    /// returned by `pd_get_pdcap`.
    fn describe(&self, val: u8) -> String {
        match self {
            FieldRule::Enum(items) => items
                .iter()
                .find(|(v, _)| *v == val)
                .map(|(_, m)| (*m).to_string())
                .unwrap_or_else(|| format!("unrecognized value 0x{val:02X}")),
            FieldRule::EnumPrivate(items, priv_from) => items
                .iter()
                .find(|(v, _)| *v == val)
                .map(|(_, m)| (*m).to_string())
                .unwrap_or_else(|| {
                    if val >= *priv_from {
                        format!("private use (0x{val:02X})")
                    } else {
                        format!("reserved / unrecognized (0x{val:02X})")
                    }
                }),
            FieldRule::Zero(note) => {
                if val == 0 {
                    (*note).to_string()
                } else {
                    format!("invalid: {note} (got 0x{val:02X})")
                }
            }
            FieldRule::Any(note) => format!("{note}: {val}"),
            FieldRule::Bitmap(mask, note) => {
                if val & !mask == 0 {
                    format!("{note} (0x{val:02X})")
                } else {
                    format!("invalid bits set: {note} (got 0x{val:02X})")
                }
            }
        }
    }

    /// Check `val` against this rule. `field` / `code` only flavor the
    /// error text.
    fn validate(&self, val: u8, field: &str, code: u8) -> Result<(), String> {
        let ok = match self {
            FieldRule::Enum(items) => items.iter().any(|(v, _)| *v == val),
            FieldRule::EnumPrivate(items, priv_from) => {
                items.iter().any(|(v, _)| *v == val) || val >= *priv_from
            }
            FieldRule::Zero(_) => val == 0,
            FieldRule::Any(_) => true,
            FieldRule::Bitmap(mask, _) => val & !mask == 0,
        };
        if ok {
            return Ok(());
        }
        Err(format!(
            "function code {code} ({}): {field} value 0x{val:02X} is invalid — {}",
            lookup(code).map(|c| c.name).unwrap_or("?"),
            self.allowed_help()
        ))
    }

    /// Short "allowed values are …" clause for error messages.
    fn allowed_help(&self) -> String {
        match self {
            FieldRule::Enum(items) => {
                let list = items
                    .iter()
                    .map(|(v, m)| format!("0x{v:02X} ({m})"))
                    .collect::<Vec<_>>()
                    .join(", ");
                format!("valid values: {list}")
            }
            FieldRule::EnumPrivate(items, priv_from) => {
                let list = items
                    .iter()
                    .map(|(v, m)| format!("0x{v:02X} ({m})"))
                    .collect::<Vec<_>>()
                    .join(", ");
                format!("valid values: {list}, or 0x{priv_from:02X}..0xFF (private use)")
            }
            FieldRule::Zero(note) => format!("must be 0x00 ({note})"),
            FieldRule::Any(note) => format!("any value 0x00..0xFF ({note})"),
            FieldRule::Bitmap(mask, note) => {
                format!("only bits in mask 0x{mask:02X} may be set ({note})")
            }
        }
    }
}

/// One function code's definition: its name, a one-line summary, and
/// the rules for its two data bytes.
pub struct CapSpec {
    pub code: u8,
    pub name: &'static str,
    pub summary: &'static str,
    compliance: FieldRule,
    num_objects: FieldRule,
}

/// The catalog, one entry per function code defined in Annex B
/// (1..=17). Function code 18 ("Extended Capability Display") is
/// referenced by the spec's table of contents but its body is marked
/// "Error! Bookmark not defined." in the source document, so it is
/// deliberately omitted until the definition is available.
static CATALOG: &[CapSpec] = &[
    CapSpec {
        code: 1,
        name: "Contact Status Monitoring",
        summary: "Ability to monitor input contacts (switches).",
        compliance: FieldRule::Enum(&[
            (0, "not supported"),
            (1, "unsupervised, default encoding"),
            (2, "+ configurable NO/NC encoding"),
            (3, "+ supervised monitoring"),
            (4, "+ custom end-of-line settings"),
        ]),
        num_objects: FieldRule::Any("number of inputs"),
    },
    CapSpec {
        code: 2,
        name: "Output Control",
        summary: "Switched outputs (typically relays).",
        compliance: FieldRule::Enum(&[
            (0, "not supported"),
            (1, "direct on/off"),
            (2, "+ configurable inactive drive (fail-safe/secure)"),
            (3, "+ timed commands"),
            (4, "normal/inverted drive and timed operation"),
        ]),
        num_objects: FieldRule::Any("number of outputs"),
    },
    CapSpec {
        code: 3,
        name: "Card Data Format",
        summary: "Form in which card data is presented to the ACU.",
        compliance: FieldRule::Enum(&[
            (0, "not supported"),
            (1, "bit array (<=1024 bits)"),
            (2, "BCD characters (<=256)"),
            (3, "bits or BCD characters"),
        ]),
        num_objects: FieldRule::Zero("must be 0x00"),
    },
    CapSpec {
        code: 4,
        name: "Reader LED Control",
        summary: "Presence and type of reader LEDs.",
        compliance: FieldRule::Enum(&[
            (0, "not supported"),
            (1, "on/off only, colors 0-1"),
            (2, "timed, colors 0-1"),
            (3, "+ red/green, colors 0-2"),
            (4, "+ red/green/amber, colors 0-3"),
            (5, "+ RGB, colors 0-7"),
            (6, "+ RGB, colors 0-255"),
        ]),
        num_objects: FieldRule::Any("number of LEDs per reader"),
    },
    CapSpec {
        code: 5,
        name: "Reader Audible Output",
        summary: "Presence and type of audible annunciator (buzzer).",
        compliance: FieldRule::Enum(&[
            (0, "not supported"),
            (1, "on/off only"),
            (2, "timed commands"),
        ]),
        num_objects: FieldRule::Any("ignored (one audible output per PD)"),
    },
    CapSpec {
        code: 6,
        name: "Reader Text Output",
        summary: "Character display support.",
        compliance: FieldRule::Enum(&[
            (0, "not supported"),
            (1, "1 row x 16 chars"),
            (2, "2 rows x 16 chars"),
            (3, "4 rows x 16 chars"),
        ]),
        num_objects: FieldRule::Any("number of text displays per reader"),
    },
    CapSpec {
        code: 7,
        name: "Time Keeping",
        summary: "Date/time awareness (deprecated).",
        compliance: FieldRule::Enum(&[(0, "no time/date support")]),
        num_objects: FieldRule::Zero("must be 0x00"),
    },
    CapSpec {
        code: 8,
        name: "Check Character Support",
        summary: "CRC-16 support (all PDs support checksum).",
        compliance: FieldRule::Enum(&[(0, "checksum only (no CRC-16)"), (1, "CRC-16 supported")]),
        num_objects: FieldRule::Zero("must be 0x00"),
    },
    CapSpec {
        code: 9,
        name: "Communication Security",
        summary: "Secure Channel / encryption support (Annex D).",
        compliance: FieldRule::Bitmap(0x01, "bit0 = AES128 support"),
        num_objects: FieldRule::Bitmap(0x01, "bit0 = AES128 key-exchange support"),
    },
    CapSpec {
        code: 10,
        name: "Receive Buffer Size",
        summary: "Maximum single message the PD can receive.",
        compliance: FieldRule::Any("LSB of receive buffer size"),
        num_objects: FieldRule::Any("MSB of receive buffer size"),
    },
    CapSpec {
        code: 11,
        name: "Largest Combined Message Size",
        summary: "Maximum multi-part message the PD can handle.",
        compliance: FieldRule::Any("LSB of largest combined message size"),
        num_objects: FieldRule::Any("MSB of largest combined message size"),
    },
    CapSpec {
        code: 12,
        name: "Smart Card Support",
        summary: "Transparent / extended smart card modes.",
        compliance: FieldRule::Bitmap(
            0x03,
            "bit0 = transparent mode (XRW_MODE=1), bit1 = extended packet mode",
        ),
        num_objects: FieldRule::Zero("must be 0x00"),
    },
    CapSpec {
        code: 13,
        name: "Readers",
        summary: "Number of attached downstream credential readers.",
        compliance: FieldRule::Zero("must be 0x00"),
        num_objects: FieldRule::Any("number of attached downstream readers"),
    },
    CapSpec {
        code: 14,
        name: "Biometrics",
        summary: "Biometric input capability.",
        compliance: FieldRule::Enum(&[
            (0, "not supported"),
            (1, "fingerprint, template 1"),
            (2, "fingerprint, template 2"),
            (3, "iris, template 1"),
        ]),
        num_objects: FieldRule::Zero("must be 0x00"),
    },
    CapSpec {
        code: 15,
        name: "Secure PIN Entry",
        summary: "Secure PIN Entry (SPE) for smart cards.",
        compliance: FieldRule::Enum(&[(0, "not supported"), (1, "Secure PIN Entry supported")]),
        num_objects: FieldRule::Zero("must be 0x00"),
    },
    CapSpec {
        code: 16,
        name: "OSDP Version",
        summary: "Version of OSDP this PD supports.",
        compliance: FieldRule::EnumPrivate(
            &[
                (0, "unspecified / pre-IEC 60839-11-5"),
                (1, "IEC 60839-11-5"),
                (2, "SIA OSDP 2.2"),
                (3, "SIA OSDP 2.2.1"),
                (4, "SIA OSDP 2.2.2"),
            ],
            0x80,
        ),
        num_objects: FieldRule::Zero("must be 0x00"),
    },
    CapSpec {
        code: 17,
        name: "Secure PD Biometrics Match Support",
        // Spec B.18 body is not present in the extracted reference text,
        // so both bytes are accepted permissively rather than guessing
        // at the enumeration.
        summary: "Secure PD biometrics match support (spec B.18).",
        compliance: FieldRule::Any("compliance level (see spec B.18)"),
        num_objects: FieldRule::Any("number of objects (see spec B.18)"),
    },
];

/// Look up a function code's definition, if it is one this catalog
/// knows about.
pub fn lookup(code: u8) -> Option<&'static CapSpec> {
    CATALOG.iter().find(|c| c.code == code)
}

/// All known function codes, ascending — used to build a helpful error
/// when an unknown code is supplied.
fn known_codes() -> String {
    CATALOG
        .iter()
        .map(|c| c.code.to_string())
        .collect::<Vec<_>>()
        .join(", ")
}

/// Validate one capability record against Annex B. Returns `Ok(())` if
/// the record is well-formed, or a human-readable error naming the
/// offending field and its allowed values.
pub fn validate_record(
    function_code: u8,
    compliance_level: u8,
    num_objects: u8,
) -> Result<(), String> {
    let spec = lookup(function_code).ok_or_else(|| {
        format!(
            "unknown function code {function_code}; OSDP v2.2.2 defines codes {}",
            known_codes()
        )
    })?;
    spec.compliance
        .validate(compliance_level, "compliance level", function_code)?;
    spec.num_objects
        .validate(num_objects, "number of objects", function_code)?;
    Ok(())
}

/// Human-readable interpretation of a record's three bytes:
/// `(function name, compliance meaning, num-objects meaning)`. For an
/// unknown function code the name is `"unknown"` and the byte meanings
/// fall back to a generic description.
pub fn interpret(
    function_code: u8,
    compliance_level: u8,
    num_objects: u8,
) -> (String, String, String) {
    match lookup(function_code) {
        Some(spec) => (
            spec.name.to_string(),
            spec.compliance.describe(compliance_level),
            spec.num_objects.describe(num_objects),
        ),
        None => (
            "unknown function code".to_string(),
            format!("0x{compliance_level:02X}"),
            format!("0x{num_objects:02X}"),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shipped_default_pdcap_is_spec_conformant() {
        // pd_reset_pdcap restores this set wholesale, and the get-view
        // annotates every byte — so the default must itself pass the
        // same validation pd_set_capability enforces, or the tool would
        // contradict itself.
        for r in crate::handler::default_pdcap().records {
            validate_record(r.function_code, r.compliance_level, r.num_objects).unwrap_or_else(
                |e| panic!("default PDCAP record {r:?} is not spec-conformant: {e}"),
            );
        }
    }

    #[test]
    fn enum_rejects_out_of_range_compliance() {
        // FC4 (LED) tops out at compliance 6.
        assert!(validate_record(4, 7, 1).is_err());
        assert!(validate_record(4, 6, 1).is_ok());
    }

    #[test]
    fn zero_only_num_objects_enforced() {
        // FC3 (Card Data Format) requires num_objects == 0.
        assert!(validate_record(3, 1, 1).is_err());
        assert!(validate_record(3, 1, 0).is_ok());
    }

    #[test]
    fn bitmap_rejects_reserved_bits() {
        // FC9 (Comm Security) compliance is a 1-bit map.
        assert!(validate_record(9, 0x02, 0x01).is_err());
        assert!(validate_record(9, 0x01, 0x01).is_ok());
    }

    #[test]
    fn osdp_version_allows_private_band_but_not_reserved() {
        assert!(validate_record(16, 0x04, 0).is_ok()); // 2.2.2
        assert!(validate_record(16, 0x05, 0).is_err()); // reserved
        assert!(validate_record(16, 0x90, 0).is_ok()); // private use
    }

    #[test]
    fn unknown_function_code_rejected() {
        assert!(validate_record(0, 0, 0).is_err());
        assert!(validate_record(99, 0, 0).is_err());
    }

    #[test]
    fn any_field_accepts_anything() {
        // FC10 buffer size: both bytes are free-form.
        assert!(validate_record(10, 0x00, 0x02).is_ok());
        assert!(validate_record(10, 0xFF, 0xFF).is_ok());
    }

    #[test]
    fn interpret_names_known_code() {
        let (name, _c, _n) = interpret(4, 4, 1);
        assert_eq!(name, "Reader LED Control");
    }
}
