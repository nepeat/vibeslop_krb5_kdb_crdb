//! Wire format for principal entries stored in CockroachDB.
//!
//! Design note: libkdb5 does NOT export a public entry codec — the in-tree
//! backends each roll their own (db2 has kdb_xdr.c, klmdb has marshal.c).
//! kurbu5 likewise doesn't expose one, so we define our own *versioned*
//! encoding here. postcard gives us a compact, deterministic-enough binary
//! layout; the explicit `WIRE_VERSION` byte is what actually protects us
//! during schema evolution — bump it and keep decoding old versions forever.
//!
//! Everything krb5 cares about round-trips through this struct:
//! base fields, TL-data (which transports mod-princ, last-pwd-change,
//! string attrs, etc.), and the encrypted key data. Key material is already
//! encrypted under the master key before it reaches put_principal, so the
//! database only ever sees ciphertext — same trust model as BDB/LMDB files.

use kurbu5_kdb_rs::{
    KdbContext, KdbError, KeyDataBuilder, KeyDataOwned, PolicyEntry,
    PrincipalAttributes, PrincipalEntry, PrincipalEntryRef, Timestamp,
    TlDataBuilder,
};
use serde::{Deserialize, Serialize};

pub const WIRE_VERSION: u8 = 1;

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct WireKey {
    /// krb5_key_data.key_data_ver == 2 means a salt slot is present (even
    /// a zero-length one). Read via KeyDataRef::has_salt (patched kurbu5).
    pub has_salt: bool,
    pub kvno: u16,
    pub enctype: i16,
    pub salttype: i16,
    pub key_bytes: Vec<u8>,
    pub salt_bytes: Vec<u8>,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct WireEntry {
    pub version: u8,
    /// Canonical unparsed principal name, INCLUDING realm. This is the
    /// authoritative name; the SQL primary key is derived from it. Rename
    /// rewrites this field (see lib.rs::rename_principal).
    pub princ_name: String,
    pub attributes: u32,
    pub max_life: i32,
    pub max_renewable_life: i32,
    pub expiration: i32,
    pub pw_expiration: i32,
    /// last_success / last_failed / fail_auth_count round-trip for dump
    /// fidelity, but with disable_lockout + disable_last_success set (and
    /// you MUST set them — see README) the KDC never writes them back.
    pub last_success: i32,
    pub last_failed: i32,
    pub fail_auth_count: u32,
    pub len: u16,
    /// (tl_data_type, contents) pairs, order preserved.
    pub tl_data: Vec<(u16, Vec<u8>)>,
    pub keys: Vec<WireKey>,
}

/// Serialize a zero-copy entry view into the wire blob.
pub fn encode_entry(
    ctx: &KdbContext<'_>,
    e: PrincipalEntryRef<'_>,
) -> Result<Vec<u8>, KdbError> {
    let wire = WireEntry {
        version: WIRE_VERSION,
        princ_name: ctx.unparse_principal(e.princ())?,
        attributes: e.attributes().bits(),
        max_life: e.max_life(),
        max_renewable_life: e.max_renewable_life(),
        expiration: i32::from(e.expiration()),
        pw_expiration: i32::from(e.pw_expiration()),
        last_success: i32::from(e.last_success()),
        last_failed: i32::from(e.last_failed()),
        fail_auth_count: e.fail_auth_count(),
        len: e.len(),
        tl_data: e.tl_data().map(|t| (t.ty, t.data.to_vec())).collect(),
        keys: e
            .key_data()
            .iter()
            .map(|k| WireKey {
                has_salt: k.has_salt(),
                kvno: k.kvno(),
                enctype: k.enctype(),
                salttype: k.salttype(),
                key_bytes: k.key_bytes().to_vec(),
                salt_bytes: k.salt_bytes().to_vec(),
            })
            .collect(),
    };
    postcard::to_allocvec(&wire).map_err(|_| KdbError::OutOfMemory)
}

pub fn decode_wire(blob: &[u8]) -> Result<WireEntry, KdbError> {
    let wire: WireEntry = postcard::from_bytes(blob)
        .map_err(|_| KdbError::Custom(libc::EINVAL))?;
    if wire.version != WIRE_VERSION {
        // Future versions: match on wire.version and up-convert here.
        return Err(KdbError::Custom(libc::EINVAL));
    }
    Ok(wire)
}

/// Rehydrate a wire blob into an owned PrincipalEntry for libkdb5.
pub fn decode_entry(
    ctx: &KdbContext<'_>,
    blob: &[u8],
) -> Result<PrincipalEntry, KdbError> {
    let wire = decode_wire(blob)?;

    let mut entry = PrincipalEntry::new();
    entry
        .set_princ(ctx, ctx.parse_principal(&wire.princ_name)?)
        .set_attributes(PrincipalAttributes::from_bits_truncate(
            wire.attributes,
        ))
        .set_max_life(wire.max_life)
        .set_max_renewable_life(wire.max_renewable_life)
        .set_expiration(Timestamp::from(wire.expiration))
        .set_pw_expiration(Timestamp::from(wire.pw_expiration))
        .set_last_success(Timestamp::from(wire.last_success))
        .set_last_failed(Timestamp::from(wire.last_failed))
        .set_fail_auth_count(wire.fail_auth_count)
        .set_len(wire.len);

    if !wire.tl_data.is_empty() {
        let mut tlb = TlDataBuilder::new();
        for (ty, data) in wire.tl_data {
            tlb.push(ty, data);
        }
        entry.set_tl_data(tlb.build());
    }

    if !wire.keys.is_empty() {
        let mut kb = KeyDataBuilder::new();
        for k in wire.keys {
            kb.push(KeyDataOwned {
                has_salt: k.has_salt,
                kvno: k.kvno,
                enctype: k.enctype,
                salttype: k.salttype,
                key_bytes: k.key_bytes,
                salt_bytes: k.salt_bytes,
            });
        }
        entry.set_key_data(kb);
    }

    Ok(entry)
}

// ---------------------------------------------------------------------------
// Policies
// ---------------------------------------------------------------------------

/// Policy wire version 2 adds tl_data at the end. postcard is positional,
/// so v1 blobs (written before the kurbu5 tl_data getter existed) need
/// their own decode shape; the leading version byte dispatches.
pub const POLICY_WIRE_VERSION: u8 = 2;

#[derive(Serialize, Deserialize)]
pub struct WirePolicy {
    pub version: u8,
    pub name: String,
    pub pw_min_life: u32,
    pub pw_max_life: u32,
    pub pw_min_length: u32,
    pub pw_min_classes: u32,
    pub pw_history_num: u32,
    pub pw_max_fail: u32,
    pub pw_failcnt_interval: u32,
    pub pw_lockout_duration: u32,
    pub attributes: u32,
    pub max_life: u32,
    pub max_renewable_life: u32,
    pub allowed_keysalts: Option<String>,
    /// (tl_data_type, contents) pairs, order preserved. v2+.
    pub tl_data: Vec<(u16, Vec<u8>)>,
}

/// v1 layout: identical minus the trailing tl_data.
#[derive(Deserialize)]
struct WirePolicyV1 {
    pub version: u8,
    pub name: String,
    pub pw_min_life: u32,
    pub pw_max_life: u32,
    pub pw_min_length: u32,
    pub pw_min_classes: u32,
    pub pw_history_num: u32,
    pub pw_max_fail: u32,
    pub pw_failcnt_interval: u32,
    pub pw_lockout_duration: u32,
    pub attributes: u32,
    pub max_life: u32,
    pub max_renewable_life: u32,
    pub allowed_keysalts: Option<String>,
}

pub fn encode_policy(p: &PolicyEntry) -> Result<Vec<u8>, KdbError> {
    let wire = WirePolicy {
        version: POLICY_WIRE_VERSION,
        name: p.name.clone(),
        pw_min_life: p.pw_min_life,
        pw_max_life: p.pw_max_life,
        pw_min_length: p.pw_min_length,
        pw_min_classes: p.pw_min_classes,
        pw_history_num: p.pw_history_num,
        pw_max_fail: p.pw_max_fail,
        pw_failcnt_interval: p.pw_failcnt_interval,
        pw_lockout_duration: p.pw_lockout_duration,
        attributes: p.attributes,
        max_life: p.max_life,
        max_renewable_life: p.max_renewable_life,
        allowed_keysalts: p.allowed_keysalts.clone(),
        tl_data: p.tl_data().map(|(ty, d)| (ty, d.to_vec())).collect(),
    };
    postcard::to_allocvec(&wire).map_err(|_| KdbError::OutOfMemory)
}

pub fn decode_policy(blob: &[u8]) -> Result<PolicyEntry, KdbError> {
    // First byte is the version (u8 encodes as one byte in postcard).
    let w: WirePolicy = match blob.first() {
        Some(&POLICY_WIRE_VERSION) => postcard::from_bytes(blob)
            .map_err(|_| KdbError::Custom(libc::EINVAL))?,
        Some(&1) => {
            let v1: WirePolicyV1 = postcard::from_bytes(blob)
                .map_err(|_| KdbError::Custom(libc::EINVAL))?;
            WirePolicy {
                version: v1.version,
                name: v1.name,
                pw_min_life: v1.pw_min_life,
                pw_max_life: v1.pw_max_life,
                pw_min_length: v1.pw_min_length,
                pw_min_classes: v1.pw_min_classes,
                pw_history_num: v1.pw_history_num,
                pw_max_fail: v1.pw_max_fail,
                pw_failcnt_interval: v1.pw_failcnt_interval,
                pw_lockout_duration: v1.pw_lockout_duration,
                attributes: v1.attributes,
                max_life: v1.max_life,
                max_renewable_life: v1.max_renewable_life,
                allowed_keysalts: v1.allowed_keysalts,
                tl_data: vec![],
            }
        }
        _ => return Err(KdbError::Custom(libc::EINVAL)),
    };
    let mut p = PolicyEntry::new(w.name);
    p.pw_min_life = w.pw_min_life;
    p.pw_max_life = w.pw_max_life;
    p.pw_min_length = w.pw_min_length;
    p.pw_min_classes = w.pw_min_classes;
    p.pw_history_num = w.pw_history_num;
    p.pw_max_fail = w.pw_max_fail;
    p.pw_failcnt_interval = w.pw_failcnt_interval;
    p.pw_lockout_duration = w.pw_lockout_duration;
    p.attributes = w.attributes;
    p.max_life = w.max_life;
    p.max_renewable_life = w.max_renewable_life;
    p.allowed_keysalts = w.allowed_keysalts;
    for (ty, data) in w.tl_data {
        p.add_tl_data(ty, data);
    }
    Ok(p)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// A realistic entry as the KDC would hand it to put_principal: two key
/// generations (kvno 2 current, kvno 1 retained), aes256/aes128, one salted
/// key, mod-princ TL-data. Key bytes are stand-in ciphertext — real ones are
/// already encrypted under the master key by the time they reach the DAL.
#[cfg(test)]
pub(crate) fn sample_wire_entry(princ_name: &str) -> WireEntry {
    WireEntry {
        version: WIRE_VERSION,
        princ_name: princ_name.to_owned(),
        attributes: 0x0000_0080, // REQUIRES_PRE_AUTH
        max_life: 86_400,
        max_renewable_life: 604_800,
        expiration: 0,
        pw_expiration: 1_900_000_000,
        last_success: 0,
        last_failed: 0,
        fail_auth_count: 0,
        len: 0,
        tl_data: vec![(2, vec![0xde, 0xad, 0xbe, 0xef, 0x00])], // KRB5_TL_MOD_PRINC-ish
        keys: vec![
            WireKey {
                has_salt: false,
                kvno: 2,
                enctype: 18, // aes256-cts-hmac-sha1-96
                salttype: 0,
                key_bytes: (0u8..=35).collect(), // 2-byte len prefix + 34 ct bytes, opaque to us
                salt_bytes: vec![],
            },
            WireKey {
                has_salt: true,
                kvno: 2,
                enctype: 17, // aes128-cts-hmac-sha1-96
                salttype: 4, // KRB5_KDB_SALTTYPE_SPECIAL
                key_bytes: (100u8..=119).collect(),
                salt_bytes: b"EXAMPLE.COMextra-salt".to_vec(),
            },
            WireKey {
                has_salt: false,
                kvno: 1,
                enctype: 18,
                salttype: 0,
                key_bytes: (200u8..=235).collect(),
                salt_bytes: vec![],
            },
        ],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wire_entry_roundtrip() {
        let entry = sample_wire_entry("alice@EXAMPLE.COM");
        let blob = postcard::to_allocvec(&entry).unwrap();
        let back = decode_wire(&blob).unwrap();
        assert_eq!(entry, back);
    }

    #[test]
    fn wire_entry_rejects_unknown_version() {
        let mut entry = sample_wire_entry("alice@EXAMPLE.COM");
        entry.version = WIRE_VERSION + 1;
        let blob = postcard::to_allocvec(&entry).unwrap();
        assert!(decode_wire(&blob).is_err());
    }

    #[test]
    fn wire_entry_rejects_garbage() {
        assert!(decode_wire(&[0xff; 64]).is_err());
    }

    #[test]
    fn policy_tl_data_roundtrips() {
        let mut p = PolicyEntry::new("stress-pol");
        p.pw_min_length = 12;
        p.add_tl_data(7, vec![1, 2, 3]);
        p.add_tl_data(9, vec![]);
        let blob = encode_policy(&p).unwrap();
        let back = decode_policy(&blob).unwrap();
        assert_eq!(back.pw_min_length, 12);
        let tl: Vec<_> =
            back.tl_data().map(|(ty, d)| (ty, d.to_vec())).collect();
        assert_eq!(tl, vec![(7, vec![1, 2, 3]), (9, vec![])]);
    }

    #[test]
    fn policy_v1_blob_still_decodes() {
        // A v1 blob is exactly the v2 layout minus the trailing tl_data
        // vec; postcard appends fields positionally, so encoding v2 with
        // empty tl_data and stripping the trailing zero-length marker
        // reproduces v1 bytes.
        let p = PolicyEntry::new("legacy");
        let mut blob = encode_policy(&p).unwrap();
        assert_eq!(*blob.last().unwrap(), 0); // empty tl_data vec length
        blob.pop();
        blob[0] = 1; // version byte back to v1
        let back = decode_policy(&blob).unwrap();
        assert_eq!(back.name, "legacy");
        assert_eq!(back.tl_data().count(), 0);
    }
}
