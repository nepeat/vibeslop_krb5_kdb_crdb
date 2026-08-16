//! kdb-crdb — MIT Kerberos KDB backend on CockroachDB GLOBAL tables.
//!
//! Goal: a strongly consistent, multi-region principal database. Every
//! AS-REQ/TGS-REQ lookup is a non-stale read served by the KDC's local
//! region (GLOBAL table read path); kadmin writes pay cross-region commit
//! latency, which is fine because writes are rare *provided* lockout and
//! last-auth tracking are disabled — see the kdc.conf in the README. Do
//! not skip that part: with lockout enabled, every authentication becomes
//! a cross-region consensus write.
//!
//! Built on kurbu5 (https://codeberg.org/abbra/kurbu5), targeting KDB DAL
//! major version 9 (krb5 >= 1.21) via kurbu5 0.1.2. Only glue inside
//! kurbu5 is unsafe; this crate is 100% safe Rust.
//!
//! What this deliberately does NOT do:
//! - lock()/unlock(): left as default no-ops. BDB needs whole-DB locks;
//!   we rely on per-statement/txn atomicity instead, same as klmdb.
//! - fetch/store master key: defaults to libkdb5's stash-file handling.
//!   The stash stays local to each KDC; the DB only holds ciphertext.
//! - decrypt/encrypt_key_data: defaults (krb5_dbe_def_*) are correct.

mod marshal;
mod offline;
mod store;

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use kurbu5_kdb_rs::{
    kdb_plugin, IterFlags, KdbContext, KdbError, KdbModule, LookupFlags,
    OpenMode, PolicyEntry, PrincipalEntry, PrincipalEntryRef, PrincipalRef,
    ServerType,
};
use offline::OfflineCache;
use store::{Store, StoreOpts};

/// Operational logging. The plugin has no logging channel of its own —
/// libkdb5 gives modules no logger and krb5_klog is private to the
/// daemons — so notices go to stderr with a fixed prefix, which krb5kdc
/// and kadmind inherit (systemd/quadlet/k8s capture it as the unit's
/// log). Deliberately NOT `eprintln!`: that panics if stderr is closed,
/// and this crate must never unwind across the C vtable boundary.
///
/// Reserved for state changes an operator must be able to see after the
/// fact (connect retries, running without a database, cache trouble) —
/// never per-request chatter.
pub(crate) fn warn(msg: &str) {
    use std::io::Write;
    let _ = writeln!(std::io::stderr(), "kdb_crdb: {msg}");
}

/// Per-process TTL cache of principal wire blobs, KDC role only.
///
/// Every TGS-REQ does three lookups (krbtgt, service, client) and the hot
/// set is tiny: krbtgt on every request, popular services fleet-wide, and
/// each client right after its own AS-REQ. The DB round-trip — not CPU —
/// bounds KDC throughput, so this is the single biggest QPS lever.
///
/// Staleness contract: key changes / SQL edits become visible to a KDC
/// worker at most `ttl` late (local writes through this process
/// invalidate immediately; kadmind and kdb5_util never cache at all).
/// Lockout/last-auth are already required to be off for this backend, so
/// no security counters ride on read freshness. Misses are never cached.
struct EntryCache {
    ttl: Duration,
    map: Mutex<HashMap<String, (Instant, Vec<u8>)>>,
}

/// Coarse memory bound: wipe and restart rather than tracking LRU order.
/// At KDC request rates the hot set re-fills within a second.
const CACHE_MAX_ENTRIES: usize = 65_536;

impl EntryCache {
    fn get(&self, name: &str) -> Option<Vec<u8>> {
        let map = self.map.lock().ok()?;
        let (stamp, blob) = map.get(name)?;
        (stamp.elapsed() < self.ttl).then(|| blob.clone())
    }

    fn put(&self, name: &str, blob: &[u8]) {
        if let Ok(mut map) = self.map.lock() {
            if map.len() >= CACHE_MAX_ENTRIES {
                map.clear();
            }
            map.insert(name.to_owned(), (Instant::now(), blob.to_vec()));
        }
    }

    fn invalidate(&self, name: &str) {
        if let Ok(mut map) = self.map.lock() {
            map.remove(name);
        }
    }
}

pub struct CrdbKdb {
    store: Store,
    cache: Option<EntryCache>,
}

/// Realm of an unparsed principal name: everything after the last
/// unescaped '@'. krb5 quotes specials with a backslash and a literal
/// backslash as "\\", so scan FORWARD tracking escape state — a reverse
/// scan misreads "comp\\@R" (component ending in a literal backslash) as
/// having an escaped separator.
fn realm_of(name: &str) -> &str {
    let bytes = name.as_bytes();
    let mut at = None;
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'\\' => i += 2, // escape consumes the next char
            b'@' => {
                at = Some(i);
                i += 1;
            }
            _ => i += 1,
        }
    }
    // '@' is ASCII, so at+1 is always a char boundary.
    at.map_or("", |i| &name[i + 1..])
}

/// Config lookup order for every knob: `-x key=value` on kadmin/kdb5_util
/// first, then the `[dbmodules]` profile key.
fn conf(
    ctx: &KdbContext<'_>,
    section: &str,
    db_args: &[&str],
    key: &str,
) -> Option<String> {
    let prefix = format!("{key}=");
    db_args
        .iter()
        .find_map(|a| a.strip_prefix(&prefix).map(str::to_owned))
        .or_else(|| ctx.db_module_string(section, key))
}

fn conf_ms(
    ctx: &KdbContext<'_>,
    section: &str,
    db_args: &[&str],
    key: &str,
    default: u64,
) -> Result<u64, KdbError> {
    conf(ctx, section, db_args, key).map_or(Ok(default), |s| {
        s.parse::<u64>().map_err(|_| KdbError::Custom(libc::EINVAL))
    })
}

impl CrdbKdb {
    fn canonical_name(
        &self,
        ctx: &KdbContext<'_>,
        princ: PrincipalRef<'_>,
    ) -> Result<String, KdbError> {
        // Full unparse (with realm) so one cluster can serve several realms
        // out of a single principals table if you ever want that.
        ctx.unparse_principal(princ)
    }
}

impl KdbModule for CrdbKdb {
    fn open(
        ctx: &KdbContext<'_>,
        conf_section: &str,
        db_args: &[&str],
        mode: OpenMode,
    ) -> Result<Self, KdbError> {
        // kdb5_util load (without -update) opens a "temporary" database,
        // streams the dump into it, then atomically swaps it live via
        // promote_db. There is no side database here: accepting the arg
        // would write the dump straight into the live GLOBAL tables and
        // only fail at the end. Fail fast instead; restore with
        // `kdb5_util load -update` or CRDB-native BACKUP/RESTORE.
        if db_args
            .iter()
            .any(|a| *a == "temporary" || a.starts_with("temporary="))
        {
            return Err(KdbError::Custom(libc::EINVAL));
        }

        // Resolution order: -x dburl=... on kdb5_util/kadmin, then the
        // dbmodules profile key, then the environment (handy in dev).
        let uri = db_args
            .iter()
            .find_map(|a| a.strip_prefix("dburl=").map(str::to_owned))
            .or_else(|| ctx.db_module_string(conf_section, "connection_uri"))
            .or_else(|| std::env::var("KDB_CRDB_URI").ok())
            .ok_or(KdbError::Custom(libc::EINVAL))?;

        let is_kdc = matches!(mode.server, ServerType::Kdc);

        // entry_cache_ms: TTL for the KDC-role read cache (see EntryCache).
        // 0 disables. Only the KDC ever caches: kadmind/kdb5_util do
        // read-modify-write cycles and must always see fresh rows.
        let cache_ms =
            conf_ms(ctx, conf_section, db_args, "entry_cache_ms", 1000)?;
        let cache = (cache_ms > 0 && is_kdc).then(|| EntryCache {
            ttl: Duration::from_millis(cache_ms),
            map: Mutex::new(HashMap::new()),
        });

        // stale_reads_ms: max staleness for the degraded-read fallback
        // (0 = off, the default). KDC role only: kadmind/kdb5_util do
        // read-modify-write and must never act on stale rows; the KDC's
        // auth path is read-only, so bounded staleness there just means
        // "keep issuing tickets through a DB quorum outage".
        let stale_ms =
            conf_ms(ctx, conf_section, db_args, "stale_reads_ms", 0)?;
        let stale_ms = if is_kdc { stale_ms } else { 0 };

        // startup_retry_ms: budget for retrying the initial connection
        // (0 = fail fast, the historic behaviour). Every role gets this:
        // a kadmind or kdb5_util that starts a few seconds before the DB
        // is reachable should wait, not die.
        let startup_retry_ms =
            conf_ms(ctx, conf_section, db_args, "startup_retry_ms", 0)?;

        // offline_cache_path + offline_cache_max_age_ms: last-known-good
        // entry cache for surviving a cold start during a DB outage.
        // Both or neither — a path without an age bound would serve
        // unbounded-stale principal data, and an age bound without a path
        // is a typo the operator wants to hear about.
        let offline_path = conf(ctx, conf_section, db_args, "offline_cache_path");
        let offline_age =
            conf(ctx, conf_section, db_args, "offline_cache_max_age_ms")
                .map(|s| {
                    s.parse::<u64>().map_err(|_| KdbError::Custom(libc::EINVAL))
                })
                .transpose()?;
        let offline = match (offline_path, offline_age) {
            (None, None) => None,
            // A zero max age can never serve anything: also a config error.
            (Some(_), Some(0)) | (Some(_), None) | (None, Some(_)) => {
                return Err(KdbError::Custom(libc::EINVAL))
            }
            // KDC role ONLY. kadmind/kdb5_util read-modify-write and make
            // authorization decisions; they must never see a blob that
            // did not come from a live, quorate database.
            (Some(path), Some(age_ms)) => is_kdc.then(|| {
                OfflineCache::open(&path, Duration::from_millis(age_ms))
            }),
        };

        Ok(CrdbKdb {
            store: Store::connect_opts(
                &uri,
                StoreOpts { stale_ms, startup_retry_ms, offline },
            )?,
            cache,
        })
    }

    // -- database lifecycle --------------------------------------------------

    // `kdb5_util create` calls krb5_db_create, which needs this vtable slot;
    // without it realm bootstrap dies with KRB5_PLUGIN_OP_NOTSUPP. There is
    // no DDL to run (schema.sql is the operator's job), so "create" is just
    // open + install: the contract (see kurbu5's KdbModule docs, klmdb's
    // create) is to leave db_context set so the following puts work without
    // a separate krb5_db_open.
    const SUPPORTS_CREATE: bool = true;

    fn create(
        ctx: &KdbContext<'_>,
        conf_section: &str,
        db_args: &[&str],
    ) -> Result<(), KdbError> {
        use kurbu5_kdb_rs::{AccessMode, ServerType};
        let module = Self::open(
            ctx,
            conf_section,
            db_args,
            OpenMode {
                access: AccessMode::ReadWrite,
                server: ServerType::Admin,
            },
        )?;
        ctx.set_module(module)
    }

    // The plugin never issues DDL and never mass-deletes shared state: the
    // GLOBAL tables may be serving KDCs in every region, so `kdb5_util
    // destroy` from one admin box must not vaporize the realm. No-op:
    // removing data is the operator's job, via SQL (schema.sql's domain).
    const SUPPORTS_DESTROY: bool = true;

    fn destroy(
        _ctx: &KdbContext<'_>,
        _conf_section: &str,
        _db_args: &[&str],
    ) -> Result<(), KdbError> {
        Ok(())
    }

    // Unreachable in practice: promote_db only runs at the end of a plain
    // `kdb5_util load`, whose "temporary" open is already rejected above.
    // No-op so nothing ever unwinds or errors mid-swap if some other code
    // path calls it.
    const SUPPORTS_PROMOTE_DB: bool = true;

    fn promote_db(
        _ctx: &KdbContext<'_>,
        _conf_section: &str,
        _db_args: &[&str],
    ) -> Result<(), KdbError> {
        Ok(())
    }

    // -- principal CRUD ------------------------------------------------------

    fn get_principal(
        &self,
        ctx: &KdbContext<'_>,
        search_for: PrincipalRef<'_>,
        flags: LookupFlags,
    ) -> Result<Option<PrincipalEntry>, KdbError> {
        let name = self.canonical_name(ctx, search_for)?;
        if let Some(cache) = &self.cache {
            if let Some(blob) = cache.get(&name) {
                return Ok(Some(marshal::decode_entry(ctx, &blob)?));
            }
        }
        // `offline` tracks "the database was unreachable and the offline
        // cache could not answer". While that is true, a miss anywhere in
        // the chain below must NOT become Ok(None): the cache is partial
        // by construction, and a false "principal does not exist" is a
        // much worse answer than "service unavailable, try later".
        let mut offline = false;
        match self.store.get_principal(&name) {
            Ok(Some(blob)) => {
                if let Some(cache) = &self.cache {
                    cache.put(&name, &blob);
                }
                return Ok(Some(marshal::decode_entry(ctx, &blob)?));
            }
            Ok(None) => {}
            // Still worth trying the alias table: the offline cache keeps
            // alias rows too, so an aliased principal stays resolvable.
            Err(e) if store::is_unavailable(&e) => offline = true,
            Err(e) => return Err(e),
        }

        // Miss: try the operator-managed aliases table. Per the kdb.h
        // contract we may always return an in-realm alias (the entry's
        // princ field carries the canonical name; the KDC decides from the
        // request whether canonicalization is acceptable). An alias whose
        // canonical name lives in ANOTHER realm is a referral, and those
        // may only be surfaced when the KDC set KRB5_KDB_FLAG_REFERRAL_OK.
        let miss = |offline: bool| {
            if offline { Err(store::offline_unavailable()) } else { Ok(None) }
        };
        let canonical = match self.store.get_alias(&name) {
            Ok(Some(c)) => c,
            Ok(None) => return miss(offline),
            Err(e) if store::is_unavailable(&e) => return miss(true),
            Err(e) => return Err(e),
        };
        if realm_of(&canonical) != realm_of(&name)
            && !flags.contains(LookupFlags::REFERRAL_OK)
        {
            return Ok(None);
        }
        match self.store.get_principal(&canonical) {
            Ok(Some(blob)) => Ok(Some(marshal::decode_entry(ctx, &blob)?)),
            // Dangling alias row = the principal does not exist.
            Ok(None) => miss(offline),
            Err(e) => Err(e),
        }
    }

    fn put_principal(
        &self,
        ctx: &KdbContext<'_>,
        entry: PrincipalEntryRef<'_>,
        _db_args: &[&str],
    ) -> Result<(), KdbError> {
        let name = self.canonical_name(ctx, entry.princ())?;
        let blob = marshal::encode_entry(ctx, entry)?;
        if let Some(cache) = &self.cache {
            cache.invalidate(&name);
        }
        self.store.put_principal(&name, &blob)
    }

    fn delete_principal(
        &self,
        ctx: &KdbContext<'_>,
        search_for: PrincipalRef<'_>,
    ) -> Result<(), KdbError> {
        let name = self.canonical_name(ctx, search_for)?;
        if let Some(cache) = &self.cache {
            cache.invalidate(&name);
        }
        self.store.delete_principal(&name)
    }

    fn rename_principal(
        &self,
        ctx: &KdbContext<'_>,
        source: PrincipalRef<'_>,
        target: PrincipalRef<'_>,
    ) -> Result<(), KdbError> {
        let old = self.canonical_name(ctx, source)?;
        let new = self.canonical_name(ctx, target)?;
        // Old name's raw fields, for pinning name-derived salts below.
        let old_realm = source.realm().to_vec();
        let old_comps: Vec<Vec<u8>> =
            source.components().map(<[u8]>::to_vec).collect();

        // Single serializable txn: no observer in any region can see both
        // names or neither. The blob embeds the canonical name; the store
        // reads it INSIDE the txn and this closure rewrites it, so a cpw
        // racing the rename retries instead of being reverted. Default
        // (NORMAL) salts derive from the principal name, so they must be
        // made explicit under the OLD name or passwords break — same as
        // krb5_db_def_rename_principal's specialize_salt step. (kadmind
        // refreshes KRB5_TL_MOD_PRINC on its own next write.)
        if let Some(cache) = &self.cache {
            cache.invalidate(&old);
            cache.invalidate(&new);
        }
        self.store.rename_principal(&old, &new, |blob| {
            let mut wire = marshal::decode_wire(blob)?;
            wire.princ_name = new.clone();
            let comps: Vec<&[u8]> =
                old_comps.iter().map(Vec::as_slice).collect();
            marshal::specialize_salts(&mut wire, &old_realm, &comps)?;
            postcard::to_allocvec(&wire).map_err(|_| KdbError::OutOfMemory)
        })
    }

    fn iterate_principals(
        &self,
        ctx: &KdbContext<'_>,
        _match_entry: Option<&str>,
        _flags: IterFlags,
        callback: &mut dyn FnMut(
            PrincipalEntryRef<'_>,
        ) -> Result<(), KdbError>,
    ) -> Result<(), KdbError> {
        // match_entry is an optional regex hint; ignoring it is permitted
        // (libkdb5 filters again). Used by kdb5_util dump & listprincs.
        self.store.iterate_principals(|blob| {
            let entry = marshal::decode_entry(ctx, blob)?;
            callback(entry.as_ref())
        })
    }

    // -- policy CRUD ---------------------------------------------------------

    fn create_policy(
        &self,
        _ctx: &KdbContext<'_>,
        policy: &PolicyEntry,
    ) -> Result<(), KdbError> {
        let blob = marshal::encode_policy(policy)?;
        self.store.create_policy(&policy.name, &blob)
    }

    fn get_policy(
        &self,
        _ctx: &KdbContext<'_>,
        name: &str,
    ) -> Result<Option<PolicyEntry>, KdbError> {
        match self.store.get_policy(name)? {
            Some(blob) => Ok(Some(marshal::decode_policy(&blob)?)),
            None => Ok(None),
        }
    }

    fn put_policy(
        &self,
        _ctx: &KdbContext<'_>,
        policy: &PolicyEntry,
    ) -> Result<(), KdbError> {
        let blob = marshal::encode_policy(policy)?;
        self.store.put_policy(&policy.name, &blob)
    }

    fn iter_policy(
        &self,
        _ctx: &KdbContext<'_>,
        _match_entry: Option<&str>,
        callback: &mut dyn FnMut(&PolicyEntry) -> Result<(), KdbError>,
    ) -> Result<(), KdbError> {
        self.store.iterate_policies(|blob| {
            let p = marshal::decode_policy(blob)?;
            callback(&p)
        })
    }

    fn delete_policy(
        &self,
        _ctx: &KdbContext<'_>,
        name: &str,
    ) -> Result<(), KdbError> {
        self.store.delete_policy(name)
    }
}

// Exports the C symbol `kdb_function_table` that libkdb5 resolves after
// dlopen()ing kdb_crdb.so from the plugin dir.
kdb_plugin!(kdb_crdb, CrdbKdb);

#[cfg(test)]
mod tests {
    use super::realm_of;

    #[test]
    fn realm_of_handles_krb5_quoting() {
        // Plain names.
        assert_eq!(realm_of("alice@EXAMPLE.COM"), "EXAMPLE.COM");
        assert_eq!(realm_of("host/a.example.com@EXAMPLE.COM"), "EXAMPLE.COM");
        assert_eq!(realm_of("norealm"), "");
        assert_eq!(realm_of("empty@"), "");
        // Escaped '@' inside a component is not the separator.
        assert_eq!(realm_of(r"odd\@user@REALM"), "REALM");
        assert_eq!(realm_of(r"odd\@user"), "");
        // Component ending in a literal backslash: krb5 unparses it as
        // "\\", so the separator is preceded by a backslash that does NOT
        // escape it. A naive reverse scan misreads this.
        assert_eq!(realm_of(r"trail\\@REALM"), "REALM");
        // Escaped backslash then escaped '@', then the real separator.
        assert_eq!(realm_of(r"a\\\@b@R"), "R");
    }
}
