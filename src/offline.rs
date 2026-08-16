//! Opt-in offline last-known-good entry cache (KDC role only).
//!
//! Why: a KDC must be able to (re)start and keep answering AS/TGS while
//! CockroachDB is unreachable. The `stale_reads_ms` fallback covers an
//! outage only as long as the process keeps its *existing* SQL session —
//! a NEW session to a quorum-less node cannot even be established (CRDB's
//! own user lookup and descriptor leasing need writes). So a KDC that is
//! restarted mid-outage, or a whole datacenter coming back from power
//! loss, has nothing to read. This file is that nothing's replacement.
//!
//! What is stored: the raw wire blobs exactly as they sit in the
//! `principals` table, plus the alias rows needed to resolve a lookup,
//! each with a written-at stamp. Key material inside a blob is already
//! encrypted under the realm master key (marshal.rs), so the file is in
//! the SAME on-disk sensitivity class as a db2/LMDB principal file — and
//! strictly weaker than the stash, which it never contains. See README's
//! threat-model section before deploying it.
//!
//! What it is NOT: a replica. It is fed only by reads this KDC actually
//! performed, it is refused past `offline_cache_max_age_ms`, it is never
//! consulted for admin-role lookups or for writes, and a miss while
//! offline is an error (never "no such principal") — a partial cache must
//! not be able to manufacture a false KDC_ERR_C_PRINCIPAL_UNKNOWN.

use std::collections::HashMap;
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

/// Bumped on any incompatible layout change; older files are discarded
/// (an unreadable cache is never fatal, it just starts empty).
const FILE_VERSION: u8 = 1;

/// Coarse bound on the on-disk file. This is a cold-start aid for the hot
/// set, not a mirror of the realm: past the cap the oldest stamps are
/// dropped. 16k entries is ~3-6 MB of blobs.
const MAX_ENTRIES: usize = 16_384;

/// Minimum wall time between flushes. Writes piggyback on the request
/// flow (no background thread by design — a KDC worker is a single
/// synchronous loop), so this is what bounds write amplification: at most
/// one rewrite per interval per worker no matter the request rate.
const FLUSH_MIN_INTERVAL: Duration = Duration::from_secs(10);

/// A stamp further in the future than this means the clock moved
/// backwards under us; treat those entries as expired rather than as
/// eternally fresh (fail closed — see `age_ms`).
const FUTURE_SLACK_MS: u64 = 60_000;

/// Postcard payload. Vec-of-tuples rather than maps: postcard's map
/// support depends on serde features we don't otherwise need, and a
/// deterministic ordering makes the file diffable in a pinch.
#[derive(Serialize, Deserialize)]
struct CacheFile {
    version: u8,
    /// (principal name, written-at ms since epoch, wire blob)
    entries: Vec<(String, u64, Vec<u8>)>,
    /// (alias, written-at ms since epoch, canonical name)
    aliases: Vec<(String, u64, String)>,
}

/// Result of an offline lookup. `Expired` and `Miss` are distinct for
/// logging/tests only — both fail closed at the call site.
#[derive(Debug, PartialEq, Eq)]
pub enum Hit {
    Fresh(Vec<u8>),
    /// Present but older than `offline_cache_max_age_ms`.
    Expired,
    Miss,
}

struct State {
    entries: HashMap<String, (u64, Vec<u8>)>,
    aliases: HashMap<String, (u64, String)>,
    dirty: bool,
    next_flush: Instant,
    /// Highest stamp handed out so far, so stamps stay monotone even if
    /// the system clock steps backwards mid-run.
    last_stamp: u64,
}

pub struct OfflineCache {
    path: PathBuf,
    max_age_ms: u64,
    state: Mutex<State>,
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_millis() as u64)
}

/// Age of a stamp, or None when it is unusable (in the future beyond the
/// slack — a stepped clock must not make stale entries look fresh).
fn age_ms(stamp: u64, now: u64) -> Option<u64> {
    if stamp > now.saturating_add(FUTURE_SLACK_MS) {
        None
    } else {
        Some(now.saturating_sub(stamp))
    }
}

impl OfflineCache {
    /// Load the cache file. NEVER fails: a missing, truncated, corrupt or
    /// unreadable file just yields an empty cache, because refusing to
    /// open the database because its *optional* cache is damaged would
    /// turn a resilience feature into an outage.
    pub fn open(path: &str, max_age: Duration) -> Self {
        let path = PathBuf::from(path);
        let (entries, aliases) = match Self::load(&path) {
            Ok(v) => v,
            Err(why) => {
                if path.exists() {
                    crate::warn(&format!(
                        "offline cache {} unusable ({why}); starting empty",
                        path.display()
                    ));
                }
                (HashMap::new(), HashMap::new())
            }
        };
        OfflineCache {
            path,
            max_age_ms: max_age.as_millis() as u64,
            state: Mutex::new(State {
                entries,
                aliases,
                dirty: false,
                // Flush the FIRST change immediately: krb5kdc reads K/M
                // and the TGS principal at startup, and if the outage
                // begins before the first interval elapses those are
                // exactly the entries a cold start needs on disk.
                next_flush: Instant::now(),
                last_stamp: 0,
            }),
        }
    }

    #[allow(clippy::type_complexity)]
    fn load(
        path: &Path,
    ) -> Result<
        (HashMap<String, (u64, Vec<u8>)>, HashMap<String, (u64, String)>),
        String,
    > {
        let raw = std::fs::read(path).map_err(|e| e.to_string())?;
        let file: CacheFile =
            postcard::from_bytes(&raw).map_err(|e| e.to_string())?;
        if file.version != FILE_VERSION {
            return Err(format!("wire version {}", file.version));
        }
        Ok((
            file.entries.into_iter().map(|(k, t, v)| (k, (t, v))).collect(),
            file.aliases.into_iter().map(|(k, t, v)| (k, (t, v))).collect(),
        ))
    }

    /// Number of cached principal entries (diagnostics/tests).
    pub fn entry_count(&self) -> usize {
        self.state.lock().map_or(0, |s| s.entries.len())
    }

    // -- read path ----------------------------------------------------------

    pub fn get_entry(&self, name: &str) -> Hit {
        let now = now_ms();
        let Ok(state) = self.state.lock() else { return Hit::Miss };
        match state.entries.get(name) {
            None => Hit::Miss,
            Some((stamp, blob)) => match age_ms(*stamp, now) {
                Some(age) if age <= self.max_age_ms => Hit::Fresh(blob.clone()),
                _ => Hit::Expired,
            },
        }
    }

    /// Cached alias -> canonical, subject to the same age bound. An
    /// expired or absent alias is None; the caller must still not turn
    /// that into "no such principal" while offline.
    pub fn get_alias(&self, alias: &str) -> Option<String> {
        let now = now_ms();
        let state = self.state.lock().ok()?;
        let (stamp, canonical) = state.aliases.get(alias)?;
        (age_ms(*stamp, now)? <= self.max_age_ms).then(|| canonical.clone())
    }

    // -- write path ---------------------------------------------------------

    pub fn note_entry(&self, name: &str, blob: &[u8]) {
        let now = now_ms();
        let Ok(mut state) = self.state.lock() else { return };
        let stamp = now.max(state.last_stamp);
        state.last_stamp = stamp;
        // Re-stamp only when the blob changed or the existing stamp has
        // burned a quarter of its budget: re-stamping on every read would
        // dirty the map on every request and defeat the flush interval,
        // never re-stamping would let a constantly-read entry expire.
        let fresh_enough = state.entries.get(name).is_some_and(|(t, b)| {
            b == blob
                && age_ms(*t, now).is_some_and(|a| a * 4 <= self.max_age_ms)
        });
        if !fresh_enough {
            state.entries.insert(name.to_owned(), (stamp, blob.to_vec()));
            state.dirty = true;
            Self::prune(&mut state);
        }
        // Checked even when nothing changed: a KDC whose hot set has gone
        // quiet (all re-reads "fresh enough") would otherwise never write
        // out the entries it accumulated before the last flush.
        self.maybe_flush(&mut state);
    }

    pub fn note_alias(&self, alias: &str, canonical: &str) {
        let now = now_ms();
        let Ok(mut state) = self.state.lock() else { return };
        let stamp = now.max(state.last_stamp);
        state.last_stamp = stamp;
        let fresh_enough = state.aliases.get(alias).is_some_and(|(t, c)| {
            c == canonical
                && age_ms(*t, now).is_some_and(|a| a * 4 <= self.max_age_ms)
        });
        if !fresh_enough {
            state
                .aliases
                .insert(alias.to_owned(), (stamp, canonical.to_owned()));
            state.dirty = true;
        }
        self.maybe_flush(&mut state);
    }

    /// Drop the oldest entries once over the cap. Sorting a 16k map is a
    /// millisecond and only happens at the boundary.
    fn prune(state: &mut State) {
        let over = state.entries.len().saturating_sub(MAX_ENTRIES);
        if over == 0 {
            return;
        }
        let mut by_age: Vec<(u64, String)> = state
            .entries
            .iter()
            .map(|(k, (t, _))| (*t, k.clone()))
            .collect();
        by_age.sort_unstable();
        for (_, k) in by_age.into_iter().take(over) {
            state.entries.remove(&k);
        }
    }

    fn maybe_flush(&self, state: &mut State) {
        if !state.dirty || Instant::now() < state.next_flush {
            return;
        }
        state.next_flush = Instant::now() + FLUSH_MIN_INTERVAL;
        match self.write_file(state) {
            Ok(()) => state.dirty = false,
            // Keep serving; a cache we cannot persist is not an error the
            // KDC should surface to a client.
            Err(why) => crate::warn(&format!(
                "offline cache {}: flush failed ({why})",
                self.path.display()
            )),
        }
    }

    /// Flush now, ignoring the interval. Errors are logged, never
    /// propagated. (Tests only today — production flushes ride the
    /// request flow, which is the whole no-background-thread point.)
    #[allow(dead_code)]
    pub fn flush_now(&self) {
        let Ok(mut state) = self.state.lock() else { return };
        state.next_flush = Instant::now();
        state.dirty = true;
        self.maybe_flush(&mut state);
    }

    /// Atomic replace: write a 0600 temp file in the same directory,
    /// fsync it, rename over the target, then fsync the directory so the
    /// rename itself survives power loss (this whole feature exists for
    /// power loss — a durability hole here would be silly).
    ///
    /// `krb5kdc -w N` gives every worker its own copy of this cache
    /// pointed at the same path, so the file is merged with whatever is
    /// on disk first, newest stamp winning. Workers therefore converge on
    /// the union of what the fleet has read instead of clobbering each
    /// other with partial views.
    fn write_file(&self, state: &mut State) -> Result<(), String> {
        if let Ok((disk_entries, disk_aliases)) = Self::load(&self.path) {
            for (k, (t, v)) in disk_entries {
                match state.entries.get(&k) {
                    Some((cur, _)) if *cur >= t => {}
                    _ => {
                        state.entries.insert(k, (t, v));
                    }
                }
            }
            for (k, (t, v)) in disk_aliases {
                match state.aliases.get(&k) {
                    Some((cur, _)) if *cur >= t => {}
                    _ => {
                        state.aliases.insert(k, (t, v));
                    }
                }
            }
            Self::prune(state);
        }

        let mut entries: Vec<(String, u64, Vec<u8>)> = state
            .entries
            .iter()
            .map(|(k, (t, v))| (k.clone(), *t, v.clone()))
            .collect();
        entries.sort_unstable_by(|a, b| a.0.cmp(&b.0));
        let mut aliases: Vec<(String, u64, String)> = state
            .aliases
            .iter()
            .map(|(k, (t, v))| (k.clone(), *t, v.clone()))
            .collect();
        aliases.sort_unstable_by(|a, b| a.0.cmp(&b.0));
        let blob =
            postcard::to_allocvec(&CacheFile { version: FILE_VERSION, entries, aliases })
                .map_err(|e| e.to_string())?;

        let dir = self.path.parent().unwrap_or(Path::new("."));
        let tmp = dir.join(format!(
            ".{}.{}.tmp",
            self.path.file_name().and_then(|s| s.to_str()).unwrap_or("cache"),
            std::process::id()
        ));
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&tmp)
            .map_err(|e| e.to_string())?;
        let res = f
            .write_all(&blob)
            .and_then(|()| f.sync_all())
            .map_err(|e| e.to_string());
        drop(f);
        if let Err(e) = res {
            let _ = std::fs::remove_file(&tmp);
            return Err(e);
        }
        std::fs::rename(&tmp, &self.path).map_err(|e| {
            let _ = std::fs::remove_file(&tmp);
            e.to_string()
        })?;
        if let Ok(d) = std::fs::File::open(dir) {
            let _ = d.sync_all();
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmpdir(tag: &str) -> PathBuf {
        let p = std::env::temp_dir().join(format!(
            "kdb-crdb-offline-{}-{}-{}",
            tag,
            std::process::id(),
            now_ms()
        ));
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    fn cache(dir: &Path, max_age: Duration) -> OfflineCache {
        OfflineCache::open(dir.join("cache.bin").to_str().unwrap(), max_age)
    }

    #[test]
    fn round_trips_entries_and_aliases_through_the_file() {
        let dir = tmpdir("roundtrip");
        let c = cache(&dir, Duration::from_secs(600));
        c.note_entry("K/M@EXAMPLE.COM", b"master-key-blob");
        c.note_entry("krbtgt/EXAMPLE.COM@EXAMPLE.COM", b"tgs-blob");
        c.note_alias("alicia@EXAMPLE.COM", "alice@EXAMPLE.COM");
        c.flush_now();

        // A *fresh process* (cold start) must see everything.
        let c2 = cache(&dir, Duration::from_secs(600));
        assert_eq!(c2.entry_count(), 2);
        assert_eq!(
            c2.get_entry("K/M@EXAMPLE.COM"),
            Hit::Fresh(b"master-key-blob".to_vec())
        );
        assert_eq!(
            c2.get_alias("alicia@EXAMPLE.COM").as_deref(),
            Some("alice@EXAMPLE.COM")
        );
        // Never fabricate a negative answer.
        assert_eq!(c2.get_entry("nobody@EXAMPLE.COM"), Hit::Miss);
        assert_eq!(c2.get_alias("nobody@EXAMPLE.COM"), None);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn file_is_0600() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tmpdir("mode");
        let c = cache(&dir, Duration::from_secs(600));
        c.note_entry("a@R", b"x");
        c.flush_now();
        let mode = std::fs::metadata(dir.join("cache.bin"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600, "cache file must not be world readable");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn entries_past_max_age_are_refused_not_served() {
        let dir = tmpdir("age");
        // Written under a 10-minute budget...
        let c = cache(&dir, Duration::from_secs(600));
        c.note_entry("alice@EXAMPLE.COM", b"blob");
        c.flush_now();
        // ...re-read by a KDC configured with a 0-tolerance budget: the
        // entry is older than the bound, so it must fail closed rather
        // than serve unbounded-stale principal data.
        let strict = OfflineCache::open(
            dir.join("cache.bin").to_str().unwrap(),
            Duration::from_millis(0),
        );
        std::thread::sleep(Duration::from_millis(5));
        assert_eq!(strict.get_entry("alice@EXAMPLE.COM"), Hit::Expired);
        assert_eq!(strict.get_alias("alice@EXAMPLE.COM"), None);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn future_stamps_are_treated_as_expired() {
        // A clock step backwards must not make an old entry immortal.
        assert_eq!(age_ms(1_000, 5_000), Some(4_000));
        assert_eq!(age_ms(5_000, 5_000), Some(0));
        assert_eq!(age_ms(5_000 + FUTURE_SLACK_MS, 5_000), Some(0));
        assert_eq!(age_ms(5_001 + FUTURE_SLACK_MS, 5_000), None);
    }

    #[test]
    fn corrupt_or_missing_file_starts_empty_and_still_works() {
        let dir = tmpdir("corrupt");
        // Missing file.
        let c = cache(&dir, Duration::from_secs(600));
        assert_eq!(c.entry_count(), 0);

        // Garbage, truncated payload, and a wrong-version header must all
        // be tolerated: open() never fails because of the cache.
        for junk in [
            b"\xff\xff\xff\xff not postcard at all".to_vec(),
            vec![],
            postcard::to_allocvec(&CacheFile {
                version: FILE_VERSION + 7,
                entries: vec![("a@R".into(), 1, b"x".to_vec())],
                aliases: vec![],
            })
            .unwrap(),
        ] {
            std::fs::write(dir.join("cache.bin"), &junk).unwrap();
            let c = cache(&dir, Duration::from_secs(600));
            assert_eq!(c.entry_count(), 0, "corrupt file must start empty");
            // And it must recover: writing over it produces a good file.
            c.note_entry("a@R", b"good");
            c.flush_now();
            let c2 = cache(&dir, Duration::from_secs(600));
            assert_eq!(c2.get_entry("a@R"), Hit::Fresh(b"good".to_vec()));
        }
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn partial_cache_miss_is_a_miss_not_an_empty_answer() {
        // The whole point of the offline-miss contract: a cache that only
        // ever saw `alice` must not be able to say anything about `bob`.
        // (store.rs turns Miss into KRB5KDC_ERR_SVC_UNAVAILABLE, never
        // NoEntry — see store::offline_unavailable.)
        let dir = tmpdir("partial");
        let c = cache(&dir, Duration::from_secs(600));
        c.note_entry("alice@EXAMPLE.COM", b"blob");
        c.flush_now();
        let c2 = cache(&dir, Duration::from_secs(600));
        assert!(matches!(c2.get_entry("alice@EXAMPLE.COM"), Hit::Fresh(_)));
        assert_eq!(c2.get_entry("bob@EXAMPLE.COM"), Hit::Miss);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn concurrent_writers_merge_instead_of_clobbering() {
        // `krb5kdc -w N`: every worker owns a cache over the same path.
        // Worker A's entries must survive worker B's flush.
        let dir = tmpdir("merge");
        let a = cache(&dir, Duration::from_secs(600));
        let b = cache(&dir, Duration::from_secs(600));
        a.note_entry("a@R", b"from-a");
        a.flush_now();
        b.note_entry("b@R", b"from-b");
        b.flush_now();

        let c = cache(&dir, Duration::from_secs(600));
        assert_eq!(c.get_entry("a@R"), Hit::Fresh(b"from-a".to_vec()));
        assert_eq!(c.get_entry("b@R"), Hit::Fresh(b"from-b".to_vec()));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn rewritten_entry_wins_over_the_on_disk_copy() {
        // A cpw seen by this worker must not be reverted by the merge.
        let dir = tmpdir("newer");
        let a = cache(&dir, Duration::from_secs(600));
        a.note_entry("a@R", b"old-keys");
        a.flush_now();
        let b = cache(&dir, Duration::from_secs(600));
        std::thread::sleep(Duration::from_millis(5));
        b.note_entry("a@R", b"new-keys");
        b.flush_now();
        let c = cache(&dir, Duration::from_secs(600));
        assert_eq!(c.get_entry("a@R"), Hit::Fresh(b"new-keys".to_vec()));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn flush_interval_bounds_write_amplification() {
        // The first change is written straight through (so a KDC that
        // dies seconds after start still leaves K/M on disk)...
        let dir = tmpdir("interval");
        let c = cache(&dir, Duration::from_secs(600));
        c.note_entry("u0@R", b"blob");
        assert!(dir.join("cache.bin").exists(), "first change must persist");
        // ...but hammering it after that must NOT rewrite the file per
        // request: everything else stays in memory until the interval.
        for i in 1..500 {
            c.note_entry(&format!("u{i}@R"), b"blob");
        }
        assert_eq!(
            cache(&dir, Duration::from_secs(600)).entry_count(),
            1,
            "flush interval did not bound write amplification"
        );
        c.flush_now();
        assert_eq!(cache(&dir, Duration::from_secs(600)).entry_count(), 500);
        std::fs::remove_dir_all(&dir).ok();
    }
}
