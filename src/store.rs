//! CockroachDB access layer.
//!
//! One synchronous libpq-style connection per KdbModule instance, behind a
//! Mutex. This matches the krb5 process model: krb5kdc's event loop and
//! kadmind are single-threaded, and `krb5kdc -w N` forks N processes that
//! each dlopen the plugin and open their own context. Short-lived tools
//! (kadmin.local, kdb5_util) pay one connection setup per invocation, which
//! is cheap with postgres-protocol (unlike, notably, the fdb client's
//! network-thread spin-up — one of the reasons crdb won this bake-off).
//!
//! Retry policy: CockroachDB surfaces serialization conflicts as SQLSTATE
//! 40001. Single implicit-transaction statements are mostly retried
//! server-side, but we still guard everything with a small client-side
//! retry loop, and multi-statement operations (rename) run in an explicit
//! transaction inside the same loop.

use std::collections::HashMap;
use std::sync::Mutex;

use kurbu5_kdb_rs::KdbError;
use native_tls::{Certificate, Identity, TlsConnector};
use postgres::{Client, NoTls, Statement};
use postgres_native_tls::MakeTlsConnector;

const MAX_RETRIES: usize = 8;

/// A connection plus its prepared-statement cache. Preparing once per
/// connection removes the per-query parse/describe work from the AS/TGS
/// hot path (rust-postgres re-prepares unnamed statements on every
/// text-SQL call). Statements are per-connection server state, so the
/// cache lives and dies with the Client.
struct Conn {
    client: Client,
    stmts: HashMap<&'static str, Statement>,
}

impl Conn {
    fn new(client: Client) -> Self {
        Conn { client, stmts: HashMap::new() }
    }

    fn stmt(
        &mut self,
        sql: &'static str,
    ) -> Result<Statement, postgres::Error> {
        if let Some(s) = self.stmts.get(sql) {
            return Ok(s.clone());
        }
        let s = self.client.prepare(sql)?;
        self.stmts.insert(sql, s.clone());
        Ok(s)
    }
}

/// TLS choice, decided once from the URI at connect time and reused on
/// reconnect. Anything other than an explicit `sslmode=disable` gets a
/// *verifying* TLS connector: certificate chain AND hostname are always
/// checked (i.e. verify-full semantics — there is no "encrypted but
/// unauthenticated" mode here, on purpose: the KDC must know it is talking
/// to the cluster it trusts for authorization data).
enum Tls {
    Disabled,
    Verified(MakeTlsConnector),
}

pub struct Store {
    conn: Mutex<Conn>,
    uri: String,
    tls: Tls,
    /// Max read staleness (ms) for the degraded-read fallback; 0 = off.
    /// When CRDB loses quorum (downed nodes, split brain), normal reads
    /// hang and then error; bounded-staleness follower reads
    /// (`AS OF SYSTEM TIME with_max_staleness`) are servable by ANY live
    /// replica without quorum. Trading <= stale_ms of principal-data
    /// staleness for staying up through a DB outage is the right call
    /// for a KDC: auth is read-only (lockout is off by design) and key
    /// changes are rare and operator-driven.
    stale_ms: u64,
    /// Circuit breaker: after a primary-read failure, serve stale reads
    /// first until this instant, then probe the primary again. Without
    /// it every request would eat a full statement_timeout before
    /// falling back, cratering QPS during the outage.
    degraded_until: Mutex<Option<std::time::Instant>>,
}

/// Fail primary statements fast when the fallback exists; quorum-less
/// ranges otherwise block "forever" and kinit would time out first.
const DEGRADED_STMT_TIMEOUT_MS: u64 = 1500;
/// How long to stay on stale reads before re-probing the primary.
const DEGRADED_HOLD_MS: u64 = 5000;

/// Split TLS-related params out of the URI: rust-postgres does not
/// understand `sslrootcert`/`sslcert`/`sslkey` (and only knows sslmode
/// disable/prefer/require), so we consume them and hand back a URI it can
/// parse. Returns the cleaned URI and the TLS configuration.
fn parse_tls(uri: &str) -> Result<(String, Tls), KdbError> {
    let (base, query) = match uri.split_once('?') {
        Some((b, q)) => (b, q),
        None => (uri, ""),
    };
    let mut kept = Vec::new();
    let mut sslmode = None;
    let mut sslrootcert = None;
    let mut sslcert = None;
    let mut sslkey = None;
    for pair in query.split('&').filter(|p| !p.is_empty()) {
        let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
        match k {
            "sslmode" => sslmode = Some(v.to_owned()),
            "sslrootcert" => sslrootcert = Some(v.to_owned()),
            "sslcert" => sslcert = Some(v.to_owned()),
            "sslkey" => sslkey = Some(v.to_owned()),
            _ => kept.push(pair.to_owned()),
        }
    }

    let tls = match sslmode.as_deref() {
        Some("disable") => Tls::Disabled,
        // No sslmode given: default to TLS like libpq's prefer, but
        // verified. (Use sslmode=disable explicitly for dev clusters.)
        _ => {
            let mut builder = TlsConnector::builder();
            if let Some(path) = &sslrootcert {
                let pem = std::fs::read(path)
                    .map_err(|_| KdbError::Io(libc::EIO))?;
                builder.add_root_certificate(
                    Certificate::from_pem(&pem)
                        .map_err(|_| KdbError::Custom(libc::EINVAL))?,
                );
            }
            match (&sslcert, &sslkey) {
                (Some(cert), Some(key)) => {
                    builder.identity(client_identity(cert, key)?);
                }
                (None, None) => {}
                // Half a keypair is a config error, not something to limp
                // past silently (libpq would just fall back to password).
                _ => return Err(KdbError::Custom(libc::EINVAL)),
            }
            let connector = builder
                .build()
                .map_err(|_| KdbError::Custom(libc::EINVAL))?;
            kept.push("sslmode=require".to_owned());
            Tls::Verified(MakeTlsConnector::new(connector))
        }
    };
    if matches!(tls, Tls::Disabled) {
        kept.push("sslmode=disable".to_owned());
    }

    let clean = if kept.is_empty() {
        base.to_owned()
    } else {
        format!("{base}?{}", kept.join("&"))
    };
    Ok((clean, tls))
}

/// Build a TLS client identity for cert auth (`sslcert`/`sslkey`).
/// `cockroach cert create-client` emits PKCS#1 keys but native-tls only
/// accepts PKCS#8, so re-encode through openssl (already linked via
/// native-tls) instead of pushing the conversion onto every operator.
fn client_identity(cert: &str, key: &str) -> Result<Identity, KdbError> {
    let cert_pem = std::fs::read(cert).map_err(|_| KdbError::Io(libc::EIO))?;
    let key_pem = std::fs::read(key).map_err(|_| KdbError::Io(libc::EIO))?;
    let pkey = openssl::pkey::PKey::private_key_from_pem(&key_pem)
        .map_err(|_| KdbError::Custom(libc::EINVAL))?;
    let pkcs8 = pkey
        .private_key_to_pem_pkcs8()
        .map_err(|_| KdbError::Custom(libc::EINVAL))?;
    Identity::from_pkcs8(&cert_pem, &pkcs8)
        .map_err(|_| KdbError::Custom(libc::EINVAL))
}

/// Rotate a URI's comma-separated host list by `seed` (no-op for a
/// single host). Operates textually on the authority section so TLS
/// params and everything else pass through untouched.
fn rotate_hosts(uri: &str, seed: usize) -> String {
    let Some(scheme_end) = uri.find("://") else { return uri.to_owned() };
    let rest = &uri[scheme_end + 3..];
    let path_start = rest.find(['/', '?']).unwrap_or(rest.len());
    let authority = &rest[..path_start];
    let (userinfo, hostlist) = match authority.rfind('@') {
        Some(i) => (&authority[..=i], &authority[i + 1..]),
        None => ("", authority),
    };
    let hosts: Vec<&str> = hostlist.split(',').collect();
    if hosts.len() < 2 {
        return uri.to_owned();
    }
    let k = seed % hosts.len();
    let rotated: Vec<&str> =
        hosts[k..].iter().chain(hosts[..k].iter()).copied().collect();
    format!(
        "{}{}{}{}",
        &uri[..scheme_end + 3],
        userinfo,
        rotated.join(","),
        &rest[path_start..],
    )
}

fn pg_err(e: &postgres::Error) -> KdbError {
    // Map "our fault / their fault" coarsely; refine as needed.
    if e.as_db_error().is_some() {
        KdbError::Custom(libc::EIO)
    } else {
        // Connection-level error (network, TLS, auth).
        KdbError::Io(libc::EIO)
    }
}

fn is_retryable(e: &postgres::Error) -> bool {
    e.code()
        .map(|c| c.code() == "40001" || c.code() == "40003")
        .unwrap_or(false)
}

impl Store {
    /// `uri` example:
    ///   postgresql://krb5kdc@lb.crdb.internal:26257/krb5?sslmode=verify-full&sslrootcert=/etc/krb5kdc/crdb-ca.crt
    ///
    /// TLS policy: only `sslmode=disable` skips TLS. Every other mode —
    /// including verify-ca/verify-full spellings and *no* sslmode at all —
    /// connects with full verification (chain + hostname) against
    /// `sslrootcert` (or the system trust store if unset). The blobs are
    /// ciphertext, but principal names/metadata should not transit
    /// plaintext, and the KDC must authenticate the cluster it trusts.
    pub fn connect(uri: &str) -> Result<Self, KdbError> {
        Self::connect_with(uri, 0)
    }

    /// `stale_ms` > 0 enables the degraded-read fallback (see field doc).
    pub fn connect_with(uri: &str, stale_ms: u64) -> Result<Self, KdbError> {
        // Multi-host URIs (host1:p,host2:p,...) are tried in order by
        // rust-postgres; rotate the list per process so a fleet of KDC
        // workers spreads gateways instead of all picking host1, and so
        // reconnect after a node death naturally walks to a survivor.
        let uri = rotate_hosts(uri, std::process::id() as usize);
        let (clean_uri, tls) = parse_tls(&uri)?;
        let client = Self::open_client(&clean_uri, &tls, stale_ms)?;
        Ok(Store {
            conn: Mutex::new(Conn::new(client)),
            uri: clean_uri,
            tls,
            stale_ms,
            degraded_until: Mutex::new(None),
        })
    }

    fn open_client(
        uri: &str,
        tls: &Tls,
        stale_ms: u64,
    ) -> Result<Client, KdbError> {
        let mut client = match tls {
            Tls::Disabled => {
                Client::connect(uri, NoTls).map_err(|e| pg_err(&e))?
            }
            Tls::Verified(connector) => {
                Client::connect(uri, connector.clone())
                    .map_err(|e| pg_err(&e))?
            }
        };
        if stale_ms > 0 {
            client
                .batch_execute(&format!(
                    "SET statement_timeout = '{DEGRADED_STMT_TIMEOUT_MS}ms'"
                ))
                .map_err(|e| pg_err(&e))?;
        }
        Ok(client)
    }

    fn is_degraded(&self) -> bool {
        self.degraded_until
            .lock()
            .ok()
            .and_then(|g| *g)
            .is_some_and(|t| std::time::Instant::now() < t)
    }

    fn set_degraded(&self) {
        if let Ok(mut g) = self.degraded_until.lock() {
            *g = Some(
                std::time::Instant::now()
                    + std::time::Duration::from_millis(DEGRADED_HOLD_MS),
            );
        }
    }

    fn clear_degraded(&self) {
        if let Ok(mut g) = self.degraded_until.lock() {
            *g = None;
        }
    }

    /// Bounded-staleness point read: served by any live replica, no
    /// quorum needed. nearest_only=true so it never waits on an
    /// unreachable leaseholder.
    fn stale_read<T: postgres::types::FromSqlOwned>(
        &self,
        primary_sql: &str,
        key: &str,
    ) -> Result<Option<T>, KdbError> {
        // "SELECT x FROM t WHERE k = $1" ->
        // "SELECT x FROM t AS OF SYSTEM TIME ... WHERE k = $1"
        let sql = primary_sql.replacen(
            " WHERE ",
            &format!(
                " AS OF SYSTEM TIME with_max_staleness('{}ms', true) WHERE ",
                self.stale_ms
            ),
            1,
        );
        self.with_retry(|c| {
            let row = c.client.query_opt(sql.as_str(), &[&key])?;
            Ok(row.map(|r| r.get::<_, T>(0)))
        })
    }

    /// Primary read with the degraded fallback wrapped around it.
    fn read_with_fallback<T: postgres::types::FromSqlOwned>(
        &self,
        primary_sql: &'static str,
        key: &str,
    ) -> Result<Option<T>, KdbError> {
        if self.stale_ms > 0 && self.is_degraded() {
            if let Ok(v) = self.stale_read::<T>(primary_sql, key) {
                return Ok(v);
            }
            // Stale path itself failed — fall through and try primary.
        }
        let primary = self.with_retry(|c| {
            let stmt = c.stmt(primary_sql)?;
            let row = c.client.query_opt(&stmt, &[&key])?;
            Ok(row.map(|r| r.get::<_, T>(0)))
        });
        match primary {
            Ok(v) => {
                if self.stale_ms > 0 {
                    self.clear_degraded();
                }
                Ok(v)
            }
            Err(e) if self.stale_ms > 0 => {
                self.set_degraded();
                self.stale_read::<T>(primary_sql, key).map_err(|_| e)
            }
            Err(e) => Err(e),
        }
    }

    /// Run `f` with the connection, reconnecting once on connection loss
    /// and retrying on serialization failures with capped exponential
    /// backoff. Reconnect swaps in a fresh Conn, which drops the statement
    /// cache with the dead session.
    fn with_retry<T>(
        &self,
        mut f: impl FnMut(&mut Conn) -> Result<T, postgres::Error>,
    ) -> Result<T, KdbError> {
        let mut guard = self.conn.lock().map_err(|_| KdbError::Locked)?;
        let mut backoff_ms = 5u64;
        for attempt in 0..MAX_RETRIES {
            match f(&mut guard) {
                Ok(v) => return Ok(v),
                Err(e) if is_retryable(&e) && attempt + 1 < MAX_RETRIES => {
                    std::thread::sleep(std::time::Duration::from_millis(
                        backoff_ms,
                    ));
                    backoff_ms = (backoff_ms * 2).min(200);
                }
                Err(e) if guard.client.is_closed() => {
                    // One reconnect attempt, then replay.
                    let _ = e; // original error superseded
                    *guard = Conn::new(Self::open_client(
                        &self.uri,
                        &self.tls,
                        self.stale_ms,
                    )?);
                }
                Err(e) => return Err(pg_err(&e)),
            }
        }
        Err(KdbError::Custom(libc::EIO))
    }

    // -- principals ---------------------------------------------------------

    pub fn get_principal(
        &self,
        name: &str,
    ) -> Result<Option<Vec<u8>>, KdbError> {
        // The AS/TGS hot path. On a GLOBAL table this is a strongly
        // consistent read served by the local region: no WAN round-trip.
        // Prepared once per connection: no parse/describe per request.
        // Falls back to a bounded-staleness read when quorum is gone.
        self.read_with_fallback(
            "SELECT entry FROM principals WHERE name = $1",
            name,
        )
    }

    /// Resolve an alias to its canonical principal name (aliases table is
    /// operator-managed; see schema.sql). On the exact-match hot path this
    /// is never called — only on a lookup miss.
    pub fn get_alias(&self, name: &str) -> Result<Option<String>, KdbError> {
        self.read_with_fallback(
            "SELECT canonical FROM aliases WHERE alias = $1",
            name,
        )
    }

    pub fn put_principal(
        &self,
        name: &str,
        blob: &[u8],
    ) -> Result<(), KdbError> {
        self.with_retry(|c| {
            let stmt = c.stmt(
                "UPSERT INTO principals (name, entry, updated_at) \
                 VALUES ($1, $2, now())",
            )?;
            c.client.execute(&stmt, &[&name, &blob])?;
            Ok(())
        })
    }

    pub fn delete_principal(&self, name: &str) -> Result<(), KdbError> {
        let n = self.with_retry(|c| {
            let stmt =
                c.stmt("DELETE FROM principals WHERE name = $1")?;
            c.client.execute(&stmt, &[&name])
        })?;
        if n == 0 { Err(KdbError::NoEntry) } else { Ok(()) }
    }

    /// Atomic rename: the wire blob embeds the canonical principal name, so
    /// the caller re-encodes it and we swap rows in one transaction. Strong
    /// consistency means no region can observe both or neither name.
    pub fn rename_principal(
        &self,
        old: &str,
        new: &str,
        new_blob: &[u8],
    ) -> Result<(), KdbError> {
        // Delete first: if the source row doesn't exist the txn must end
        // WITHOUT the upsert becoming visible. (Upsert-then-delete commits
        // a phantom target row when the source is missing — found the hard
        // way, as a stray row that resurfaced through dump/load.)
        let renamed = self.with_retry(|c| {
            let mut txn = c.client.transaction()?;
            let n = txn
                .execute("DELETE FROM principals WHERE name = $1", &[&old])?;
            if n == 0 {
                txn.rollback()?;
                return Ok(false);
            }
            txn.execute(
                "UPSERT INTO principals (name, entry, updated_at) \
                 VALUES ($1, $2, now())",
                &[&new, &new_blob],
            )?;
            txn.commit()?;
            Ok(true)
        })?;
        if renamed { Ok(()) } else { Err(KdbError::NoEntry) }
    }

    /// Full scan for kdb5_util dump / kadmin listprincs. Paged so a large
    /// realm doesn't hold one enormous result set (and CRDB follower reads
    /// keep this cheap even mid-write-load).
    pub fn iterate_principals(
        &self,
        mut cb: impl FnMut(&[u8]) -> Result<(), KdbError>,
    ) -> Result<(), KdbError> {
        let mut last = String::new();
        loop {
            let rows: Vec<Vec<u8>> = self.with_retry(|c| {
                let stmt = c.stmt(
                    "SELECT name, entry FROM principals \
                     WHERE name > $1 ORDER BY name LIMIT 512",
                )?;
                Ok(c.client
                    .query(&stmt, &[&last])?
                .into_iter()
                .map(|r| {
                    last = r.get::<_, String>(0);
                    r.get::<_, Vec<u8>>(1)
                })
                .collect())
            })?;
            if rows.is_empty() {
                return Ok(());
            }
            for blob in &rows {
                cb(blob)?;
            }
        }
    }

    // -- policies -----------------------------------------------------------

    pub fn get_policy(&self, name: &str) -> Result<Option<Vec<u8>>, KdbError> {
        self.with_retry(|c| {
            let stmt =
                c.stmt("SELECT entry FROM policies WHERE name = $1")?;
            let row = c.client.query_opt(&stmt, &[&name])?;
            Ok(row.map(|r| r.get::<_, Vec<u8>>(0)))
        })
    }

    pub fn put_policy(&self, name: &str, blob: &[u8]) -> Result<(), KdbError> {
        self.with_retry(|c| {
            let stmt = c.stmt(
                "UPSERT INTO policies (name, entry, updated_at) \
                 VALUES ($1, $2, now())",
            )?;
            c.client.execute(&stmt, &[&name, &blob])?;
            Ok(())
        })
    }

    /// Create-only variant for the KADM5 create path (must fail on dup).
    pub fn create_policy(
        &self,
        name: &str,
        blob: &[u8],
    ) -> Result<(), KdbError> {
        self.with_retry(|c| {
            let stmt = c.stmt(
                "INSERT INTO policies (name, entry) VALUES ($1, $2)",
            )?;
            match c.client.execute(&stmt, &[&name, &blob]) {
                Ok(_) => Ok(Ok(())),
                Err(e)
                    if e.code().map(|c| c.code()) == Some("23505") =>
                {
                    Ok(Err(KdbError::Custom(libc::EEXIST)))
                }
                Err(e) => Err(e),
            }
        })?
    }

    pub fn delete_policy(&self, name: &str) -> Result<(), KdbError> {
        let n = self.with_retry(|c| {
            let stmt = c.stmt("DELETE FROM policies WHERE name = $1")?;
            c.client.execute(&stmt, &[&name])
        })?;
        if n == 0 { Err(KdbError::NoEntry) } else { Ok(()) }
    }

    pub fn iterate_policies(
        &self,
        mut cb: impl FnMut(&[u8]) -> Result<(), KdbError>,
    ) -> Result<(), KdbError> {
        let rows: Vec<Vec<u8>> = self.with_retry(|c| {
            Ok(c.client
                .query("SELECT entry FROM policies ORDER BY name", &[])?
                .into_iter()
                .map(|r| r.get::<_, Vec<u8>>(0))
                .collect())
        })?;
        for blob in &rows {
            cb(blob)?;
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Integration tests — need the docker-compose CRDB cluster:
//   docker compose up -d && nix develop --command cargo test
// Override the target with KDB_CRDB_TEST_URI if it isn't on localhost:26257.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::marshal::{self, sample_wire_entry};

    #[test]
    fn tls_uri_parsing() {
        // Explicit disable → NoTls, sslmode passed through.
        let (uri, tls) =
            parse_tls("postgresql://u@h:26257/db?sslmode=disable").unwrap();
        assert!(matches!(tls, Tls::Disabled));
        assert_eq!(uri, "postgresql://u@h:26257/db?sslmode=disable");

        // verify-full + sslrootcert: both consumed, rust-postgres gets
        // `require`, connector is verifying. (Missing cert file must error.)
        assert!(parse_tls(
            "postgresql://u@h/db?sslmode=verify-full&sslrootcert=/nonexistent"
        )
        .is_err());

        // No sslmode at all → TLS with verification, not plaintext.
        let (uri, tls) = parse_tls("postgresql://u@h/db").unwrap();
        assert!(matches!(tls, Tls::Verified(_)));
        assert_eq!(uri, "postgresql://u@h/db?sslmode=require");

        // Unrelated params survive.
        let (uri, _) =
            parse_tls("postgresql://u@h/db?application_name=kdc&sslmode=disable")
                .unwrap();
        assert_eq!(
            uri,
            "postgresql://u@h/db?application_name=kdc&sslmode=disable"
        );

        // sslcert without sslkey (and vice versa) is a config error.
        assert!(parse_tls("postgresql://u@h/db?sslcert=/x.crt").is_err());
        assert!(parse_tls("postgresql://u@h/db?sslkey=/x.key").is_err());

        // Cert-auth params are consumed (rust-postgres can't parse them)
        // and a missing cert file fails closed.
        assert!(parse_tls(
            "postgresql://u@h/db?sslcert=/nonexistent.crt&sslkey=/nonexistent.key"
        )
        .is_err());
        let certs = format!("{}/e2e/.certs", env!("CARGO_MANIFEST_DIR"));
        if std::path::Path::new(&format!("{certs}/client.krb5kdc.crt"))
            .exists()
        {
            let (uri, tls) = parse_tls(&format!(
                "postgresql://u@h/db?sslcert={certs}/client.krb5kdc.crt\
                 &sslkey={certs}/client.krb5kdc.key"
            ))
            .unwrap();
            assert!(matches!(tls, Tls::Verified(_)));
            assert_eq!(uri, "postgresql://u@h/db?sslmode=require");
        }
    }

    #[test]
    fn host_rotation() {
        let u = "postgresql://u@h1:1,h2:2,h3:3/db?sslmode=disable";
        assert_eq!(rotate_hosts(u, 0), u);
        assert_eq!(
            rotate_hosts(u, 1),
            "postgresql://u@h2:2,h3:3,h1:1/db?sslmode=disable"
        );
        assert_eq!(
            rotate_hosts(u, 5),
            "postgresql://u@h3:3,h1:1,h2:2/db?sslmode=disable"
        );
        // Single host and no-path forms are untouched.
        let single = "postgresql://u:pw@only:26257/db";
        assert_eq!(rotate_hosts(single, 7), single);
        assert_eq!(rotate_hosts("postgresql://u@h1,h2", 1),
                   "postgresql://u@h2,h1");
    }

    #[test]
    fn stale_read_fallback_serves_data() {
        // With stale reads enabled and the breaker forced open, reads go
        // through the bounded-staleness path and still return the row.
        let uri = std::env::var("KDB_CRDB_TEST_URI").unwrap_or_else(|_| {
            format!(
                "postgresql://krb5kdc:krb5kdc-dev-pw@localhost:26257/krb5\
                 ?sslmode=verify-full&sslrootcert={}/e2e/.certs/ca.crt",
                env!("CARGO_MANIFEST_DIR"),
            )
        });
        let store = Store::connect_with(&uri, 30_000).unwrap();
        let name = uniq("kt-stale");
        let blob =
            postcard::to_allocvec(&sample_wire_entry(&name)).unwrap();
        store.put_principal(&name, &blob).unwrap();

        // Bounded staleness picks the freshest servable timestamp; on a
        // healthy cluster that is close enough to now to see the row —
        // but not instantly, so poll briefly before asserting.
        store.set_degraded();
        assert!(store.is_degraded());
        let mut got = None;
        for _ in 0..50 {
            got = store.get_principal(&name).unwrap();
            if got.is_some() {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
        assert_eq!(got.as_deref(), Some(&blob[..]), "stale read lost the row");

        // A healthy primary read clears the breaker again.
        store.clear_degraded();
        assert!(store.get_principal(&name).unwrap().is_some());
        assert!(!store.is_degraded());
        store.delete_principal(&name).unwrap();
    }

    #[test]
    fn cert_auth_connects_without_password() {
        // Client-cert auth against the compose cluster: no password in the
        // URI at all — the identity comes from client.krb5kdc.{crt,key}.
        let certs = format!("{}/e2e/.certs", env!("CARGO_MANIFEST_DIR"));
        if !std::path::Path::new(&format!("{certs}/client.krb5kdc.crt"))
            .exists()
        {
            eprintln!("skipping: no client.krb5kdc cert (old .certs dir?)");
            return;
        }
        let uri = format!(
            "postgresql://krb5kdc@localhost:26257/krb5?sslmode=verify-full\
             &sslrootcert={certs}/ca.crt&sslcert={certs}/client.krb5kdc.crt\
             &sslkey={certs}/client.krb5kdc.key"
        );
        let store = Store::connect(&uri).expect("cert auth should connect");
        assert!(store.get_principal(&uniq("kt-certauth")).unwrap().is_none());
    }

    fn test_store() -> Store {
        // Default matches the secure compose cluster (verify-full TLS,
        // dev password) — so every test run also exercises the TLS path.
        let uri = std::env::var("KDB_CRDB_TEST_URI").unwrap_or_else(|_| {
            format!(
                "postgresql://krb5kdc:krb5kdc-dev-pw@localhost:26257/krb5\
                 ?sslmode=verify-full&sslrootcert={}/e2e/.certs/ca.crt",
                env!("CARGO_MANIFEST_DIR"),
            )
        });
        Store::connect(&uri).unwrap_or_else(|e| {
            panic!(
                "cannot connect to CRDB at {uri} ({e:?}) — \
                 is the compose cluster up? (docker compose up -d)"
            )
        })
    }

    /// Unique per test run so re-runs and parallel tests never collide.
    fn uniq(prefix: &str) -> String {
        use std::time::{SystemTime, UNIX_EPOCH};
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        format!("{prefix}-{}-{nanos}@EXAMPLE.COM", std::process::id())
    }

    #[test]
    fn principal_keydata_roundtrip() {
        let store = test_store();
        let name = uniq("kt-roundtrip");
        let entry = sample_wire_entry(&name);
        let blob = postcard::to_allocvec(&entry).unwrap();

        store.put_principal(&name, &blob).unwrap();
        let fetched = store.get_principal(&name).unwrap().expect("row exists");
        let back = marshal::decode_wire(&fetched).unwrap();

        // The whole point: encrypted key data (what ends up in keytabs)
        // survives the trip through CRDB bit-for-bit.
        assert_eq!(back.keys, entry.keys);
        assert_eq!(back, entry);

        store.delete_principal(&name).unwrap();
    }

    #[test]
    fn principal_key_rotation_upserts() {
        let store = test_store();
        let name = uniq("kt-rotate");
        let mut entry = sample_wire_entry(&name);
        let blob = postcard::to_allocvec(&entry).unwrap();
        store.put_principal(&name, &blob).unwrap();

        // cpw: new kvno replaces the key set; put must overwrite in place.
        entry.keys[0].kvno = 3;
        entry.keys[0].key_bytes = vec![0x42; 34];
        let blob2 = postcard::to_allocvec(&entry).unwrap();
        store.put_principal(&name, &blob2).unwrap();

        let back = marshal::decode_wire(
            &store.get_principal(&name).unwrap().expect("row exists"),
        )
        .unwrap();
        assert_eq!(back.keys[0].kvno, 3);
        assert_eq!(back.keys[0].key_bytes, vec![0x42; 34]);

        store.delete_principal(&name).unwrap();
    }

    #[test]
    fn principal_get_missing_is_none() {
        let store = test_store();
        assert!(store.get_principal(&uniq("kt-missing")).unwrap().is_none());
    }

    #[test]
    fn principal_delete_missing_is_noentry() {
        let store = test_store();
        let err = store.delete_principal(&uniq("kt-del-missing")).unwrap_err();
        assert!(matches!(err, KdbError::NoEntry));
    }

    #[test]
    fn principal_rename_swaps_atomically() {
        let store = test_store();
        let old = uniq("kt-rename-old");
        let new = uniq("kt-rename-new");

        let entry = sample_wire_entry(&old);
        let blob = postcard::to_allocvec(&entry).unwrap();
        store.put_principal(&old, &blob).unwrap();

        // Mirror lib.rs::rename_principal: rewrite the embedded name first.
        let mut wire =
            marshal::decode_wire(&store.get_principal(&old).unwrap().unwrap())
                .unwrap();
        wire.princ_name = new.clone();
        let new_blob = postcard::to_allocvec(&wire).unwrap();
        store.rename_principal(&old, &new, &new_blob).unwrap();

        assert!(store.get_principal(&old).unwrap().is_none());
        let back = marshal::decode_wire(
            &store.get_principal(&new).unwrap().expect("new name exists"),
        )
        .unwrap();
        assert_eq!(back.princ_name, new);
        assert_eq!(back.keys, entry.keys); // key data survives the rename

        // Renaming a nonexistent principal must be NoEntry — and must NOT
        // leave a phantom target row behind (regression: upsert-then-delete
        // committed the upsert even when the source row was missing, and the
        // phantom later resurfaced through dump/load).
        let none_target = uniq("kt-rename-none");
        let err = store
            .rename_principal(&old, &none_target, &new_blob)
            .unwrap_err();
        assert!(matches!(err, KdbError::NoEntry));
        assert!(
            store.get_principal(&none_target).unwrap().is_none(),
            "failed rename left a phantom target row"
        );

        store.delete_principal(&new).unwrap();
    }

    #[test]
    fn principal_iteration_sees_all_rows() {
        let store = test_store();
        let names: Vec<String> =
            (0..3).map(|i| uniq(&format!("kt-iter{i}"))).collect();
        for name in &names {
            let blob =
                postcard::to_allocvec(&sample_wire_entry(name)).unwrap();
            store.put_principal(name, &blob).unwrap();
        }

        let mut seen = Vec::new();
        store
            .iterate_principals(|blob| {
                seen.push(marshal::decode_wire(blob)?.princ_name);
                Ok(())
            })
            .unwrap();
        for name in &names {
            assert!(seen.contains(name), "iteration missed {name}");
            store.delete_principal(name).unwrap();
        }
    }

    #[test]
    fn policy_create_is_create_only() {
        let store = test_store();
        let name = uniq("pol-create");
        store.create_policy(&name, b"blob-v1").unwrap();
        // KADM5 create path must fail on duplicates (unlike put's upsert)...
        assert!(store.create_policy(&name, b"blob-v2").is_err());
        // ...and leave the original row untouched.
        assert_eq!(
            store.get_policy(&name).unwrap().expect("row exists"),
            b"blob-v1"
        );
        store.put_policy(&name, b"blob-v3").unwrap();
        assert_eq!(
            store.get_policy(&name).unwrap().expect("row exists"),
            b"blob-v3"
        );
        store.delete_policy(&name).unwrap();
        assert!(store.get_policy(&name).unwrap().is_none());
    }
}
