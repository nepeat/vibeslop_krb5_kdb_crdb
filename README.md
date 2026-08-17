# kdb-crdb

MIT Kerberos KDB backend on CockroachDB **GLOBAL tables**: strongly
consistent, multi-region, with the AS/TGS read path served locally in every
region. Written in safe Rust on [kurbu5](https://codeberg.org/abbra/kurbu5)
(v0.1.2, KDB DAL major version 9, krb5 ≥ 1.21 — kurbu5 itself wants headers
from ≥ 1.22.1).

## Why this shape

The KDC workload is read-dominated: every AS-REQ/TGS-REQ is a
`get_principal`; writes are only kadmin operations and key changes. CRDB
GLOBAL tables trade slow writes for **non-stale local reads in every
region**, which matches that profile exactly. The one thing that breaks the
model is lockout/last-auth writeback, which turns every login into a
cross-region consensus write — so it must be off (below), or split into a
REGIONAL BY ROW side table (klmdb's split-lockout trick, see schema.sql).

Key material is encrypted under the realm master key before it ever reaches
the DAL; the database stores ciphertext only, and each KDC keeps its stash
file locally (default libkdb5 handling — this module doesn't override
`fetch_master_key`). Replay caches remain per-KDC local state as usual, so
the principal DB is the *only* geo-distributed component.

## Layout

```
src/lib.rs      KdbModule impl + kdb_plugin! export (kdb_function_table)
src/marshal.rs  versioned wire codec (postcard) — our own, like every
                in-tree backend (db2/kdb_xdr.c, lmdb/marshal.c)
src/store.rs    postgres client, SQLSTATE 40001 retry loop, paged iteration
schema.sql      multi-region DDL, GLOBAL tables, optional lockout side table
```

## Bring-up

1. Multi-region CRDB cluster, nodes started with `--locality=region=...`.
   Apply `schema.sql` (edit the region list). Issue a client cert for the
   `krb5kdc` SQL user (`cockroach cert create-client krb5kdc`); the plugin
   speaks verify-full TLS and authenticates with `sslcert`/`sslkey` — no
   password needed anywhere.

2. kdc.conf:

```ini
[dbmodules]
    crdb = {
        db_library = kdb_crdb
        connection_uri = postgresql://krb5kdc@localhost:26257/krb5?sslmode=verify-full&sslrootcert=/etc/krb5kdc/ca.crt&sslcert=/etc/krb5kdc/client.krb5kdc.crt&sslkey=/etc/krb5kdc/client.krb5kdc.key
        # non-negotiable for the GLOBAL-table design:
        disable_last_success = true
        disable_lockout = true
        # KDC read-cache TTL in ms (default 1000, 0 = off). Every TGS-REQ
        # does 3 lookups (krbtgt/service/client) over a tiny hot set; the
        # cache turns that DB-latency wall into CPU-bound throughput
        # (~3.5k -> ~8.4k TGS/s on the dev box; stock BDB is ~13.8k).
        # Bounds how late key changes reach a KDC worker; local writes
        # invalidate immediately, kadmind/kdb5_util never cache.
        entry_cache_ms = 1000
        # Degraded-read fallback (KDC role only; 0 = off). On quorum
        # loss, reads retry as bounded-staleness follower reads served
        # by any surviving replica: the realm keeps issuing tickets
        # through node loss and even a full split brain, at most this
        # many ms stale. Writes still (correctly) require quorum.
        # This is ALSO the outage budget, not just a staleness bound:
        # the local resolved timestamp freezes the moment quorum goes,
        # so CockroachDB stops being able to satisfy the read about
        # this many ms later and auth then fails closed rather than
        # serving anything older (measured on the compose cluster:
        # 30000 -> auth held 30.9s, 10000 -> 10.5s; see
        # e2e/staleness-bound.sh). Size it against how long you expect
        # to need to restore quorum.
        # For multi-node failover, list every local CRDB node in
        # connection_uri (host1:26257,host2:26257,...) — the plugin
        # rotates the order per process and walks the list on reconnect.
        stale_reads_ms = 30000
        # Cold-start resilience (see "Surviving a database outage").
        # Budget in ms for the FIRST connection: retried with capped
        # backoff (250ms doubling to 2s) instead of exiting, so a daemon
        # that starts a few seconds ahead of the database waits instead
        # of crash-looping. 0 (default) = fail fast, as before. The same
        # budget, capped at 2s, bounds per-request reconnects.
        startup_retry_ms = 30000
        # Offline last-known-good entry cache, KDC role ONLY, off unless
        # BOTH are set (setting one alone is a config error). Lets a KDC
        # restart and serve AS/TGS with the database entirely gone —
        # bounded-staleness reads cannot, because a NEW SQL session to a
        # quorum-less node cannot be established at all. Entries older
        # than the max age are refused, not served. Read the threat model
        # before enabling: this file is as sensitive as a db2 principal
        # file, and a disabled principal keeps authenticating from it for
        # up to max_age during a full outage.
        offline_cache_path = /var/lib/krb5kdc/crdb-offline.cache
        offline_cache_max_age_ms = 3600000
    }

[realms]
    EXAMPLE.COM = {
        database_module = crdb
    }
```

3. Install `kdb_crdb.so` into the krb5 plugin dir
   (e.g. `/usr/lib64/krb5/plugins/kdb/`), then:

```sh
kdb5_util create -s        # stash file is local; principals go to CRDB
systemctl start krb5kdc kadmind
```

Point each region's KDCs at a local CRDB node/LB; DNS SRV or
`kdc = ` entries fan clients out per region as usual.

## Semantics & invariants

- **get/put/delete**: single-statement, serializable, retried on 40001.
- **rename**: upsert-new + delete-old in one explicit transaction; the wire
  blob's embedded canonical name is rewritten first. No region can ever
  observe both names or neither.
- **iterate**: keyset-paginated full scan (dump, listprincs).
- **lock/unlock**: no-ops (like klmdb) — per-txn atomicity replaces BDB's
  whole-file locks. `kdb5_util dump` therefore isn't a single snapshot
  across pages; if you want that, run the scan `AS OF SYSTEM TIME` pinned
  to one timestamp (fine for dumps — it's a backup, not the auth path).
- **create (SUPPORTS_CREATE)**: implemented as open + install (libkdb5
  requires the vtable slot or `kdb5_util create` fails with
  KRB5_PLUGIN_OP_NOTSUPP), but it runs **no DDL**. Schema creation is
  `schema.sql`'s job, deliberately — DDL from inside a KDC plugin is a
  footgun.

## Surviving a database outage

Three layers, each covering what the one above it cannot:

| layer | knob | covers | bound |
|---|---|---|---|
| entry cache | `entry_cache_ms` | DB latency | 1s of staleness |
| bounded-stale reads | `stale_reads_ms` | quorum loss, split brain, **while the process keeps running** | ~`stale_reads_ms` of outage |
| offline cache | `offline_cache_path` + `offline_cache_max_age_ms` | **restart** during an outage — power loss, rolling reboot, OOM kill, node replacement | `offline_cache_max_age_ms` |

The middle layer has a hard limit that is not obvious: it only works on
an **existing** SQL session. Establishing a *new* session against a
quorum-less CockroachDB node is architecturally impossible — session
setup writes (`sqlliveness`, descriptor leasing) — so a KDC that restarts
mid-outage has nothing to read, no matter how it connects. That is the
gap the offline cache fills, and the reason `startup_retry_ms` alone is
not enough.

**What is cached**: the raw wire blobs exactly as stored in the
`principals` table, keyed by principal name, plus the `aliases` rows a
lookup needed, plus a written-at stamp per row. Fed only by successful
KDC-role reads — it is a cache of what this KDC actually served, not a
replica. Flushed with an atomic tmp+rename+fsync at most once per 10s,
piggybacked on the request flow (no background thread: a KDC worker is
one synchronous loop). `krb5kdc -w N` workers share the path and merge
newest-stamp-wins, so they converge on the union of what the fleet read.
A corrupt or unreadable cache file is logged and started empty; it can
never keep the database from opening.

**Threat model.** Key material inside the blobs is already encrypted
under the realm master key before it reaches the DAL, so the file is in
the same on-disk sensitivity class as a db2/LMDB principal database, and
strictly weaker than one: it never contains the stash. An attacker who
steals it gets what they would get from stealing `principal.db` **minus**
the stash file — encrypted keys plus principal metadata (names,
expiries, attributes, TL-data). Without the master key that is an
offline-attack target of the same strength as the ciphertext already
sitting in CockroachDB. Keep it 0600 (the plugin writes it that way) on
storage you already trust with the stash, and destroy it with the same
care.

**Staleness is a revocation window.** During a full outage the KDC will
keep authenticating a principal that was disabled, deleted, or had its
password changed, for up to `offline_cache_max_age_ms` after the last
time it read that principal — the cache cannot learn about a change it
cannot see. Size the knob as "how long am I willing to honour a
revocation late in exchange for staying up", not as "how long might my
database be down". Lockout and last-auth counters are already required to
be off for this backend, so no security counter depends on read freshness
either way.

**Fail-closed everywhere else.** Writes never touch the cache and keep
failing without quorum. kadmind and kdb5_util never read it (admin
decisions must never rest on data that did not come from a live, quorate
database). Entries past the max age are refused rather than served. And a
*miss* while offline returns `KDC_ERR_SVC_UNAVAILABLE`, never
"principal unknown": the cache is partial by construction, and a partial
cache that answered misses with NOENTRY could tell a client that a
principal which exists does not.

## Running as a kprop/iprop replica (opt-in)

The cluster can act as a **replica of an external MIT krb5 primary**
(db2/LDAP/whatever): full `kprop` dumps land atomically-enough via staging
tables, and `kpropd`'s iprop polling applies incremental updates between
them. Main use cases: **migrating a production realm onto this backend**
(replicate continuously, verify, then cut over) and **bulk-loading an
exact copy of a realm for testing** (a dump load carries the real key
material, unlike re-creating principals with kadmin).

This is the single most dangerous thing the plugin can do — a full prop
**replaces the entire realm, cluster-wide, in every region** — so it is
gated behind three independent keys, all required:

1. `prop_receiver = kprop|iprop` in the receiver host's `[dbmodules]`
   stanza (default `off`; `iprop` also covers plain kprop loads).
2. The operator marker row, created only by explicit SQL:
   `UPSERT INTO prop_control (singleton, enabled, mode) VALUES (true, true, 'iprop');`
3. The `krb5prop` SQL identity (client cert) — the only user with DML on
   the staging tables. Provision it solely on the kpropd host.

With any key missing, `kdb5_util load` is refused **before the first
write** (the historic EINVAL behavior is bit-identical when the knob is
off). Mechanics, verified against MIT 1.22.2 end-to-end
(`e2e/kprop-replica.sh`):

- A gated load streams the dump into `principals_staging`/
  `policies_staging` (REGIONAL — no GLOBAL commit-wait per record; the
  live tables serve every KDC untouched throughout). `promote_db` then
  **diff-syncs**: batched upserts of new/changed rows first, deletes of
  absent rows last — a KDC mid-promote sees old-or-new entries, never a
  hole, and a routine re-prop where almost nothing changed writes almost
  nothing. Deliberately *not* one atomic flip (a realm-sized txn is a
  multi-hundred-MB intent set); the bounded old-or-new window matches
  what iprop incrementals produce anyway.
- A single-receiver **lease** in `prop_control` makes concurrent kpropds
  structurally impossible; an aborted load leaves live data untouched
  and the next load clears staging first.
- **Write-freeze**: while the marker is enabled, kadmind/kdb5_util
  writes from everyone except the receiver are refused (EPERM) — a
  replica realm is read-only outside the propagation stream, because any
  local write would be silently destroyed by the next full resync.
  Promote-to-primary = `UPDATE prop_control SET enabled = false` (drops
  the freeze, pushes start being refused again).
- The replica KDC needs the **primary's master key stash** — the dump is
  ciphertext under the primary's K/M, byte-for-byte.
- iprop notes: `iprop_port` is required on both sides once
  `iprop_enable = true`; the replica ulog is a local file managed by
  libkdb5 (no backend involvement); MIT does not propagate policy
  *changes* incrementally (full props carry policies). Being an iprop
  **master** stays unsupported — this cluster is the end of the chain,
  it is already its own multi-region replication.

Measured on the compose cluster: 527-principal bootstrap push in 4 s
end-to-end; 2,063 in 14 s (~150/s — bound by kdb5_util's serial per-row
round-trips into staging, not by promote); re-push over a live realm in
4 s with an auth canary looping through it, zero failures; incremental
addprinc/cpw/delprinc visible on the replica within the 2 s poll.

## Known gaps / TODO

- ~~TLS is stubbed~~ Fixed: TLS with chain + hostname verification is the
  default; only an explicit `sslmode=disable` connects plaintext, and
  `sslrootcert=` is honored. There is deliberately no "encrypted but
  unauthenticated" mode. Client-cert auth via `sslcert=`/`sslkey=`
  (PKCS#1 keys from `cockroach cert` are re-encoded automatically) keeps
  the SQL password out of kdc.conf entirely.
- ~~Alias/referral `LookupFlags` ignored~~ Fixed: operator-managed
  `aliases` table (see schema.sql); in-realm aliases resolve for AS and
  TGS lookups, out-of-realm canonical names are referrals gated on
  `KRB5_KDB_FLAG_REFERRAL_OK`.
- ~~Policy TL-data dropped on write~~ / ~~`has_salt` inferred~~ Fixed via
  two additive kurbu5 accessor patches (`patches/`, applied to the
  vendored tree under `vendor/kurbu5`, pending upstreaming): policy
  TL-data round-trips (wire v2, v1 still decodes) and `has_salt` reads
  the real `key_data_ver`.
- kurbu5's KDB glue bridges synchronously; their roadmap lists async
  `KdbModule` — if that lands, `store.rs` can move to tokio-postgres +
  connection pooling.
- Add a `kdb5_util dump`-vs-restore round-trip test realm in CI (kurbu5's
  own test suite layout in `contrib/ci` is a good template).
