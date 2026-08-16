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
        # For multi-node failover, list every local CRDB node in
        # connection_uri (host1:26257,host2:26257,...) — the plugin
        # rotates the order per process and walks the list on reconnect.
        stale_reads_ms = 30000
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
