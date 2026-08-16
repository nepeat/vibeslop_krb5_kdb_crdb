# Progress log

Running log for agent work on kdb-crdb. Append dated entries; don't rewrite
history. See ../CLAUDE.md for project goals and conventions.

## 2026-07-11

- Repo bootstrapped: `lib.rs` (KdbModule impl), `marshal.rs` (postcard wire
  codec), `store.rs` (postgres client + retry loop), `schema.sql`
  (multi-region GLOBAL tables), `Cargo.toml`, `README.md`.
- Added `CLAUDE.md` with project goals and conventions, and this log.
- Not yet done: no test suite, TLS still stubbed as `NoTls`, no
  docker-compose file for a local multi-region CRDB cluster.
- Next step: stand up a docker-compose CRDB cluster for local dev/test,
  then write an integration test that exercises get/put/delete/rename/
  iterate against it.

## 2026-07-11 (later): dev env + CRDB integration tests

- Moved sources into `src/` (Cargo layout; they were sitting at repo root
  and nothing compiled).
- Added `flake.nix` dev shell (per user: **flakes, not shell.nix**), pinned
  to nixpkgs-unstable via `flake.lock`. Needed because kurbu5 0.1.2 requires
  krb5 >= 1.22.1 headers (`krb5_db_load_module` missing from 1.21's kdb.h —
  stable nixpkgs' 1.21.3 fails the build). Shell provides openssl,
  krb5 1.22.2, libclang + `BINDGEN_EXTRA_CLANG_ARGS` (bindgen doesn't see
  the cc-wrapper's include paths). `nix develop --command cargo build`
  builds the cdylib clean.
- Added `docker-compose.yml`: 3-node CRDB (cockroachdb/cockroach:latest-v25.2)
  with `--locality=region={us-west2,us-east1,europe-west4}` matching
  schema.sql, plus a one-shot `roach-init` that runs `cockroach init` and
  applies `schema.sql`. Multi-region DDL (PRIMARY REGION, LOCALITY GLOBAL)
  applies without license trouble on v25.2. SQL on localhost:26257/26258/26259
  (west/east/eu), admin UI on 8081 (8080 was taken on this box).
- Test suite (first one): `cargo test` runs unit tests in `marshal.rs`
  (postcard wire round-trip incl. key data, version rejection) and
  integration tests in `store.rs` against the compose cluster
  (`KDB_CRDB_TEST_URI` overrides the default localhost:26257 insecure URI).
  Covers: **key-data put/get round-trip (the keytab material — bit-for-bit)**,
  key-rotation upsert, get-missing → None, delete-missing → NoEntry, rename
  (blob name rewrite + atomic swap + NoEntry case), keyset-paginated
  iteration, policy create-only/put/get/delete. 10/10 pass; store suite also
  passes pointed at the us-east1 node (26258), i.e. writes are readable from
  every region as designed.
- Derived `Debug/Clone/PartialEq/Eq` on `WireKey`/`WireEntry` for the tests.
- Still open: TLS still `NoTls`; no real krb5kdc/kadmind in compose yet
  (that's the "functional" bar); marshal `decode_entry`/`encode_entry`
  (KdbContext paths) untested — needs a real krb5 context, which points at
  the same next step.
- Next concrete step: add krb5kdc + kadmind containers (nix or distro pkgs
  + the built kdb_crdb.so) to docker-compose and script `kdb5_util create`,
  `kadmin.local addprinc/ktadd`, `kinit` smoke test end-to-end.

## 2026-07-11 (later still): end-to-end kadmin/ktadd/kinit PASSES

- `e2e/run.sh` (+ `krb5.conf.in`/`kdc.conf.in` templates): runs a real
  krb5kdc + kadmind from the pinned nix krb5 1.22.2 (same libkdb5 the
  plugin links) directly on this box against the compose CRDB cluster —
  no KDC container needed after all. Unprivileged ports (KDC 10088,
  kadmind 10749). DESTRUCTIVE: truncates principals/policies first.
  Flow: cargo build → kdb5_util create -s → start daemons →
  network kadmin addprinc alice + addprinc -randkey host/… + ktadd →
  kinit alice (AS-REQ) → kvno host/… (TGS-REQ) → kinit -kt keytab.
  **All steps pass.** The full get/put path through KdbContext
  (marshal encode/decode_entry) is now exercised by real krb5 daemons.
- Two fixes needed to get there:
  1. libkdb5 ignores `plugin_base_dir` for KDB modules — it loads from
     `db_module_dir` in `[dbmodules]` (kdc.conf). Set in the template.
  2. `kdb5_util create` calls the `create` vtable slot; a NULL slot is
     KRB5_PLUGIN_OP_NOTSUPP and bootstrap dies (README's old claim that
     create "initializes via open + puts" was wrong). Implemented
     `SUPPORTS_CREATE = true` + `create()` = open + `ctx.set_module()`
     (the klmdb contract per kurbu5 docs) in lib.rs.
- `cargo test` still 10/10 after the change.
- Still open: TLS (`NoTls`), alias/referral LookupFlags, policy tl_data,
  `has_salt` inference — see CLAUDE.md gaps.
- Next concrete step: TLS (postgres-native-tls + verify-full, secure-mode
  compose with certs), then start looking at read QPS on get_principal
  (e.g. prepared statement caching) per the project goal ordering.

## 2026-07-11 (afternoon): rename bug, load/destroy semantics, stress + backend validation

- **Real bug found & fixed** in `store::rename_principal`: it ran
  UPSERT-new *then* DELETE-old in one txn and only checked the delete
  count after commit — renaming a *nonexistent* principal committed a
  phantom target row (with a mismatched embedded blob name, which then
  resurfaced under a *third* name via dump → load -update). Discovered
  via stray `kt-rename-*` rows in a dump/load experiment. Fix: DELETE
  first, roll back and return NoEntry when it matches nothing. Regression
  assert added to `principal_rename_swaps_atomically`.
- `kdb5_util load` (plain) footgun guarded: `open()` now rejects the
  `temporary` db_arg with EINVAL, so plain load fails *before* streaming
  a dump into the live GLOBAL tables (it used to die only at promote_db,
  after overwriting). Restores: `load -update` (verified working) or
  CRDB-native BACKUP/RESTORE. Verified: dump ok, plain load fails clean
  with live rows untouched, destroy is a safe no-op.
- `destroy`/`promote_db` implemented as deliberate no-ops (user call):
  a shared multi-region realm must not be vaporizable from one admin
  box, and the plugin never issues DDL; data removal is operator SQL.
- `e2e/run.sh` grew: backend validation (kdb_crdb.so mapped in both
  daemons, no db2/klmdb/kldap loaded, no local principal* files,
  SQL-delete-then-kinit-fails canary proving reads hit CRDB) and a
  stress phase (STRESS_N=1024 users + 1024 hosts via one batched
  kadmin.local session, row-count check, >512-row paged listprincs,
  spot AS/TGS/keytab checks).
- `e2e/full-cycle.sh`: the whole thing from a clean slate — compose
  down -v → up → wait for schema → cargo test → e2e/run.sh.

## 2026-07-11 (evening): TLS everywhere + 100 QPS goal → 787 QPS

- **Write-speed fixes** (stress was ~1.4 addprinc/s): (a) 32 parallel
  kadmin.local workers — GLOBAL commit-wait is latency, not throughput;
  (b) dev-only `kv.closed_timestamp.lead_for_global_reads_override=25ms`
  (set by run.sh; `TRUE_LATENCY=1` disables). 25min stress phase → ~5s
  (435/s creates).
- **QPS instrumentation**: every phase appends TSV to `e2e/qps.log`
  (time, git rev, phase, n, secs, rate). Baseline vs now in that file.
- **TGS 100 QPS goal**: profiling showed the 42.8/s baseline was a
  client artifact — FILE ccache grows per ticket and re-parse dominates
  (64 reqs: 86/s small cache vs 47/s at ~470 tickets). Server was never
  the bottleneck (148/s vs single krb5kdc). Now: `krb5kdc -w 4` (workers
  each hold own CRDB conn) + 16 parallel kvno clients over 1024 tickets:
  **787.7/s measured; run.sh FAILS below `TGS_TARGET_QPS` (100)**.
  Serial latency tracked separately (75/s ≈ 13ms incl. client).
- **TLS done** (the big "safe" gap): `store.rs` now only skips TLS on
  explicit `sslmode=disable`; anything else = native-tls with chain +
  hostname verification (verify-full semantics), `sslrootcert=` parsed
  out of the URI (rust-postgres doesn't know it), fail-closed on missing
  cert. No unauthenticated-encryption mode, on purpose. Reconnect path
  reuses the connector. `tls_uri_parsing` unit test added (11 tests now).
- **Compose cluster is secure-mode now**: `roach-cert` one-shot generates
  CA/node/client certs into `e2e/.certs` (gitignored), nodes refuse
  plaintext, roach-init sets dev passwords (root-dev-pw/krb5kdc-dev-pw),
  all host access is password over verify-full TLS. e2e asserts
  `sslmode=disable` is *rejected* by the cluster. cargo test default URI
  is the secure one, so unit runs exercise TLS too.
- **Nix gotcha**: plugin's new openssl dep broke dlopen under nix's
  loader (no system ld cache) — flake now sets RUSTFLAGS rpath to the
  nix openssl. Symptom was the misleading "plugin symbol
  'kdb_function_table' not found".
- Full clean-state cycle green end to end (exit 0): 11 cargo tests,
  kadmin/ktadd/kinit/kvno, no-BDB/LMDB validation, SQL-canary, TLS
  enforcement, 2048-principal stress, QPS assert.
- Still open: alias/referral LookupFlags, policy tl_data (kurbu5
  upstream), `has_salt` inference, client-cert auth for the plugin
  (password-over-TLS now; cert auth would drop the password from
  kdc.conf), maybe prepared-statement caching if read QPS ever matters
  beyond this.

## 2026-08-16: client-cert auth (no more password in kdc.conf)

- **Cert auth done**: `store.rs` now consumes `sslcert`/`sslkey` from the
  URI and presents them as the TLS client identity (native-tls). Half a
  keypair is EINVAL (fail closed, no silent fallback to password).
  `cockroach cert create-client` emits PKCS#1 keys but native-tls only
  takes PKCS#8, so the key is re-encoded via the openssl crate (already
  linked through native-tls — new direct dep in Cargo.toml, no new
  native dep). compose `roach-cert` now also creates
  `client.krb5kdc.{crt,key}` (own idempotence guard since old .certs
  dirs predate it; key chmod 644 = DEV ONLY). `e2e/kdc.conf.in` switched
  to cert auth — **no secret in the config file**. Tests: 12 now
  (parse_tls cases for cert/key pairing + live no-password connect).
- **GOTCHA found the hard way — CRDB license throttling**: the July
  cluster's data volumes were a month old; CRDB v25.2 without a license
  throttles concurrently open transactions (SQLSTATE XXC02, "No license
  installed") once the grace period lapses. Symptom: serial e2e phases
  pass, the 32-worker stress phase fails ~2/3 of creates with plain
  "Input/output error" (our EIO mapping hides the SQLSTATE — worth a
  debug-log hook someday). Fix for dev: recreate the cluster
  (`docker compose down -v`, or just run `e2e/full-cycle.sh`), which
  resets the grace period. A registered CockroachDB Free license would
  fix it properly; not done (needs signup).
- Full clean-slate cycle green end to end with cert auth (12 cargo
  tests + full e2e incl. stress and QPS assert).
- Still open: alias/referral LookupFlags, policy tl_data + `has_salt`
  (kurbu5 upstream), dump-vs-restore round-trip in CI, prepared-statement
  caching (optional).

## 2026-08-16 (later): aliases, kurbu5 patches, 1000+ QPS — implementation complete

User direction: finish everything except the dump/restore round-trip test
(explicitly excluded); caching/perf now REQUIRED with a 1000+ TGS QPS
floor; explain kurbu5 patches before implementing.

- **Prepared-statement caching** (`store.rs`): Client is now wrapped in a
  `Conn { client, stmts: HashMap }`; every point query goes through a
  per-connection prepared-statement cache (rust-postgres re-prepares
  unnamed statements on every text call, so this removes parse/describe
  from the hot path). Cache drops with the connection on reconnect.
- **QPS**: e2e defaults now `krb5kdc -w 8` + 32 parallel kvno clients;
  `TGS_TARGET_QPS` default raised 100 → 1000 (run.sh FAILS below it).
  Measured: 1706.7/s (warm cluster), 2048.0/s (fresh cluster full cycle).
  Serial TGS latency ~95/s (unchanged — that's per-request latency).
- **Aliases/LookupFlags** (`lib.rs`, `schema.sql`): new operator-managed
  `aliases` table (GLOBAL, SELECT-only for krb5kdc; no kadmin verbs, like
  kldap's LDAP-side aliases). get_principal: exact match, then alias
  lookup; in-realm aliases always returned (entry carries canonical name,
  KDC decides), out-of-realm canonical = referral, only followed with
  KRB5_KDB_FLAG_REFERRAL_OK. e2e: TGS via alias, AS via alias with -C
  (canonicalizes) and without (krb5 >= 1.20 issues under requested name —
  first test expectation was wrong), out-of-realm alias correctly refused.
- **kurbu5 vendored at main b52c19e** (user request; was tag v0.1.2) into
  `vendor/kurbu5` + Cargo `[patch]`, commit recorded in
  `vendor/kurbu5/.vendored-commit`. kdb crate delta vs 0.1.2 was tiny
  (c_char cast, changelogs, version 0.1.3); big changes are kurbu5-rs
  preauth/principal APIs we don't call.
- **Two accessor patches applied to the vendor tree** (in `patches/`,
  explained to user before implementing, NOT yet sent upstream):
  0001 `PolicyEntry::tl_data()` getter → policy TL-data now round-trips
  (policy wire v2 with trailing tl_data; v1 blobs still decode — see
  `decode_policy` version dispatch + `policy_v1_blob_still_decodes` test).
  0002 `KeyDataRef::key_data_ver()/has_salt()` → `has_salt` now read from
  the entry instead of inferred from salt presence.
- Tests 12 → 14 (policy tl_data round-trip, v1 back-compat). Full clean
  cycle green: 14 cargo tests + full e2e incl. alias suite and the
  1000 QPS gate.
- Next: send patches/ upstream to kurbu5 (codeberg), then re-pin to a
  released tag and drop vendor/. Excluded by user: dump/restore CI test.

## 2026-08-16 (evening): 8.4k TGS QPS (target was 4-5k for 200K machines)

User goal: ≥2x the 2k number, sized for 200K machines / 4-5k QPS worst
case. Landed at ~8k-8.4k measured, gate raised to 4000.

- **Bench honesty first**: kvno-based parallel load was benchmarking
  fork/exec + FILE-ccache re-parse, not the KDC. New `e2e/tgsbench.c`:
  N threads hot on krb5_get_credentials(KRB5_GC_NO_STORE), per-thread
  MEMORY ccache (the shared FILE cc takes an fcntl lock per read and
  serializes threads). qps.log phase renamed read_tgs_kvno_parallel →
  read_tgs_bench (numbers not comparable).
- **Bottleneck hunt** (numbers on this 16-core box, 3-node docker CRDB):
  2.2k/s w/ kvno load → 3.5k/s w/ tgsbench, plateaued regardless of
  -w 16/32/48; nothing CPU-bound (workers ~19%, CRDB ~1 core). Cause:
  every TGS-REQ = **3 sequential get_principal round-trips** (measured
  3.00 SELECTs/req via crdb node_metrics; names via temp debug print:
  krbtgt/REALM, service, client — client lookup is the 1.20+ PAC path),
  at ~1.4ms p75 per SELECT under load (CRDB service latency histogram).
  Sync round-trips × single-threaded workers = latency wall.
- **Fix: per-process TTL entry cache in lib.rs** (`EntryCache`), KDC
  role ONLY (kadmind/kdb5_util never cache — read-modify-write must stay
  fresh). `entry_cache_ms` profile/db_args knob, default 1000, 0=off.
  Local writes invalidate; cross-worker staleness bounded by TTL; misses
  never cached; 64k-entry coarse wipe bound. e2e canary now sleeps 1.2s
  after the SQL delete (staleness contract made explicit in kdc.conf.in).
- **Results** (tgsbench 128 threads / 65k reqs, err=0 everywhere):
  16 workers 8196/s, 32 workers 7744/s → now CPU-bound like stock;
  KDC_WORKERS default stays 16. Full-cycle fresh cluster: 8402/s.
  Serial latency 94.8 → 134.7/s (krbtgt+client now cache hits).
- **Stock-krb5 baseline** (subagent, same box/bench, db2 backend):
  13.8k/s at -w 16, 9.9-10.1k/s at -w 32. So kdb-crdb is now at ~60% of
  stock BDB while being strongly consistent + multi-region. Remaining
  gap = residual cache-miss SELECTs (each worker refetches each hot
  entry once per TTL) + AES vs file-read cost.
- Headroom if ever needed: longer TTL, multi-host connection_uri with
  per-process gateway spread across CRDB nodes, kurbu5 async KdbModule.
- For the 200K-machine sizing: worst case 4-5k QPS is met 2x over on ONE
  16-core dev box also running the whole 3-node cluster; production
  regions add KDCs horizontally (shared-nothing except CRDB).

## 2026-08-16 (night): deployed to sea1 kubernetes (ns tmp-crdb-krb5)

Everything under k8s/ (manifests + secrets material, .gitignore-grade
files chmod 600: .registry-pass, .master-pass, .admin-pass, .crdb-certs/,
.bootstrap/). Cluster: 3x Talos metal (72 cores / 754Gi / 1.8T NVMe).

- **Registry**: Talos containerd refuses plain-HTTP registries and we
  have no machine-config access, so the dev-box registry idea was
  replaced by an in-cluster one: registry:2 + ceph-rbd PVC behind
  traefik at registry-tmp-crdb.owo.me (cert-manager letsencrypt-genprog,
  cloudflare-proxied OFF — CF proxy caps layer uploads), htpasswd auth
  (creds k8s/.registry-pass, k8s secret "regcred" for pulls). Push from
  dev box with skopeo (dockerd would need insecure-registry config;
  skopeo doesn't).
- **CRDB**: official Helm chart, release "crdb", 3 nodes (chart
  anti-affinity put one per metal node), TLS self-signer,
  storage local-path (node NVMe /var/mnt/data), 200Gi each,
  locality region=sea1. Schema: k8s/schema-sea1.sql (single region, no
  SURVIVE REGION FAILURE — needs >=3 regions; tables stay GLOBAL).
  krb5kdc SQL user + client cert signed from the chart CA secret
  (cockroach cert via docker; chart CA lifetime forced --lifetime=8760h).
- **KDC image**: nix closure (krb5 1.22.2 + openssl + bash, 118MB) +
  target/release/libkdb_crdb.so at /opt/kdb, FROM scratch →
  registry-tmp-crdb.owo.me/kdc:v1. Same store paths as the dev bench.
- **Realm bootstrap from the dev box**: kubectl port-forward to
  crdb-public + local kdb5_util create -s (chart node certs include
  localhost SAN, so verify-full works through the forward). Stash →
  secret kdc-stash; admin/admin created (pw k8s/.admin-pass).
- **KDCs**: k8s/kdc.yaml — Deployment x3, REQUIRED podAntiAffinity on
  kubernetes.io/hostname (verified 1 pod per node), krb5kdc -n -w 16,
  unprivileged 8888 with Service kdc:88, entry_cache_ms=1000, kadmind x1
  (service kadmind:749). PodSecurity "restricted" satisfied (nonroot,
  no caps, seccomp). Smoke: kinit admin/admin via the kdc Service issued
  a TGT (AS_REQ ISSUE in pod logs).
- Gotchas hit: kubectl port-forward dies between shells (plugin EIO =
  connection refused — restart it before blaming TLS); registry:2 needs
  htpasswd secret BEFORE deploy; PodSecurity is warn-only here but
  manifests comply anyway.
- Next: in-cluster tgsbench pod(s) for a cluster-scale QPS run
  (provision principals through kadmind or direct SQL), then a
  Grafana/monitoring pass, then teardown or keep as demo realm.

## 2026-08-16 (late night): 262k burn-test principals + cluster perf numbers

Dataset (user spec): 4 /16s of host/A.B.C.D principals = **262,144**
(host/10.100.0.0 … host/10.103.255.255), created with -randkey via
parallel kadmin.local in the loadgen pod (k8s/loadgen.yaml, image kdc:v3
= v1 + tgsbench + coreutils/grep/gawk; kadmin.local needs `-p` in this
image — no /etc/passwd for uid 1000). Row count verified via SQL.

**Write performance** (creates/s, kadmin.local addprinc -randkey):
| config                                   | 32 workers | 128 workers |
|------------------------------------------|-----------:|------------:|
| GLOBAL table, cluster defaults           |       39/s |     (~150)  |
| GLOBAL + lead_for_global_reads=25ms      |      891/s |     3,560/s |
| REGIONAL BY TABLE, defaults              |    3,978/s |         —   |
- Default GLOBAL write latency ≈ 820ms/op = the commit-wait, exactly as
  README warns. The 25ms override is THE bulk-load lever (full 262k load
  ran at **4,045/s sustained, 64.8s total**). REGIONAL matches it with no
  override — on a single-region cluster GLOBAL buys nothing for reads
  and costs writes; multi-region prod is where GLOBAL earns its keep.
- Gotcha: first REGIONAL measurement (86/s) was garbage — taken during
  post-ALTER replica rebalancing. Re-measure after zone-config jobs
  settle. (Raw UPSERT sanity check: 5-12ms.)
- Cluster restored to prod shape afterwards: LOCALITY GLOBAL, override
  RESET, test ranges (10.96-99, tmp-*) deleted. 262,149 rows total.

**Read performance** (tgsbench ip:10.100 mode, random over all 262k —
service-entry cache hit rate ~1%, so ~1 real CRDB read per TGS):
- 1 bench pod → kdc Service (UDP): 3,657/s, and per-pod TGS counts were
  18k/0/10k — cilium UDP flows do NOT spread evenly, and one KDC pod
  carried most load at only ~0.8 cores (16 workers latency-bound).
- Fixes: krb5kdc -w 16 → 48 (I/O-bound workers; also needed
  maxSurge=0/maxUnavailable=1 — a surge pod can never schedule with
  required anti-affinity on 3 nodes), bench pinned per-KDC via 3
  krb5.confs (what DNS SRV does for a real fleet).
- Result: **40,577 TGS/s aggregate, 196,608 requests, err=0**
  (3 × 128 threads, one tgsbench per KDC pod).
- krb5.conf gotcha: `REALM = { kdc = x }` on one line is invalid profile
  syntax and fails every request instantly; the brace needs newlines.

Verdict vs the 200K-machine / 4-5k QPS worst case: cluster serves ~8-10x
that with 3 KDC pods, and writes can bulk-load a full fleet's keytabs in
about a minute with the override set. Left running: loadgen pod, bench
user (bench/bench-pw), KDCs at -w 48.

## 2026-08-16 (later still): chaos suites — auth survives quorum loss & split brain

New plugin capability: **degraded-read fallback** (`stale_reads_ms`, KDC
role only, default off). When primary reads fail (quorum loss), reads
retry as CRDB bounded-staleness follower reads
(`AS OF SYSTEM TIME with_max_staleness('Xms', true)`) — servable by any
live replica, no quorum. A circuit breaker (5s hold) routes straight to
stale reads while degraded so QPS doesn't die on statement_timeouts
(1.5s, set on KDC conns only). kadmind/kdb5_util never see stale rows.
Second capability found necessary on k8s: **multi-host connection_uri**
(host1,host2,host3) with per-process rotation — first chaos run FAILED
phase 2 because quorum loss makes every CRDB pod unready, the public
Service empties, and reconnects had nowhere to go. Fix: kdc.conf lists
all three pod DNS names (headless svc resolves regardless of readiness)
+ connect_timeout=3; plugin rotates order per process (spreads gateways)
and reconnect walks the list. Tests: 16 cargo (rotation, stale-path).

**Codified suites**:
- `e2e/chaos.sh` (compose; now step 5 of full-cycle.sh): baseline → 1
  node down → 2 down (quorum gone) → recovery. Asserts kinit+kvno each
  phase, QPS floor (CHAOS_QPS_FLOOR, default 1000), writes REFUSED
  without quorum, writes recover after. Results: 7264/s one-down,
  2892/s quorum-lost (single compose node).
- `k8s/chaos-test.sh` (metal; CHAOS_QPS_FLOOR default 4000): same
  phases via sts scaling, PLUS **split brain** — k8s/split-brain-netpol
  .yaml isolates every CRDB pod from its peers (clients still reach all
  three, no node has quorum). Results (48w KDCs, v5 image):
  baseline 37,195/s · one-down 36,850/s · quorum-gone single CRDB node
  9,186/s · split-brain 8,713/s — all err=0, writes refused while
  degraded, clean recovery + writes after heal.

Gotchas: k8s conntrack keeps established conns alive after endpoints go
unready — do NOT rely on it, that's what multi-host is for; sts
scale-down is instant but scale-up needs wait_crdb_ready before write
asserts; chaos pod scripts need `set -e` or failures masquerade as OK
(first run "passed" auth with a dead ccache).

## 2026-08-16 (wee hours): ansible/ — multi-region CRDB deploy playbook

New `ansible/` tree: deploys + clusters CRDB across regions on plain
hosts (systemd path — deliberately NOT multi-cluster k8s; see the
tooling discussion: the new CockroachDB operator can't span k8s
clusters yet, and VMs are operationally simpler for a fixed-size DB).
**Inventory hostvars ARE the topology**: crdb_region/crdb_zone drive
--locality, cross-region --join seeds (2 per region, by IP — no
cross-region DNS needed), and the schema DDL is TEMPLATED from the
inventory (PRIMARY REGION / ADD REGION IF NOT EXISTS per region /
SURVIVE REGION FAILURE when >= 3 regions) — adding a region = adding
hosts + re-run. Roles: crdb_certs (controller-local CA via `cockroach
cert`, per-node + client.root + client.krb5kdc certs; per-host include
because create-node always writes node.crt — a plain loop clobbers all
but the last), crdb_node (binary, certs, systemd unit, NTP assert),
crdb_init (idempotent init + liveness wait), crdb_schema (render+apply+
verify SHOW REGIONS). site.yml ends with an under-replicated-ranges
gate; upgrade.yml does serial drain/upgrade/restart. render-test.yml
smoke-renders join/locality/DDL with no remote connections — validated
against the 3x3 example inventory; both playbooks pass syntax check.
Not yet: real end-to-end run (needs VMs or a docker-as-hosts molecule
rig), decommission playbook, backups. Certs land in ansible/secrets/
(CA key — vault it).

## 2026-08-16 (later): terraform/hcloud substrate + docs/runbooks.md

- **terraform/hcloud/**: 9x Ubuntu 24.04 (topology var: fsn1/nbg1/hel1
  x3, cpx41) with ONE private network across all three locations (all
  eu-central zone — CRDB never touches public net; firewall = SSH+ICMP
  only), spread placement groups per region (3 nodes = 3 physical
  hosts), cloud-init (chrony, containerd, python3, sysctls), and
  generated ansible/inventory/hcloud/ (public IP = ansible_host,
  private IP = crdb_advertise, location = crdb_region). tofu validate
  clean; local.nodes/cidrhost math verified via console (10.90.<r>.1x).
  Apply needs HCLOUD_TOKEN (not present on this box yet). ~$0.55/hr
  fleet at defaults; README covers tc-netem fake-WAN trick.
- SCRAPPED 2026-08-16: terraform/hcloud (user's Hetzner account is
  capped at 5 servers; we need 9). Replaced by ansible/aws/ — see next
  entry. The tc-netem fake-WAN trick from its README still applies
  anywhere.
- **docs/runbooks.md** (subagent): add node / add region / replace-or-
  remove node (yes: cockroach node decommission; add-then-decommission
  for replace; dead-node flow for hardware loss). Agent review caught a
  REAL playbook footgun: the unit-template restart handler would have
  parallel-restarted the whole cluster on any inventory change (join
  list is baked into the unit). Fixed: crdb_node no longer notifies
  restarts at all — upgrade.yml (serial drain) is the only restart
  path; comment in the role explains why. Also noted: schema/verify
  plays pin to groups['crdb'][0] (mind --limit), stashed node certs
  need manual pruning on node removal, decommission.yml still TODO.

## 2026-08-16 (later): AWS spot substrate — built as ansible/aws/, then
## PORTED TO terraform/aws/ (user misspoke: meant Terraform all along)

The Ansible-owned version described below was built first, validated,
then replaced 1:1 by terraform/aws/ (same VPCs/peering-mesh/spot/
inventory-render design; 3 fixed provider aliases since TF can't loop
providers; spot via aws_instance instance_market_options; region module
+ explicit 3-pair peering.tf). ansible/aws/ is GONE; terraform/aws
passes tofu validate. Division of labor now: Terraform owns cloud
resources, the Ansible playbook owns everything from SSH inward and
still derives all topology from the generated inventory.

Later same session: region corrected us-west-1 → us-west-2 (PDX;
bigger region, 4 AZs, has c8a AND cheap Graviton pools). Ubuntu bumped
to 26.04 (codename-agnostic AMI filter). Graviton evaluated with LIVE
spot prices (creds now on box via .env/direnv):
  fleet $/hr (9x xlarge): c7a $0.64 · c7g $0.47 (-23%) · c8g $0.51
  (-17%); c8g is the cheapest single instance anywhere (usw2 $0.0497).
Arch made a first-class variable end to end: TF `arch` (AMI) +
`crdb_arch` (written into generated group_vars), and fixed a latent
playbook bug — crdb_certs now uses `crdb_local_arch` (controller is
x86 even when the fleet is ARM). Full `tofu plan` against live AWS
with c8g/arm64/26.04: 56 to add, zero errors. SSH key comes from the
agent (ssh-add -L) — no ~/.ssh/*.pub on this box. Reminder: KDC image
+ tgsbench closures are x86; ARM nodes are fine as DB-only, build an
aarch64 closure before putting KDC containers on them.

## 2026-08-16 (dawn): LIVE AWS 3-region burn — write numbers in, read burn cut short, infra destroyed

Fleet: 9x c8g.xlarge SPOT (Graviton4, arm64, Ubuntu 26.04) across
us-east-1/2 + us-west-2, gp3 3000/125 (sizing math in terraform vars),
~$0.51/hr. tofu apply + site.yml end to end.

**Ansible validated live** — 3 real fixes: `stdout_lines[-1]` →
`| last` (2.21 templater), under-replicated column moved into
kv_store_status `metrics` JSON in v25, and (from the burn) SG lacked
8888 (added to TF). Cluster: 9/9 nodes, correct localities, 0
under-replicated. ARM plugin built ON a node via nix develop (flake
already had aarch64; had to add cargo/rustc — dev box was silently
using rustup's). Realm bootstrapped from us-east-1 node.

**WRITE NUMBERS (recorded; the real multi-region physics)**:
- serial addprinc, cluster defaults: **984 ms/create** (GLOBAL
  commit-wait, ~70ms max-RTT topology)
- 32 workers, defaults: **38/s**
- 32 workers, lead override 25ms: **826/s**
- full load, 128 workers, override: **262,144 in 80.9s = 3,241/s**,
  count verified via SQL, override RESET after.

**READ BURN: not completed** — first attempt failed err=100% because
SG had no 8888 rule (kinit blackholed; fixed in TF module). Then
us-east-2's c8g spot pool churned: use2-1 reclaimed 04:14 GMT
(mid-setup), use2-0 reclaimed ~30 min later. Recovery worked exactly
per runbook both times (tofu apply recreates by name; prune stale node
cert — new private IP! — re-run site.yml; joined clean; dead stores
were NOT yet decommissioned). use2 KDC was up again and 3-region bench
armed when user called teardown. `tofu destroy`: 56/56 resources,
verified 0 instances in all 3 regions.

Lessons recorded: (1) us-east-2 c8g spot churns — mix families per
region (instance_type_overrides) for real burns; (2) spot reclaim +
runbook-3 recovery is genuinely smooth; (3) krb5 "plugin symbol
kdb_function_table not found" ALSO means plain file-not-found
(db_module_dir must point at the dir CONTAINING kdb_crdb.so); (4) ssh
background daemons need setsid + </dev/null or the session hangs.

Original (superseded) ansible/aws/ design notes:
- provision.yml: per region (vars.yml aws_regions: us-east-1/2,
  us-west-1, 10.91-93/16) — VPC, subnets across <=3 AZs (us-west-1 only
  exposes 2; instances round-robin AZs for spot-pool diversity), IGW,
  SG (SSH public, 26257/8080 mesh-CIDRs only), key pair, Ubuntu 24.04
  AMI lookup, launch template with SPOT market options
  (aws_instance_type var + per-region instance_type override;
  aws_spot=false for on-demand), N ec2_instances (name-tag idempotent).
  Then FULL cross-region VPC peering mesh (request + accept + pcx
  routes both ways in every RTB) and renders inventory/aws/ for
  site.yml (public IP = ansible_host, private = crdb_advertise,
  region = crdb_region, AZ = crdb_zone, ansible_user=ubuntu).
- destroy.yml + tasks/region_destroy.yml: full reverse teardown by
  project tag (instances, launch templates, peerings, SG/RTB/subnets/
  IGW/key/VPC).
- requirements.yml: amazon.aws + community.aws (ec2_vpc_peer lives in
  community). Controller needs boto3.
- Both playbooks pass syntax check; NOT yet run live — no AWS creds on
  this box. Cost at defaults 9x c7a.xlarge spot ~= $0.70/hr.
- Caveats in aws/README.md: spot vCPU quota check for new accounts,
  c8a absent in us-west-1, peering mesh is O(n^2) — Transit Gateway
  territory at 4+ regions, re-run provision.yml after a spot reclaim
  to recreate instances + refresh inventory (public IPs change).

## 2026-08-16: repo hygiene — gitignore hardening + first commits

Prepped the tree for its first real commits. Hardened .gitignore before
staging anything: .env (AWS creds), ansible/secrets/ (cluster CA key +
node/client keys), k8s/.crdb-certs + k8s/.{admin,master,registry}-pass +
.registry-htpasswd + .bootstrap/, e2e/.certs + .state (keytabs),
terraform state/backup + .terraform/, ansible/inventory/aws/ (terraform-
generated, live IPs), ansible/.cache, image-build/rootfs/ (~139MB copied
nix store — only the Dockerfile is tracked). Verified via git
check-ignore; no secret material is in any commit. No remote configured
yet — nothing has been pushed anywhere.

Committed in layers: vendored kurbu5 + patches, core plugin, e2e suite +
compose, k8s/sea1 + image-build, terraform + ansible, docs. Next
concrete step is unchanged from HANDOFF.md: redo the AWS 3-region read
burn, then upstream the two kurbu5 patches.

## 2026-08-16: KDC deployment containerized — nix image + ansible quadlets

The flake now builds release artifacts, not just the dev shell:
- `nix build .#kdb-crdb` — the plugin via buildRustPackage (cargoLock
  works with zero pinned hashes because kurbu5 is [patch]ed to the
  in-tree vendor/, no git deps in the lockfile; bindgenHook replaces the
  manual LIBCLANG/BINDGEN env from the dev shell; cdylib lands in
  result/lib with nix-store rpaths — ldd-verified openssl resolution).
- `nix build .#kdc-image` — dockerTools.buildLayeredImage,
  localhost/kdc:latest, 29MB compressed (vs the 139MB hand-copied
  rootfs). krb5 1.22.2 + bash/coreutils/grep/gawk + tgsbench (now a
  flake package built from e2e/tgsbench.c) + /opt/kdb/kdb_crdb.so, plus
  a real /etc/passwd (kills the `kadmin.local -p` gotcha from kdc:v3).
  /config and /secrets are mount points; the image carries no realm
  state, runs as root under podman, uid-agnostic for k8s (1000).
  image-build/ (Dockerfile + rootfs assembly) is retired/deleted.

Ansible got the Kerberos layer it never had (README said "wire KDCs by
hand afterwards" — no more):
- roles/kdc_node: podman via apt, image built on the CONTROLLER by nix
  (arch-mapped per host; kdc_image_tar override for cross-arch fleets),
  shipped as a tarball over SSH (no registry needed), podman-loaded,
  run as host-network quadlet units (krb5kdc everywhere, kadmind on the
  admin host; ReadOnly=true + Tmpfs=/tmp). kdc.conf is templated with
  ONLY region-local CRDB nodes (crdb_region hostvar match) using the
  crdb_certs client certs. Handlers are try-restart on purpose: inert
  until first start, so config pushes can't crash-loop a stashless KDC.
- roles/kdc_init (admin host, idempotent): master/admin passwords via
  lookup('password') into ansible/secrets/, `kdb5_util create -s` in
  the container through the plugin, stash banked controller-side and
  distributed; admin principal created if missing.
- site.yml: three new plays (kdc / kdc-init / kdc-verify tags), serial:1,
  ending in a per-node in-container kinit smoke test. render-test.yml
  renders kdc.conf + quadlet offline — verified region selection picks
  only sea1 nodes for a sea1 KDC. Inventory example + group_vars/kdc.yml
  added; terraform now renders a [kdc] group (first node per region) and
  the SG opens 88/464(tcp+udp)+749(tcp) mesh-internal.

Verification done on this box: ansible --syntax-check (site, render-test,
upgrade) clean; render-test output inspected; tofu validate clean; image
built + docker-loaded, all daemons present; and the containerized
kadmin.local ran `listprincs` against the LIVE compose cluster through
the nix-built plugin (TLS client-cert auth, stash read) — full realm
listing returned. Not yet run against real remote hosts: the AWS read
burn redo is the natural first live exercise (HANDOFF step 1 now needs
no manual KDC wiring — site.yml does it).

Known seams: kdc_init can't recover a realm whose stash is lost
everywhere (deliberate — runbook path is `kdb5_util stash` with the
banked master password); k8s/ still uses its own registry push flow
(point it at `nix build .#kdc-image` + skopeo next time the sea1 rig is
touched).

## 2026-08-16: multi-arch images + registry push (justfile)

- justfile added: `image-build [x86_64|aarch64]`, `image-load`,
  `image-push`. Push target hub.generalprogramming.org/erinpublic/kdc
  (Harbor; bare `/kdc` 400s — repos need a <project>/ prefix, and erin's
  OIDC CLI secret has no push role on `library`, which also means the
  Harbor API refuses it entirely — project changes are UI-only for us).
  Pushes <shortrev>[-dirty]-{amd64,arm64} via skopeo then stitches
  :<shortrev> and :latest manifest lists with manifest-tool.
- aarch64 on this x86 box: qemu binfmt registered per boot via
  `docker run --privileged --rm tonistiigi/binfmt --install arm64`
  (flags POCF; the F matters for nix sandbox builds). erin is a nix
  trusted user so `--extra-platforms aarch64-linux` works from the CLI;
  the kdc_node ansible task now passes it too. Full aarch64 kdc-image
  builds under emulation (~50 min, mostly rustc; both arches 29MB
  compressed) and smoke-runs via docker --platform linux/arm64.

## 2026-08-16: AWS 3-region burn #2 — containerized ansible validated, READ NUMBERS IN

Fleet: 9 spot nodes (c8g.xlarge use1/usw2, c7g.xlarge use2 per the
pool-diversity lesson), arm64, ~$0.51/hr. tofu plan+apply (56/56) →
site.yml end to end WITH the new containerized KDC flow: podman
quadlets, nix-built arm64 image (cross-built on the x86 controller
under qemu binfmt), realm bootstrap + admin principal fully automatic.
One live bug found+fixed: YAML >- folding in the smoke test (deeper-
indented continuation kept its newline → principal-less kinit → root@).
Deploy otherwise clean; per-node kinit smoke green on all 3 KDCs.

**WRITE (kadmin.local in-container on the use1 KDC node, GLOBAL tables):**
| config | result |
|---|---|
| serial, defaults | 810 ms/create |
| 32 workers, defaults | 37.2/s |
| 32 workers, lead override 25ms | 704/s |
| full 262,144 load, 128 workers, override | **2,194/s (119.5s)** |
Row count verified 263,513; override RESET after. (Burn #1: 984ms /
38/s / 826/s / 3,241/s — same physics; full-load delta is client-side:
128 kadmin.local processes shared one 4-vCPU node with KDC + CRDB.)

**READ (the missing number): tgsbench from 2 sibling nodes per region,
48 threads x 2000 reqs each, ip:10.100 over the 262k dataset:**
| region | per-KDC TGS/s (2 clients summed) |
|---|---|
| us-west-2 (c8g) | 7,205 |
| us-east-1 (c8g) | 6,056 |
| us-east-2 (c7g) | 4,864 |
| **3-region aggregate** | **~18,100/s** |
1,152,000 requests total across both runs, err=0. Each KDC is 4 vCPU
(-w 8, entry_cache_ms=1000) ALSO hosting a CRDB node — per-core this
beats the sea1 numbers. c7g region consistently ~30% slower (Graviton3
vs 4); use1/usw2 swapped ranks between runs (noise), c7g last in both.

Infra still RUNNING at entry time (teardown decision pending user).

## 2026-08-16: burn #2 teardown + repo published

tofu destroy: 56/56, verified 0 project instances in all 3 regions (the
lone us-west-2 survivor is an unrelated 2021-era t4g.micro). Repo now
public at https://github.com/nepeat/vibeslop_krb5_kdb_crdb (HTTPS
remote — no GitHub SSH key on this box). Registry images:
hub.generalprogramming.org/erinpublic/kdc {latest, e52f869} multi-arch.

## 2026-08-16: sea1 moved to hub image; kadmin safety suite (24/24)

sea1 kdc/kadmind/loadgen now run hub.generalprogramming.org/erinpublic/
kdc:e52f869 (public, multi-arch — regcred imagePullSecrets dropped).
First real exercise of kadmind RPC found a LATENT bug: MIT kadmind
ignores kadmind_port in the realm stanza (kpasswd_port IS honored) and
binds 749 — the Service's targetPort 8749 pointed at nothing since day
one; every prior write went through kadmin.local. Service now targets
749 (Talos allows unprivileged low ports; noted in kdc.yaml).

New k8s/kadmin-safety-test.sh (run from dev box, SQL asserts via
port-forward + local cockroach): 24/24 PASS on the hub image —
- 32 concurrent disjoint creates: all acked, authable, SQL-consistent.
- 16-way cpw storm on one principal: exactly one winning password,
  kvno consistent. create/delete flap x10: DB row always agrees with
  authability.
- entry_cache_ms=1000 staleness bounds: cpw, delprinc, and -allow_tix
  visible on ALL 3 KDCs within TTL+500ms slack (in-window stale hits
  0/3 this run; allowed by design).
- FULL split brain: kadmin write refused (no false ack). The refused
  write committed AFTER heal with its ack lost — fully formed and
  authable; suite calls this out as ack-loss-not-data-loss, our
  documented semantics. Single-node partition: write succeeds via the
  plugin's multi-host gateway failover.
- kadmind pod killed mid-batch (52/64 true acks via reply text — NB
  kadmin -q exits 0 on mid-RPC death, exit codes are NOT acks): zero
  acked writes lost, zero torn rows.
- Audit: principal count back to baseline 262,150; no orphan aliases;
  no container crashes.

Known seam: kadmin's client-side timeout means "refused" during a
partition can still commit later (standard exactly-once-ack problem);
operators should treat timed-out kadmin writes as indeterminate and
re-check with getprinc, not blind-retry addprinc -pw.

## 2026-08-16: multi-kadmind partition semantics + kprop/kiprop safeguards

**Q: multiple kadminds, one on a split R/O partition?** Answered with
suite phase 4b+4c (kadmin-safety-test.sh, now 28 asserts, 28/28 PASS):
a second kadmind pinned to a single CRDB gateway, that gateway cut from
its peers both ways. Results: the minority-gateway kadmind FAILS CLOSED
— refuses admin reads (stale/follower fallback is deliberately
KDC-role-only; admin decisions never see stale data) and never acks
writes. The multi-host kadmind keeps writing throughout (gateway
failover), and both agree after heal. The one seam is the known
exactly-once-ack gap: a client-side-timed-out write can commit after
heal (observed again; row always fully formed). Multi-kadmind is safe
by construction — one strongly-consistent DB, no state to diverge —
the partitioned one just goes unavailable.

**Q: safeguards against misdeployed kprop/kiprop?** Verified live on
the compose cluster (2,056-record realm, byte-identical after all
attempts): plain `kdb5_util load` (= what kpropd runs on a full prop)
is refused EINVAL at open by the existing temporary-db guard, before
any write; `load -i` refused even with iprop_enable=true, so an iprop
replica can NEVER complete the initial full resync and therefore never
reaches incremental ulog replay against CRDB; an iprop master kadmind
aborts at startup. Only `kdb5_util load -update` (the documented
restore path) is accepted — gated by the same client cert + stash as
kadmind itself. e2e/run.sh now pins this with a negative test (load
refused + record count unchanged).

Chaos-tooling landmines found on sea1 (all encoded as comments in the
suite): the CNI silently ignores per-pod
statefulset.kubernetes.io/pod-name selectors (identity label filter —
use custom labels); egress policies are not enforced (two-sided cuts
need ingress rules on BOTH sides); established flows outlive new
policies by ~30-50s (poll peer dials for enforcement, don't sleep);
and rapid label/policy churn leaves stale state (apply one partition
per run). kadmin -q exit codes are not acks — only reply text is.

## 2026-08-16: adversarial correctness pass — 5 bugs found & fixed (rename was a minefield)

Method: theorized ~10 data-safety edge cases from a close read of
lib/store/marshal, wrote failing repros first, fixed, kept the repros as
regression tests. cargo 21/21; full e2e green (TGS gate 6971/s;
listprincs 10280/s — snapshot pinning didn't hurt paging).

**CONFIRMED + FIXED** (each repro'd failing before the fix):
- **rename TOCTOU cpw loss** (lib.rs/store.rs): entry blob was read in a
  separate txn BEFORE the rename txn; a cpw landing between read and
  commit was silently reverted under the new name (repro: old kvno
  survived the rename; retry loop replayed the same stale blob). Fix:
  store::rename_principal now takes a rewrite closure and reads the
  source row INSIDE the serializable txn — a conflicting write forces a
  40001 retry that re-reads fresh. Regression test injects a cpw from a
  second connection inside the rewrite window (proves the retry path).
- **rename target clobber** (store.rs): target row was UPSERTed —
  renaming onto an existing principal silently destroyed it. Now INSERT
  + 23505→EEXIST (libkdb5 checks KRB5_KDB_INUSE first; ours is the
  race-free backstop). Test: victim row asserted byte-identical after.
- **rename salt breakage — the big one** (lib.rs/marshal.rs): found
  LIVE by the new e2e renprinc stanza: after `renprinc renate renate2`,
  kinit renate2 failed "Password incorrect". Root cause: NORMAL-salt
  keys are string-to-key'd with a salt derived from the principal NAME
  (realm+components); implementing the rename vtable slot bypasses
  krb5_db_def_rename_principal, whose krb5_dbe_specialize_salt pins
  old-name salts explicitly before the swap (verified against MIT
  1.22.2 source). marshal::specialize_salts mirrors it exactly:
  no-salt-slot/NORMAL → explicit SPECIAL realm‖comps of the OLD name,
  NOREALM → comps, ONLYREALM → realm, SPECIAL kept, V4/AFS3 refused
  (KRB5_KDB_BAD_SALTTYPE equivalent). Every rename before this entry
  silently bricked password auth for the renamed principal (-randkey/
  keytab principals unaffected — no password to salt). e2e now proves
  the pre-rename password still kinits after renprinc.
- **torn dump snapshot** (store.rs): iterate_principals paged 512 rows
  per separate implicit txn; a rename moving a row from ahead of the
  cursor to behind it mid-scan made it vanish from kdb5_util dump
  (repro: 599/600 seen → silent backup loss). Fix: whole scan pinned
  AS OF SYSTEM TIME at one cluster_logical_timestamp (ts sanity-checked
  before interpolation; GC-TTL gives hours of headroom). Test renames
  mid-iteration via a second connection and asserts 600/600.
- **realm_of quoting bug** (lib.rs): component ending in a literal
  backslash unparses as "...\\@REALM"; the reverse scan saw '\' before
  '@' and returned realm "" → alias referral gate could misjudge. Fixed
  with a forward scan tracking escape state; unit tests cover trailing
  backslash + escaped-@ mixes.

**REFUTED with evidence**:
- SQL metacharacters/unicode in names: every query is parameterized
  ($1), match_entry glob is ignored (libkdb5 refilters). Live:
  addprinc/getprinc/listprincs/delprinc of `we%ird_p\\rinc` and a
  Devanagari name all clean; globs don't leak SQL wildcards.
- alias cycles/self-alias: resolution is structurally one hop
  (get_alias then plain get_principal); live SQL cycle rows + getprinc
  → instant "Principal does not exist", no hang/crash.
- negative caching: EntryCache.put only runs on a DB hit; misses never
  cached (create→immediate kinit safe; also covered by the sea1 safety
  suite's create/delete flap).
- panics on error paths: unwrap/expect only under #[cfg(test)].
  Row::get panics only on schema-type mismatch — unreachable while
  schema.sql's NOT NULL types hold (follow-up: try_get for depth).
- y2038: timestamps round-trip Timestamp→i32→Timestamp bit-for-bit;
  MIT treats krb5_timestamp as unsigned since 1.11. No truncation.

Known seam re-noted, not pursued: reconnect-replay ack ambiguity (a
committed-then-connection-died DELETE/rename replays as NoEntry) — same
exactly-once-ack class as the kadmin timeout seam documented earlier.

Follow-ups recommended: switch Row::get → try_get (defense in depth);
send specialize_salts note upstream with the kurbu5 patches (the trait
docs don't mention the salt contract — anyone implementing rename hits
bug #3); consider caching alias-resolved entries (perf only).

## 2026-08-16: correctness fixes verified + deployed to sea1

Independently verified the adversarial-pass fixes (cargo 21/21 rerun,
diffs reviewed) and pushed d778f25. sea1 kdc/kadmind/loadgen rolled to
erinpublic/kdc:d778f25-amd64; live renprinc-then-kinit check passes on
the 262k realm (the pre-fix plugin would have bricked the password),
and the kadmin safety suite is 28/28 post-upgrade. sea1 never ran
renprinc before today, so no remediation needed. Multi-arch manifest
for :d778f25/:latest lands when the qemu arm64 rebuild finishes.

## 2026-08-16: five failure-testing gaps closed (external review) — kvno
## across a partition, region death, staleness bound, convergence, worker curve

External review found five holes in the chaos coverage. Each now has a
script with assertions plus recorded numbers, all on the compose cluster
(3 secure CRDB nodes, one per region, freshly recreated; e2e realm with
1024 users + 1024 hosts from run.sh).

**New partition primitive** (reusable): iptables INSIDE the container's
network namespace — `sudo nsenter -t <container pid> -n iptables -I INPUT
-s <peer ip> -j DROP` (+ OUTPUT). This box has no br_netfilter, so
DOCKER-USER/FORWARD rules never see container<->container traffic and
"partitions" applied there silently do nothing (verified). Cutting inside
the netns does enforce, and it leaves published host ports alone — which
is exactly what lets a KDC keep talking to a CRDB node its peers cannot
reach. Enforcement is confirmed by polling a real peer dial, never by
sleeping (the k8s suite's lesson, same convention).

### G1 — key rotation across a partition (`e2e/kvno-partition.sh`)
roach-eu isolated from west+east. KDC-majority (gateway roach-west, port
10088) and KDC-minority (gateway roach-eu, port 11088), both `-w 1` so one
worker == one cache == one breaker == one connection. `ktadd` through the
majority while partitioned:

| measurement | value |
|---|---|
| write (ktadd) with quorum present | 0.13 s |
| majority serves the NEW kvno after | 0.86 s (bound = entry_cache_ms 1000) |
| minority over a 20 s window, 7 samples | kvno=OLD every time, 0 failures, 0 wrong |
| observed DATA staleness on the minority | 18.12 s (bound = stale_reads_ms 30 s) |
| minority convergence after heal | 2.53 s (1.26 s in an earlier run) |

Not just the kvno label — the key material is checked cryptographically:
`kinit -kt` with the OLD keytab succeeds against the minority KDC and
FAILS against the majority; the NEW keytab is the mirror image.
**VERDICT: MATCHES.** Majority promptly new, minority only ever the old
value, converges after heal.

### G2 — region death (`e2e/region-death.sh`)
First, what the cluster actually is rather than what the DDL asked for:
`SHOW SURVIVAL GOAL` = region, and the derived zone config wants
num_replicas/num_voters = 5 with `voter_constraints {+region=us-west2: 2}`
— but five voters cannot be placed on three stores, so **every range runs
3 voters, quorum 2**. With one node per region, region == node, so
**SURVIVE REGION FAILURE is not expressible on this topology**; a real
test needs >= 3 nodes per region (9 total) so voters can sit 2/2/1 and a
whole region can go without dropping below quorum (terraform/aws +
ansible already build that shape). The suite prints the applied config and
the real replica counts instead of assuming them.

What this topology *can* express is proved, with **stale_reads_ms = 0** so
any dependence on the degraded fallback would show up as an outright auth
failure:

| case | auth (kinit+kvno) | TGS/s | write |
|---|---|---|---|
| baseline, 3/3, west gateway | 0.07 s | 3204 | 0.17 s |
| europe-west4 dead | 0.06 s | 3101 | 0.18 s |
| baseline, 3/3, east gateway | 0.06 s | — | 0.17 s |
| us-west2 dead (PRIMARY + lease preference) | 0.08 s | 3321 | 0.15 s |

**VERDICT: MATCHES** the "one region dead -> transparent" row (auth AND
writes unaffected, no stale reads needed, latency flat), with the caveat
above that here that means one node of three.

### G3 — the staleness bound (`e2e/staleness-bound.sh`)
One KDC `-w 1` on roach-west; east+eu stopped (quorum GONE). An auth
sampler kinits a canary every second; a SQL sampler — one psql session
opened BEFORE the partition, because a NEW connection to a quorum-less
node cannot even authenticate — issues exactly the plugin's bounded-stale
read once a second.

| stale_reads_ms | last stale read served | KDC auth last ok | first auth fail |
|---:|---|---|---|
| 30000 | t+31.6 s | t+30.9 s | t+33.5 s |
| 10000 | t+10.6 s | t+10.5 s | t+13.1 s |

CockroachDB spells the mechanism out in its refusal: *"minimum timestamp
bound of <now - stale_reads_ms> could not be satisfied by a local resolved
timestamp of <T>"* — where T is frozen at quorum loss (measured t+1.71 s
and t+0.82 s in the two runs). So **the survival window IS stale_reads_ms**
(the 10 s control proves it isn't some CRDB lease timer), and nothing older
than the bound is ever served: CRDB refuses instead, and auth fails closed.
Worst auth latency while degraded: 1.55 s spikes on a ~6.5 s cycle
(DEGRADED_HOLD_MS 5 s + the 1.5 s statement_timeout the re-probe eats).

**VERDICT: MATCHES the letter, DEVIATES from the natural reading of the
README.** "Keeps issuing tickets through node loss and even a full split
brain, at most this many ms stale" reads as indefinite availability; it is
actually bounded to ~stale_reads_ms. README + e2e/kdc.conf.in now say so
("this is also the outage budget"), with the measured numbers.

Measurement trap worth remembering: under `with_max_staleness`, SQL
`now()` reports the UPPER bound of the negotiation, not the timestamp the
KV layer settled on (a fixed `AS OF SYSTEM TIME '-10s'` DOES move now()
back 10 s — verified both ways). Timestamp-based staleness numbers from
that query are therefore meaningless; the bound is proven by the refusal
above and by G1's data-level observation.

### G4 — heal -> fresh convergence
Expected bound from the code: DEGRADED_HOLD_MS (5 s breaker) +
entry_cache_ms (1 s). Measured: **2.53 s / 1.26 s** for a write made
during a partition to become visible on the healed minority KDC (G1), and
**0.09 s** for a write made after quorum returns (G3; writes themselves
recovered 2.5-6.1 s after the containers came back). The breaker does not
cost the full 5 s in practice because bounded-staleness reads pick the
NEWEST servable timestamp — once the cluster recovers, the "stale" path is
already fresh, so only the entry cache lags. **VERDICT: MATCHES, well
inside the bound.**

### G5 — worker scaling curve (`e2e/worker-scaling.sh`)
128 client threads (tgsbench), 1024-host set, standard kdc.conf, err=0
everywhere. Sessions sampled UNDER load from
`crdb_internal.cluster_sessions`:

| -w | TGS/s | per worker | krb5kdc SQL sessions | krb5kdc procs |
|---:|------:|-----------:|---------------------:|--------------:|
|  1 |   726 |        726 |  1 |  2 |
|  2 |  1591 |        795 |  2 |  3 |
|  4 |  3837 |        959 |  4 |  5 |
|  8 |  8937 |       1117 |  8 |  9 |
| 16 |  8933 |        558 | 16 | 17 |
| 32 |  7176 |        224 | 32 | 33 |

**Knee at 8 workers** on this 16-core box (which is also hosting the whole
3-node CRDB cluster and the load generator); 16 is flat, 32 regresses ~20%.
Connection accounting is exact: **sessions == workers** for workers+1
processes, i.e. the supervisor's pre-fork handle is not a live session and
each worker really does hold its own synchronous connection. A repeat run
gave 325/1594/3742/7011/9311/7128 — same shape, w=1 and w=16 are the noisy
points (a low-thread control put single-worker capacity at ~800/s, so the
325 was client-side queueing, not the plugin).

### Wiring
`e2e/full-cycle.sh` gains step 6 (region-death.sh) and step 7
(kvno-partition.sh, skipped LOUDLY when passwordless sudo is unavailable
since it needs nsenter). staleness-bound.sh and worker-scaling.sh are
deliberately NOT in the cycle — they are multi-minute measurement suites
whose output belongs here.

### Other findings (no code changed)
- **A new connection to a quorum-less node cannot authenticate at all**:
  `operation "get-user-session" timed out ... internal error while
  retrieving user account`. Existing sessions keep working, so the
  plugin's long-lived connection survives an outage but a reconnect
  during one will not — which is the real reason multi-host
  connection_uri exists. Worth keeping in mind for restart-during-outage
  runbooks.
- While degraded, every KDC worker pays a ~1.5 s stall every ~6.5 s (the
  breaker re-probe hitting statement_timeout). Fine at -w 16 (spread
  across workers) but visible as p99 during an outage.
- Once the staleness bound lapses, the surviving node's SQL layer starts
  failing everything with `replica unavailable ... r33:/NamespaceTable`
  — not just the principals range; the whole session becomes useless.

## 2026-08-16 (later): cold-start resilience — KDC restarts through a
## TOTAL CRDB outage (startup_retry_ms + offline last-known-good cache)

Premise (established before any code, do not re-litigate): a NEW SQL
session to a quorum-less CRDB node is architecturally impossible —
session setup writes (sqlliveness, descriptor leasing). So `stale_reads_ms`
only ever covered a process that KEEPS its existing session; a KDC that
restarts mid-outage (power loss, rolling reboot, OOM kill) had nothing to
read, and `Store::connect` being eager at open() meant it exited and
crash-looped.

**Two new capabilities, three new knobs, all opt-in and default-off.**

- **`startup_retry_ms`** (all roles, default 0 = the old fail-fast).
  `store.rs::open_client_retrying`: capped backoff 250ms doubling to 2s
  until the budget lapses. The same routine, budget capped at 2s
  (`REQUEST_RETRY_CAP_MS`), covers per-request reconnects, and a second
  circuit breaker (`connect_hold_until`, 5s) means an outage costs ONE
  connect attempt per 5s window per worker instead of one per request.
  The connection is now LAZY (`conn: Mutex<Option<Conn>>`) — that is what
  lets open() succeed with no database at all. Multi-host walk unchanged
  (rust-postgres re-walks the rotated list on every attempt).
- **`offline_cache_path` + `offline_cache_max_age_ms`** (KDC role ONLY,
  both or neither — one alone is EINVAL). New `src/offline.rs`: raw wire
  blobs exactly as stored in `principals`, plus the `aliases` rows a
  lookup needed, plus a monotone written-at stamp, postcard-serialized to
  a 0600 file via tmp+write+fsync+rename+dir-fsync. Fed only by
  successful KDC-role reads. Flushes ride the request flow (NO background
  thread): first change written straight through — krb5kdc reads K/M
  before it will listen, and that entry is what makes a cold start
  possible at all — then at most once per 10s. `-w N` workers share the
  path and MERGE newest-stamp-wins on flush, so they converge on the
  union of what the fleet read instead of clobbering each other. Corrupt/
  truncated/wrong-version/unreadable file = log + start empty, never an
  open() failure. 16k entry cap, oldest stamps pruned.

**The error-semantics decision (the one worth reviewing).** An offline
MISS or an entry past max age returns `KRB5KDC_ERR_SVC_UNAVAILABLE`
(Custom(-1765328355)), never `NoEntry`. The cache is partial by
construction, so NoEntry would let it manufacture a false
KDC_ERR_C_PRINCIPAL_UNKNOWN for a principal that exists. The KDC passes
protocol-range codes straight through, so this is client-visible as
exactly the right thing — measured in the e2e:
`kinit: A service is not available that is required to process the
request while getting initial credentials`. `store::is_unavailable` lets
lib.rs still chase the alias table on an offline direct miss (the cache
keeps alias rows), and any miss anywhere in that chain stays an error
while offline instead of collapsing to Ok(None).

Layering unchanged in front: entry_cache (1s TTL) → primary read →
bounded-stale read → offline cache. Writes never touch it, admin roles
never read it, misses are never cached.

**e2e/cold-start.sh** (new; step 8 of full-cycle.sh) — warm cache →
`docker compose stop` ALL THREE nodes → restart krb5kdc (-w 1) into the
dead cluster → assert auth from cache → assert writes AND uncached
lookups fail with the right errors → age out → heal → converge. Results
on the compose cluster, exit 0:

| measurement | value |
|---|---|
| warm cache after 2 kinits + 1 kvno | 945 bytes, 0600, 4 entries (K/M, krbtgt, cold-user, host/h0001) |
| krb5kdc listening with NO database | 3.64 s (3000ms budget, paid by supervisor then worker) |
| **cold start -> first ticket** | **7.13 s** |
| uncached principal offline | `A service is not available…` (NOT "does not exist") |
| kadmin write offline | refused |
| max_age unsatisfiable | krb5kdc refuses to start ("cannot initialize realm") — fail closed at the K/M read |
| heal -> writes recovered | 2.32 s after nodes healthy |
| post-heal write -> KDC serves it | 0.11 s |

**Tests**: cargo 21 → 33. New: offline.rs round-trip through the file,
0600 mode, age refusal, future-stamp refusal, corrupt/truncated/
wrong-version tolerance + recovery, partial-cache miss semantics,
multi-writer merge, newer-wins, flush-interval amplification bound; and
in store.rs — fail-fast default preserved, startup budget actually spent
then given up, and a full DB-less cold start (warm file + dead URI →
serves K/M and the alias, SVC_UNAVAILABLE for anything unseen, writes
still fail). Full `e2e/run.sh` green (TGS 7801.9/s), `e2e/chaos.sh` green.

**Logging**: the plugin had none. Added `lib.rs::warn` — stderr with a
`kdb_crdb:` prefix, via `writeln!` NOT `eprintln!` (which panics if
stderr is closed, and this crate must never unwind across the C vtable).
State changes only, never per-request.

Docs: README gained a "Surviving a database outage" section (three-layer
table, what is cached, threat model — same sensitivity class as a db2
principal file minus the stash, staleness-as-revocation-window, fail-
closed inventory); docs/runbooks.md gained runbook 4 (sizing both knobs,
what to expect per operation, the log lines that identify the state,
how to warm a cache deliberately).

Open questions for the user: (1) `offline_cache_max_age_ms` has no
default and no upper bound — should the plugin refuse absurd values
(> 24h?) or stay operator's-rope? (2) the cache is capped at 16k entries;
a 262k-machine realm gets hot-set coverage only — deliberate, but worth a
decision if someone wants full-realm cold-start coverage. (3) kadmind
still cannot start during an outage (no offline cache for admin roles) —
intended, documented, not revisited.

## 2026-08-16: PLAN — opt-in kprop/iprop replica mode (docs/kprop-receiver-plan.md)

User asked: can the CRDB cluster be a kprop receiver of an external
krb5 primary, taking kiprop incremental updates between full dumps —
as an explicitly-enabled opt-in, since it's cluster-wide dangerous?
Answer recorded in the new plan doc: not today (the temporary-db guard
and `load -i` refusal from the safeguards session block it before any
write, on purpose), but mechanically feasible — full prop is
create(temporary)→puts→promote_db and iprop replay is plain vtable
put/delete from kpropd, all slots we already implement.

Design (see docs/kprop-receiver-plan.md for the full thing):
- Triple gate, all required: `prop_receiver=off|kprop|iprop` knob +
  operator-SQL `prop_control` marker row + dedicated `krb5prop` SQL
  identity that alone can write staging. Default-off path must stay
  bit-identical to today (existing e2e negative test kept).
- Loads stream into REGIONAL staging tables (live GLOBAL tables
  untouched until promote; staging avoids the commit-wait);
  promote_db = leased, batched diff-sync (upserts then deletes) —
  deliberately NOT one atomic flip (intent-set size at 262k rows);
  mixed-version window ≈ what iprop incrementals produce anyway.
- Replica write-freeze: marker on ⇒ kadmind writes refused (local
  writes would be silently lost at next resync). iprop MASTER stays
  unsupported; lease enforces exactly one receiver.
- Phases: 0 spike (verify load db_args/ServerType/ulog against MIT
  1.22.2), 1 schema+gates, 2 staging store+promote, 3
  e2e/kprop-replica.sh (db2 primary on-box, full prop, liveness
  during load, incrementals, forced resync, gate matrix, aborted
  load), 4 README/runbooks.

Open questions for user in the doc: write-freeze default, staging
region templating, primary-in-compose vs on-box for the e2e. Nothing
implemented yet — next concrete step is Phase 0.

## 2026-08-16: measured — what the entry cache is worth (user asked)

A/B/A/B on the compose e2e realm (-w 16, 64 threads, 32k TGS-REQs over
1024 hosts): entry_cache_ms=1000 -> 7.3-7.9k TGS/s at ~3.9ms serial;
entry_cache_ms=0 -> 2.8k TGS/s at ~7.2ms serial. The cache is worth
~2.7x throughput and halves per-request latency; without it every
lookup is a CRDB round trip and DB read load triples. Cache-off also
fails the single-box 4000 QPS e2e gate (fleet aggregate would still
clear it). Verdict recorded: staleness with the cache is already
proven bounded <=TTL+slack on every KDC (safety suite phase 3), and a
1s window is noise against 10h ticket lifetimes — revocation latency
is dominated by tickets, not this cache. Not removing it; 0 remains a
supported per-deployment knob.

## 2026-08-16: kprop-replica Phase 0 spike — MIT 1.22.2 load mechanics verified

Instrumented open/create/put/promote_db (env-gated spike build, reverted
after) and ran real kdb5_util against throwaway spike DBs (krb5spike1/2,
plain tables, root). Ground truth, all against krb5 1.22.2:

- **Plain `load`**: ONE process does `create(args=[<-x args...>,
  "temporary"])` → put_principal per record (per-put db_args EMPTY) →
  put_policy per policy → `promote_db(args=[..., "temporary"])`. libkdb5
  calls create, not open (our create delegates to open — single choke
  point holds). ServerType::Admin, ReadWrite.
- **`load -update`**: open() WITHOUT temporary, plain upserts. Unchanged.
- **`load -i`** (iprop_enable=true): identical shape to plain load but
  db_args gain **"merge_nra"** (merge non-replicated attrs; we have
  none — lockout/last-auth off by design — so it's accept-and-ignore).
  The replica ulog (2MB, auto-created by ulog_map at the profile's
  iprop_logfile path) is maintained CLIENT-side by kdb5_util/kpropd;
  no backend hooks involved.
- **iprop_enable=false** refuses dump -i/load -i client-side ("Iprop
  not enabled") before touching the backend.
- **`dump -i` FROM kdb-crdb works** (header `iprop 1 <sno> <ts>`) once
  iprop_enable=true — the backend can even be an iprop dump source.
- **kurbu5 promote_db is STATIC** (no &self, like create/destroy):
  promote must re-open its own Store from conf_section+db_args (dburl
  is present in promote's db_args). Same pid across create→puts→promote,
  so a hostname:pid lease holder id is re-derivable at promote time.

Design consequences locked in: gate enforcement stays in open() (create
delegates); staging routing keys off the `temporary` db_arg; merge_nra
accepted as no-op; promote_db re-opens, re-verifies marker+lease, then
batched diff-promotes. Implementation next (schema → store/lib → tests
→ e2e rig with a db2 primary).
