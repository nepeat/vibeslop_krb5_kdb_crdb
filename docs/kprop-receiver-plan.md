# Plan: CRDB cluster as a kprop/iprop replica of an external krb5 primary

Status: **IMPLEMENTED 2026-08-17** — see README "Running as a
kprop/iprop replica", docs/runbooks.md §5, and the 2026-08-17 progress
entry. Kept for the design rationale; deltas from plan discovered during
implementation: `iprop_port` is a required config once iprop_enable is
on; krb5prop needs SELECT on aliases (miss-path lookups during replay);
promote records no iprop serial (the ulog is client-side, set by
`kdb5_util load -i` itself via ulog_set_last); the kadmind-initiated
automatic full resync cannot run under nixpkgs krb5 (broken baked-in
kprop path) — manual/cron full props instead. Phase E's kproplog -R
variant was replaced by a manual re-push for the same reason.

Original plan follows. Written 2026-08-16 as a gated, opt-in reversal of
the kprop/kiprop safeguards recorded in docs/progress.md (2026-08-16
"multi-kadmind partition semantics + kprop/kiprop safeguards").

## The question, answered

**Can a kdb-crdb cluster act as a kprop receiver of a separate krb5
primary (db2/LDAP/whatever) outside CockroachDB, and take iprop
(kiprop) incremental updates in between full dumps?**

- **Today: no, by deliberate design.** `open()`/`create()` refuse the
  `temporary` db_arg (lib.rs:177), which kills plain `kdb5_util load`
  — the thing kpropd runs on every full prop — before it writes a
  byte. `load -i` (iprop full resync) dies on the same guard, so an
  iprop replica can never complete its initial resync and never
  reaches incremental replay. This is asserted by a negative test in
  e2e/run.sh.
- **Mechanically: yes, it is implementable.** Everything kpropd does
  goes through interfaces we already speak:
  - Full prop: kpropd receives the dump and runs `kdb5_util load`,
    which is `krb5_db_create(temporary)` → one `put_principal`/
    `put_policy` per record → `promote_db(temporary)`. All vtable
    slots we implement.
  - iprop incremental: kpropd polls kadmind's kiprop RPC and applies
    ulog entries itself via `krb5_db_put_principal`/
    `krb5_db_delete_principal` — ordinary vtable calls. The ulog is a
    local mmap'd file on the kpropd host managed by libkdb5's
    kdb_log.c, not a backend concern.
  - iprop **master** support is NOT needed and stays refused (a
    master kadmind with our backend aborts at startup today; that
    behavior is kept — see non-goals).

The hard part is not protocol plumbing; it is that `kdb5_util load`
assumes a private side database it can trash and atomically swap,
while our tables are live, shared, and GLOBAL — a misdeployed kpropd
would stream a foreign realm over every region's production data.
Hence the design below is staging-based and triple-gated.

## Why this is dangerous (what the gates must prevent)

1. A full prop **replaces the entire realm** — principals, policies,
   K/M master-key entry — with the external primary's content,
   cluster-wide, in every region at once. There is no per-KDC blast
   radius like db2's one-file-per-replica.
2. Any host with a valid client cert and a five-line kdc.conf could
   otherwise trigger it. db2 kpropd can only ruin its own replica
   file; ours can ruin everyone's.
3. Two kpropds (or a kpropd racing a live kadmind) interleaving
   writes would produce a realm that is neither the primary's nor
   ours.
4. Local kadmind writes on a replica cluster are silently lost at the
   next full resync — divergence must be prevented, not documented
   away.

## Design

### Gating: three independent keys, all required

1. **Config knob** `prop_receiver = off | kprop | iprop` (profile /
   db_args, default `off`). `iprop` implies the `kprop` load path
   (resync uses it). Anything but `off` is refused unless the other
   two keys are present.
2. **Operator SQL marker**: a `prop_control` row (`enabled`, `mode`)
   that only operator SQL can create — same philosophy as schema.sql
   (the plugin never writes it except lease/serial fields). A stray
   kdc.conf on some box cannot enable receiver mode by itself; the
   cluster itself must be marked as a replica.
3. **Dedicated SQL identity** `krb5prop`: the staging tables and the
   `prop_control` lease columns are writable ONLY by this user. The
   normal `krb5kdc` user physically cannot stage a load even if keys
   1–2 are present. Receiver hosts are provisioned with the
   `client.krb5prop` cert; nothing else is.

Refusals are loud (`lib.rs::warn`) and EINVAL, preserving today's
fail-before-first-write property for every ungated path. The existing
negative test in e2e/run.sh must keep passing with the feature merged
and all gates off.

### Replica write-freeze

While `prop_control.enabled` is true, the plugin refuses
`put_principal`/`delete_principal`/`put_policy`/`delete_policy` from
Admin-role handles that are not the prop receiver (i.e. kadmind and
plain kdb5_util): a replica realm is read-only except for the
propagation stream, exactly like a db2 replica whose KDC serves from
a file only kpropd writes. Checked at open() (cached) and re-checked
on write via the existing connection so a freshly-marked cluster
converges within one reconnect. KDC reads are untouched. Escape
hatch: operator flips the row off (promotion-to-primary runbook).

### Staging tables, not the live ones

`open()`/`create()` with `temporary` (gates passing) routes ALL
CRUD of that handle to `principals_staging` / `policies_staging`:

- Live GLOBAL tables serve every region's KDCs untouched for the
  whole (minutes-long) dump stream. A load that dies at 90% leaves
  live data byte-identical — same guarantee as db2's `@...~` temp
  file.
- Staging tables are **REGIONAL BY TABLE in the receiver's region**,
  not GLOBAL: nothing reads them until promote, so paying the GLOBAL
  commit-wait per dump record would be pure waste. Bulk-load numbers
  from the burns say regional ≈ 4k rows/s without any override —
  a 262k-principal dump stages in ~1 minute.
- Each staged load begins by clearing staging (DML DELETE — the
  plugin still never issues DDL; no TRUNCATE).

### promote_db: leased, batched diff-sync

`promote_db` stops being a no-op when (and only when) the handle is a
gated staging handle:

1. **Lease check**: single txn asserting `prop_control.enabled` and
   that this process holds the lease (`lease_holder`,
   `lease_expires`; taken at the `temporary` open, heartbeat via the
   request flow like the offline-cache flush — no background
   thread). A second kpropd fails its open, loudly.
2. **Upsert pass**: batched (≈512 rows/txn, existing 40001 retry
   loop) `UPSERT` into live of staging rows whose `entry` differs
   (`IS DISTINCT FROM` filter) — a routine re-prop where 99% of rows
   are unchanged writes almost nothing and costs the GLOBAL
   commit-wait only for the real delta.
3. **Delete pass, last**: batched delete of live rows absent from
   staging. Ordering means a KDC mid-promote can see old-or-new
   versions of an entry but never a missing one.
4. Record `last_promote_at` (+ iprop serial if present), clear
   staging, release the lease.

**Deliberate trade-off**: promote is *not* one atomic flip. A single
`DELETE live; INSERT SELECT` txn would be, but at 262k × ~1KB blobs
it is a multi-hundred-MB intent set — CRDB territory where txns get
slow and fragile. The bounded mixed-version window (seconds, delta-
sized) is exactly the consistency iprop incremental replay produces
anyway, so replicas already live with it. Alternative considered and
rejected for now: generation-pointer tables (atomic flip, but puts a
generation lookup on the AS/TGS hot path — see the read-QPS goal).
Revisit only if someone demonstrates a real need for flip atomicity.

- Aliases are ours (operator SQL, not in any dump) — promote never
  touches the `aliases` table. Documented: aliases pointing at
  principals the primary deleted become dangling (harmless: lookup
  returns not-found today).
- Entry/offline caches on KDCs converge within their existing TTLs;
  no new staleness class is introduced.

### iprop receiver mode

With `prop_receiver = iprop`:

- `load -i` variants are accepted (same staging path; the `-i` dump
  header's serial is recorded in `prop_control` at promote).
- kpropd's incremental replay needs no new plugin code: it is
  vanilla put/delete through an Admin-role handle. The write-freeze
  must exempt the receiver's handle — the discriminator is the
  gating triple (knob + marker + krb5prop identity), not a new
  ServerType (kurbu5 only exposes Kdc/Admin/Other).
- The ulog file lives on the kpropd host (`iprop_logfile`); one
  receiver ⇒ one ulog ⇒ no coordination problem. The lease enforces
  the "one receiver" part.
- iprop **master** stays unsupported: no ulog write hooks from
  kadmind against this backend, master kadmind keeps aborting. The
  CRDB cluster is the *end* of this replication chain (it is already
  its own multi-region replication).

### Schema additions (schema.sql, operator-applied)

```sql
CREATE TABLE principals_staging (name STRING PRIMARY KEY, entry BYTES NOT NULL)
    LOCALITY REGIONAL BY TABLE;          -- receiver region; see plan
CREATE TABLE policies_staging   (name STRING PRIMARY KEY, entry BYTES NOT NULL)
    LOCALITY REGIONAL BY TABLE;
CREATE TABLE prop_control (
    singleton     BOOL PRIMARY KEY DEFAULT true CHECK (singleton),
    enabled       BOOL NOT NULL,
    mode          STRING NOT NULL,       -- 'kprop' | 'iprop'
    lease_holder  STRING,
    lease_expires TIMESTAMPTZ,
    last_serial   INT8,
    last_promote_at TIMESTAMPTZ
) LOCALITY GLOBAL;
CREATE USER krb5prop;
GRANT SELECT, INSERT, UPDATE, DELETE ON principals_staging, policies_staging TO krb5prop;
GRANT SELECT, INSERT, UPDATE, DELETE ON principals, policies TO krb5prop;
GRANT SELECT ON prop_control TO krb5kdc;
GRANT SELECT, UPDATE ON prop_control TO krb5prop;   -- lease/serial only; enabled/mode are operator INSERTs as root
```

(Exact column-level grant syntax to be verified against CRDB v25.2 —
if column grants aren't supported, split lease state into a second
table.)

## Phases

### Phase 0 — spike: verify MIT mechanics against 1.22.2 (½ day)

Ground truth before code, on the compose cluster + stock db2:
- Exact db_args `kdb5_util load` / `load -i` passes to create/open
  (`temporary`, `merge_nra`?), and which ServerType the load and
  kpropd handles present.
- Confirm kpropd incremental replay path is plain vtable
  put/delete, and where the replica ulog file wants to live.
- Confirm what `kdb5_util dump -i` emits serial-wise and what
  promote needs to record for kpropd to resume incrementals instead
  of looping on full resyncs.
- Record findings in progress.md; adjust this plan if reality
  disagrees.

### Phase 1 — schema + gates (1 session)

- schema.sql additions above; compose `roach-cert` grows
  `client.krb5prop`.
- lib.rs: parse `prop_receiver`, implement the triple-gate check and
  the loud refusals. `temporary` still refused whenever any gate
  fails — the default-off path must be bit-identical to today.
- Replica write-freeze on `prop_control.enabled`.
- cargo tests: gate matrix (8 combinations of the three keys — only
  all-three passes), freeze refusals, existing 33 stay green.

### Phase 2 — staging store + promote (1–2 sessions)

- store.rs: staging-mode `Store` (table-name indirection, not string
  pasting — two static SQL sets), staging clear-on-open, lease
  take/heartbeat/release, batched diff-promote (upserts then
  deletes), serial recording.
- promote_db wired to it; non-staging handles keep the no-op.
- cargo tests: live tables untouched mid-load and after an aborted
  load; promote diff correctness incl. deletes and the unchanged-row
  fast path; lease contention (second open fails); promote with a
  node down (must fail closed — writes need quorum, already true).

### Phase 3 — e2e validation rig (1–2 sessions)

New `e2e/kprop-replica.sh` (NOT in full-cycle.sh by default —
it reconfigures the realm; wire it as an opt-in step like
staleness-bound.sh):
- **Primary**: stock krb5 1.22.2 + db2 on this box (the QPS-baseline
  recipe), its own realm dir, kadmind with `iprop_enable = true`,
  `kiprop/host` principal, kpropd_acl.
- **Replica**: compose CRDB + our plugin, gates on (marker row via
  SQL, krb5prop cert, `prop_receiver = iprop`), kpropd running
  against it, krb5kdc serving from CRDB throughout.
- Asserts:
  1. Full prop: `kdb5_util dump` + kprop on the primary → promote →
     principal counts match, a primary-created user kinits against
     the CRDB-backed KDC (proves key material + K/M survived
     byte-level), pre-existing CRDB-realm principals are gone.
  2. Liveness during load: background kinit loop against the CRDB
     KDC never fails while the dump streams (staging isolation).
  3. Incremental: `addprinc`/`cpw`/`delprinc` on the primary appear
     on the replica within the poll interval, no full resync
     triggered (serial advanced).
  4. "Snapshots in the meantime": force a full resync mid-stream of
     incrementals (bump serial past ulog size) → resync completes,
     incrementals resume after.
  5. Negative: every gate-off combination still refused before first
     write; kadmind write against the frozen replica refused; second
     kpropd refused by the lease.
  6. Aborted load: kill kpropd mid-dump → live tables byte-identical
     (reuse the dump-compare trick from the safeguards session).

### Phase 4 — docs (½ session)

- README: "Running as a kprop/iprop replica" — the three gates, the
  freeze, promote semantics (delta window, not atomic flip), and the
  promotion-to-primary escape hatch.
- runbooks.md: enable-replica runbook, promote-to-primary runbook
  (flip marker off, unfreeze, decommission kpropd), lost-lease
  recovery.
- progress.md entries per session, as always.

## Non-goals

- iprop **master** (CRDB as the source feeding external replicas) —
  dump + kprop *from* this backend already works for that.
- Multiple concurrent receivers (lease enforces exactly one).
- Merging realms — a full prop replaces, never merges.
- Making plain `kdb5_util load` work without the gates. The
  ungated refusal is a feature and keeps its regression test.

## Open questions for the user

1. Write-freeze default: plan says freeze kadmind writes whenever the
   replica marker is on (recommended — divergence is data loss at
   next resync). Acceptable, or does someone need a mixed mode?
2. Staging region: single `REGIONAL BY TABLE IN "us-west2"` default
   in schema.sql, or templated per deployment (ansible already
   templates DDL)?
3. Is the e2e rig's primary-on-the-same-box acceptable, or do you
   want the primary in a compose container for realism (needs a krb5
   image with kadmind/kprop — the kdc image already has the
   binaries)?
