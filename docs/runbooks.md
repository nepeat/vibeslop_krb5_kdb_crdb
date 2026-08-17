# Operational runbooks — multi-region CRDB for the krb5 KDB backend

Companion to `../ansible/README.md`. Assumes you have the production
inventory (`ansible/inventory/prod/`) and `ansible/secrets/` (the CA —
every cert derives from it). The inventory IS the topology: every
runbook here starts with an inventory edit and ends with the cluster
agreeing with it.

Conventions used below:

```sh
cd ansible
INV=inventory/prod/hosts.ini
# cockroach CLI commands run ON any cluster node (certs incl.
# client.root land in /etc/cockroach/certs via crdb_node):
CRDB="cockroach --certs-dir=/etc/cockroach/certs --host=<any-live-node>:26257"
```

Caveat that applies to runbooks 1 and 2: adding hosts changes
`crdb_join_list`, so an **unlimited** `site.yml` run re-templates the
systemd unit on every existing node and the `restart cockroach` handler
fires on all of them in parallel — a non-serial full-cluster restart.
The join list on running nodes is cosmetic (they gossip), so always use
`--limit` for node work and let the units refresh naturally at the next
rolling `upgrade.yml`.

---

## 1. Add a node to an existing region (scale out)

### Preconditions
- New host reachable over SSH, :26257/:8080 routable to/from every
  existing node (all regions), time-synced (chrony/ntp — asserted).
- Region already exists in the inventory; the new host uses the SAME
  `crdb_region` (new region = runbook 2).
- Cluster healthy: `$CRDB node status` shows all nodes live,
  under-replicated ranges = 0.

### Steps
1. Add the host to the inventory with its region/zone:

   ```ini
   crdb-sea-3 ansible_host=10.10.1.13 crdb_region=sea1 crdb_zone=a
   ```

2. Mint its node cert and deploy it (certs play loops over all of
   `groups['crdb']` regardless of limit; existing certs are skipped):

   ```sh
   ansible-playbook -i $INV site.yml --limit crdb-sea-3 --tags certs,nodes
   ```

   No `init` — the node auto-joins via the `--join` seed list baked
   into its unit. The limit also keeps the handler off existing nodes.

3. Wait for rebalancing (up-replication onto the new store):

   ```sh
   $CRDB node status                 # new node LIVE, ranges climbing
   $CRDB sql -e "SELECT sum(under_replicated_ranges) FROM crdb_internal.kv_store_status"
   # repeat until 0
   ```

   Or just run the gate: `ansible-playbook -i $INV site.yml --tags verify`.

### Verification
- New node listed and live in `$CRDB node status`, replica count > 0
  and growing toward parity with its region peers.
- `under_replicated_ranges` sums to 0.
- KDCs unaffected (their `connection_uri` doesn't include the new node
  until you choose to add it — optional, three hosts per region is
  plenty for failover).

### Rollback
- Node misbehaving before it holds meaningful data: `systemctl stop
  cockroach` on it, then decommission its node ID (runbook 3) and
  remove it from the inventory. Do NOT just wipe it once it has
  replicas.

### Guidance
- Keep regions symmetric (same node count/hardware per region) —
  GLOBAL replica placement and the join list both assume it.
- Scaling **read QPS is a KDC-layer job**: reads are entry-cache +
  local-follower bound, so add KDC processes, not DB nodes. Add DB
  nodes for storage headroom, write throughput, or replica spread.
- Existing nodes keep their old (stale) `--join` list until their unit
  is re-templated at the next full/rolling run. Cosmetic: live nodes
  discover peers via gossip.

---

## 2. Add a region

### Preconditions
- **>= 3 hosts** for the new region (zone-spread; GLOBAL leaseholders
  and in-region survivability want 3).
- Full mesh reachability :26257/:8080 between the new hosts and ALL
  existing regions. Time sync everywhere.
- Cluster healthy (as above).

### Steps
1. Add the hosts to the inventory with the new `crdb_region`:

   ```ini
   crdb-ams-0 ansible_host=10.40.1.10 crdb_region=ams1 crdb_zone=a
   crdb-ams-1 ansible_host=10.40.1.11 crdb_region=ams1 crdb_zone=b
   crdb-ams-2 ansible_host=10.40.1.12 crdb_region=ams1 crdb_zone=c
   ```

2. Certs + nodes for the new hosts only (they auto-join):

   ```sh
   ansible-playbook -i $INV site.yml --limit 'crdb-ams-*' --tags certs,nodes
   ```

3. Re-run the schema + verify plays (they target the first inventory
   host; tags keep `crdb_node` — and its restart handler — out of it):

   ```sh
   ansible-playbook -i $INV site.yml --tags schema,verify
   ```

   The templated DDL emits `ADD REGION IF NOT EXISTS "ams1"`, and at
   >= 3 regions adds `SURVIVE REGION FAILURE`. GLOBAL tables grow
   replicas in the new region automatically — no table DDL needed.

### Verification
```sh
$CRDB sql -e "SHOW REGIONS FROM DATABASE krb5"          # new region listed
$CRDB sql -e "SHOW SURVIVAL GOAL FROM DATABASE krb5"    # region at >=3 regions
$CRDB sql -e "SELECT sum(under_replicated_ranges) FROM crdb_internal.kv_store_status"
# replica spread — expect replicas in every region for the krb5 ranges:
$CRDB sql -e "SELECT start_pretty, replica_localities FROM crdb_internal.ranges WHERE database_name = 'krb5' LIMIT 10"
```

Then wire the new region's KDCs: region-local multi-host
`connection_uri` listing ONLY the three new nodes (plus `stale_reads_ms`
etc., see ../ansible/README.md), and publish the new KDCs to clients —
DNS SRV (`_kerberos._udp.REALM`) or `kdc =` entries in krb5.conf.

### Rollback
- Region not yet in the DDL: stop/decommission the new nodes, drop the
  hosts from the inventory.
- Region already added: `ALTER DATABASE krb5 DROP REGION "ams1";`
  (and expect `SURVIVE REGION FAILURE` to block the drop if it would
  leave < 3 regions — downgrade the survival goal first). Then
  decommission the nodes per runbook 3.

### Guidance
- GLOBAL write latency is commit-wait bound and grows with the **max
  RTT in the region set** — adding a far-away region taxes every write,
  everywhere. Reads stay local and fast; that's the trade.
- 2 -> 3 regions is the big one: the template automatically adds
  `SURVIVE REGION FAILURE`, so a whole-region outage stops being a
  quorum event. (KDC reads survive quorum loss regardless via
  `stale_reads_ms`, but writes need quorum.)
- Bulk-loading principals into the new topology? See progress.md
  2026-08-16: `ALTER TABLE ... SET (global_reads lead time)` — the
  25ms `lead_for_global_reads` override is the bulk-load lever.

---

## 3. Replace or remove a node

Fully supported — this is what `cockroach node decommission` is for.
**Never just delete a node.** An un-decommissioned node stays "suspect",
its replicas count against replication, and without spare in-region
capacity you sit under-replicated indefinitely.

### Preconditions
- Know the node ID: `$CRDB node status` (match by address).
- Enough surviving capacity for the replicas to land on: don't
  decommission below 3 nodes in a region (GLOBAL leaseholder placement)
  or below what `SURVIVE REGION FAILURE` needs cluster-wide.
- `--host` for all commands = any LIVE node, never the one leaving.

### Flow A — planned replacement
1. Add the replacement node first (runbook 1) and wait for it to be
   live and rebalanced. Capacity before evacuation.
2. Decommission the old node (moves every replica off; blocks until
   done):

   ```sh
   $CRDB node decommission <nodeID> --wait=all
   $CRDB node status --decommission     # gauge: replicas -> 0, membership -> decommissioned
   ```

3. Once it reports decommissioned: on the old host,
   `systemctl disable --now cockroach`, wipe `/var/lib/cockroach`,
   remove the host from the inventory, and delete its stashed certs
   from `ansible/secrets/` (`<host>.node.crt/.key`).

### Flow B — dead node (hardware gone)
1. If spare in-region capacity existed, the cluster already
   re-replicated ~5 min after death (`server.time_until_store_dead`).
   Confirm: under-replicated ranges = 0. If NOT zero, you lack
   capacity — add a node (runbook 1) before anything else.
2. Decommission the dead node ID to clear it from the roster (no data
   movement left to do, so it completes fast):

   ```sh
   $CRDB node decommission <nodeID> --wait=all
   ```

3. Remove the host from the inventory + its certs from secrets.

### Verification
```sh
$CRDB node status                       # departed node gone / decommissioned
$CRDB node status --decommission        # no stuck decommissions
$CRDB sql -e "SELECT sum(under_replicated_ranges) FROM crdb_internal.kv_store_status"   # 0
```
If the departed node was in any KDC `connection_uri`, update those
kdc.conf entries (multi-host failover masks it meanwhile).

### Rollback
- Decommission is abortable mid-flight: `$CRDB node recommission
  <nodeID>` (only until it completes — a fully decommissioned node can
  never rejoin; wipe its store and add it back as a NEW node).

### Guidance
- Order of operations is capacity-first: replacement in, data drained,
  THEN the old node out. Decommission with nowhere to put replicas
  just hangs.
- Drain (`cockroach node drain`, as upgrade.yml does) is for restarts;
  decommission is for removal. Don't confuse them — drain moves
  leases, decommission moves replicas.

---

## 4. KDC cold start during a database outage

For the case where a KDC **process** has to start (or restart) while
CockroachDB is unreachable: power loss to a whole site, a rolling reboot
that outruns the DB, an OOM kill mid-outage, a node replacement.

The thing to internalise first: `stale_reads_ms` does **not** cover this.
It works on the SQL session the process already has. A *new* session to a
quorum-less node cannot be established at all — CRDB's own user lookup
and descriptor leasing need writes — so a restarted KDC has nothing to
read. Two knobs cover it instead (both in the `[dbmodules]` stanza; see
README for the full text):

```ini
startup_retry_ms = 30000                 # every role
offline_cache_path = /var/lib/krb5kdc/crdb-offline.cache   # KDC role only
offline_cache_max_age_ms = 3600000                         # both or neither
```

### Sizing

- **`startup_retry_ms`** — how long a daemon waits for the DB at boot
  instead of exiting. Set it to comfortably exceed "DB comes up shortly
  after me" (systemd ordering across hosts, k8s pod scheduling): 30s is a
  reasonable default. Costs nothing when the DB is up. It is paid twice
  on a KDC cold start (the supervisor opens the DB, then each `-w`
  worker re-opens after fork), and the same budget capped at **2s**
  bounds per-request reconnects so a hung DB cannot wedge a worker.
- **`offline_cache_max_age_ms`** — this is a **revocation window**, not
  an outage budget. During a full outage a disabled/deleted principal,
  or one whose password changed, keeps authenticating for up to this long
  after the KDC last read it. Pick it as "how late am I willing to honour
  a revocation in exchange for staying up". 1h is a sane starting point;
  anything past a shift change wants a compensating control.
- The cache is fed **only by reads this KDC performed**. A KDC that has
  been up and serving has a warm hot set; a KDC that has never run has
  an empty file and will come up but answer nothing. Warm deliberately
  after provisioning (see below) if cold-start coverage matters on day
  one.
- File size: bounded at 16k entries, roughly 3-6 MB. It is not a replica
  of the realm and is not meant to be one.

### What to expect during an outage

| operation | result |
|---|---|
| KDC starts | comes up (after the retry budget lapses), logs `starting WITHOUT a database connection` |
| `kinit`/`kvno` for a cached principal, inside max age | **works** |
| lookup of a principal this KDC never read | fails with `KDC_ERR_SVC_UNAVAILABLE` — deliberately NOT "principal unknown" |
| anything past max age | fails closed; nothing unbounded-stale is ever served |
| kadmin write, `kdb5_util` anything | fails — admin roles never read the cache, and writes need quorum |
| kadmind start | **fails** (no offline cache for admin roles); that is intended, bring it up with the database |
| after the DB returns | reconnects within ~5s (reconnect breaker) + `entry_cache_ms`; live reads supersede the cache immediately |

Recognising the state in the logs (stderr, so journald/`kubectl logs`):

```
kdb_crdb: startup: connect attempt 1 failed, retrying in 250ms
kdb_crdb: startup: no connection after 5 attempts (30000ms budget)
kdb_crdb: starting WITHOUT a database connection; serving from the offline cache until CRDB is reachable
kdb_crdb: offline cache loaded: 412 entries
kdb_crdb: reconnect: connected on attempt 2          <- recovered
```

### Warming the cache deliberately

The cache only holds what the KDC served, so after standing up a new KDC
(or restoring one from an image) drive the principals you care about
through it once — a `kinit`/`kvno` loop over the service principals that
must survive an outage is enough. `K/M@REALM` and `krbtgt/REALM@REALM`
land automatically: krb5kdc reads K/M before it will listen, and every
request touches krbtgt. Flushes ride the request flow at most once per
10s, so leave the KDC serving for ≥10s after warming, then confirm:

```sh
ls -l /var/lib/krb5kdc/crdb-offline.cache   # must be 0600, non-empty
grep -a 'K/M@' /var/lib/krb5kdc/crdb-offline.cache   # cold start needs this
```

### Handling the file

Treat it exactly like a db2/LMDB `principal.db`: it holds
master-key-encrypted key material plus principal metadata. It never holds
the stash, so it is strictly weaker than the pair an attacker actually
wants — but it is not public. 0600 (the plugin enforces it), on storage
you already trust with the stash, wiped with the same care. Deleting it
is always safe: the KDC starts empty and refills from the database.

### Verification

`e2e/cold-start.sh` (step 8 of `e2e/full-cycle.sh`) is the executable
version of this runbook against the compose cluster: it warms the cache,
stops all three nodes, restarts krb5kdc into the dead cluster, asserts
auth works from the cache and that uncached lookups and writes fail with
the right errors, ages the cache out, then heals and measures
convergence.

## 5. Migrate a realm from an external krb5 primary (kprop/iprop replica mode)

Goal: replicate a production MIT realm (db2 or any KDB backend) into the
CRDB cluster continuously, verify it, then cut over — or just bulk-load an
exact copy for testing. `e2e/kprop-replica.sh` is the executable version
of this runbook.

### Schema

Re-apply `schema.sql` as root before enabling replica mode on a cluster
that ran the first replica-mode schema (2026-08-17): the receiver lease
moved out of `prop_control` into its own `prop_lease` table, so that
`krb5prop` can hold the lease without holding `UPDATE` on the marker that
freezes the cluster (CockroachDB has no column-level grants). The file is
idempotent — it creates and seeds `prop_lease`, drops the old lease
columns, and revokes the old grant. Any `last_promote_at` history is lost
in the move; the marker row itself is untouched.

### Enable (three keys, all required)

1. Provision the `client.krb5prop` cert **on the kpropd host only** and
   give that host its own `[dbmodules]` stanza:
   `prop_receiver = iprop` (profile only — `-x prop_receiver=` on a
   command line is deliberately ignored), `connection_uri` with the
   krb5prop cert, plus
   `iprop_enable = true`, `iprop_logfile`, `iprop_port` (required),
   `iprop_replica_poll`. Keep the KDCs on their normal krb5kdc stanza —
   they need none of this.
2. Mark the cluster as a replica (operator SQL, root):
   `UPSERT INTO prop_control (singleton, enabled, mode) VALUES (true, true, 'iprop');`
   From this moment kadmind writes cluster-wide are refused (EPERM,
   logged) — the propagation stream is the only writer. That is the
   point: local writes would be silently destroyed at the next resync.
3. Copy the **primary's** master key stash to the replica KDC/kpropd
   hosts (the dump is ciphertext under the primary's K/M).

On the primary: add `kiprop/<replica-fqdn>@REALM p` to kadm5.acl, create
`host/<primary-fqdn>` + `kiprop/<replica-fqdn>` principals, keytab them,
add `host/<primary-fqdn>@REALM` to the replica's kpropd.acl.

### Bootstrap + steady state

- Start kpropd on the receiver host, then push the first full dump from
  the primary: `kdb5_util dump -i /tmp/full.dump && kprop -f /tmp/full.dump <replica-fqdn>`.
  The load streams into the staging tables (live KDCs unaffected), then
  promotes. Watch for the plugin's `promote complete:` stderr line;
  `SELECT last_promote_at FROM prop_lease` confirms.
- Start the replica KDCs (or restart kpropd if it was polling before the
  KDC came up — its kadm5-init backoff can otherwise sit for minutes).
- Steady state: kpropd applies incrementals within the poll interval;
  periodic full props diff-promote (unchanged rows are not rewritten).
- Verify continuously: principal counts, and `kinit` of a known
  principal against a replica KDC (proves key material end-to-end).

### Cut over (promote-to-primary)

1. Freeze changes on the old primary (stop kadmind or its clients).
2. Push one final full dump; wait for `last_promote_at` (`prop_lease`).
3. `UPDATE prop_control SET enabled = false;` — pushes are refused from
   here on and the write-freeze lifts.
4. Stop kpropd, point kadmin traffic at this cluster's kadmind, move
   client krb5.conf/DNS to the new KDCs. The realm, including all key
   material and kvnos, is byte-identical — issued tickets stay valid.

### Recovery notes

- **Lease stuck**: a load that *fails* releases the lease itself (the
  plugin hooks kdb5_util's destroy of the temporary db), so kpropd
  retries immediately. Only a hard-killed receiver (SIGKILL, host loss)
  leaves it held; it then expires on its own (15 min), or clear it:
  `UPDATE prop_lease SET holder = NULL, expires = NULL;`. Aborted loads
  never touch live tables; the next load clears staging itself.
- **Replica ulog reset loop** ("Full resync needed" every poll): means
  ulog_replay failed — check the kpropd host's stderr for `kdb_crdb:`
  lines and CRDB grants (krb5prop needs SELECT on aliases too; a miss
  during replay's existence check otherwise fails the whole update).
- **kpropd under nix**: pass `-p $(command -v kdb5_util)` — the nixpkgs
  krb5 build bakes a nonexistent lib/sbin path and kpropd logs
  "completed" over the exec failure (silent no-op loads). The
  kadmind-initiated automatic full resync has the same broken path baked
  in with no override; trigger full props manually (cron on the primary)
  if you need them under nix.
