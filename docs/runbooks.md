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
