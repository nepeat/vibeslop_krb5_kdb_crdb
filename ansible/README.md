# Multi-region CockroachDB via Ansible (for the krb5 KDB backend)

Deploys and clusters CRDB across regions on plain hosts (systemd — the
operationally simple alternative to multi-cluster Kubernetes). The
**inventory is the region topology**: each host's `crdb_region` /
`crdb_zone` hostvars drive `--locality`, the cross-region `--join`
seeds, and the generated multi-region DDL (`PRIMARY REGION`,
`ADD REGION`, `SURVIVE REGION FAILURE` when >= 3 regions).

## Layout

```
../terraform/aws/        AWS substrate (Terraform): VPC per region +
                         cross-region peering mesh + spot instances ->
                         renders inventory/aws/ for this playbook
inventory/example/       hosts.ini (3 regions x 3 nodes) + group_vars
roles/crdb_certs         controller-local CA, node certs, client certs
roles/crdb_node          binary, certs, systemd unit, NTP preflight
roles/crdb_init          one-time cockroach init + liveness wait
roles/crdb_schema        schema.sql templated from inventory regions
site.yml                 the works, ending in a health report
upgrade.yml              serial rolling drain/upgrade/restart
```

## Use

```sh
cp -r inventory/example inventory/prod    # edit hosts + vars
ansible-playbook -i inventory/prod/hosts.ini site.yml
ansible-playbook -i inventory/prod/hosts.ini upgrade.yml -e crdb_version=X.Y.Z
```

Adding a region later: add its hosts to the inventory, re-run site.yml —
new nodes join, the schema play emits `ADD REGION IF NOT EXISTS`, and
the GLOBAL tables grow replicas there automatically.

## Preconditions (not provisioned here)

- Routable :26257 (SQL/RPC) and :8080 (HTTP) between all nodes across
  regions (VPN/WireGuard mesh, cloud peering, whatever — join uses IPs,
  so no cross-region DNS is required).
- Time sync on every host (asserted, deploy fails without it).
- `secrets/` (CA key!) appears next to the playbook after the first
  run — vault it; every cluster cert derives from it.

## Wiring the KDCs afterwards

Per region, point kdc.conf at that region's nodes only (keeps reads
in-region during failover), with the client certs this playbook minted:

```ini
connection_uri = postgresql://krb5kdc@nodeA:26257,nodeB:26257,nodeC:26257/krb5?sslmode=verify-full&sslrootcert=.../ca.crt&sslcert=.../client.krb5kdc.crt&sslkey=.../client.krb5kdc.key&connect_timeout=3
stale_reads_ms = 30000   # ride out quorum loss / region partition
entry_cache_ms = 1000
disable_last_success = true
disable_lockout = true
```

## Not covered (yet)

- Node decommission/replacement playbook
- Backup schedules (`BACKUP ... INTO`), monitoring wiring
- The chaos suites (see ../e2e/chaos.sh, ../k8s/chaos-test.sh) — port
  them here once there's a standing multi-region env to point at
