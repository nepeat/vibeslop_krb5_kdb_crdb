# Multi-region CockroachDB + Kerberos KDCs via Ansible

Deploys and clusters CRDB across regions on plain hosts (systemd — the
operationally simple alternative to multi-cluster Kubernetes), then runs
the Kerberos KDCs on top as podman quadlet units from the nix-built
container image (`nix build .#kdc-image`, built on the controller and
shipped over SSH — no registry required). The
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
roles/kdc_node           podman, nix image ship+load, config, quadlets
roles/kdc_init           one-time realm bootstrap (K/M, stash, admin)
site.yml                 the works, ending in per-KDC kinit smoke tests
upgrade.yml              serial rolling drain/upgrade/restart (CRDB)
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

## The KDCs

Hosts in `[kdc]` (typically colocated on one CRDB node per region — any
host with a `crdb_region` hostvar works) get krb5kdc, and the first one
also kadmind, as host-network podman quadlet units running the flake's
`kdc-image`. Each KDC's kdc.conf points only at its region's CRDB nodes
(keeps reads in-region during failover) over the client certs this
playbook minted; the container mounts config and secrets read-only and
carries no realm state.

Realm bootstrap is automatic and idempotent (`kdc_init`): master + admin
passwords are generated into `secrets/kdc-{master,admin}-pass`,
`kdb5_util create -s` runs once through the plugin, and the stash is
banked in `secrets/master.stash` for the other KDC hosts. The final play
proves every KDC issues tickets (kinit in the container).

Re-running `site.yml --tags kdc` after a code change rebuilds the image
via nix and serially restarts only the KDCs whose tarball changed.
Cross-arch note: an x86 controller building for arm hosts needs qemu
binfmt registered once per boot (`docker run --privileged --rm
tonistiigi/binfmt --install arm64`; see the repo justfile) — or set
`kdc_image_tar` to a prebuilt tarball. Registry-based delivery is also
available via `just image-push` (hub.generalprogramming.org/library/kdc,
multi-arch manifest), but the default flow ships tarballs over SSH and
needs neither registry access on the hosts nor pull secrets.

## Not covered (yet)

- Node decommission/replacement playbook
- Backup schedules (`BACKUP ... INTO`), monitoring wiring
- The chaos suites (see ../e2e/chaos.sh, ../k8s/chaos-test.sh) — port
  them here once there's a standing multi-region env to point at
