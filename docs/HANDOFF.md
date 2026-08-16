# HANDOFF — kdb-crdb session state (2026-08-16)

Fresh-session starter. `docs/progress.md` is the full history (read the
2026-08-16 entries); this is what's LIVE, what's DONE, and what's NEXT.

## What this project is

MIT Kerberos KDB backend on CockroachDB GLOBAL tables (safe Rust, kurbu5).
Feature-complete: aliases/referrals, policy TL-data, entry cache
(`entry_cache_ms`), degraded-read fallback (`stale_reads_ms`, bounded-
staleness + circuit breaker), multi-host connection_uri failover.
16 cargo tests; e2e + chaos suites in `e2e/` (compose) and `k8s/` (sea1).

## Live systems RIGHT NOW

- **sea1 k8s, ns tmp-crdb-krb5** (KUBECONFIG=~/.kube/config.sea1): 3-node
  CRDB on local NVMe + 3 KDCs (image kdc:v5, -w 48) + kadmind + registry
  (registry-tmp-crdb.owo.me, creds k8s/.registry-pass) + loadgen pod.
  262k host/10.10[0-3].x.y principals loaded. Realm EXAMPLE.COM,
  admin/admin pw in k8s/.admin-pass, bench/bench-pw exists.
  COSTS NOTHING extra (homelab) — fine to leave, or clean with
  `kubectl delete ns tmp-crdb-krb5` + helm uninstall crdb.
- **AWS: NOTHING RUNNING.** Full 3-region spot burn was built, run, and
  `tofu destroy`ed (56/56, verified 0 instances us-east-1/2, us-west-2).
  State file in terraform/aws/ reflects empty. .env has AWS creds.
- **Dev compose cluster** (docker, this box): may be up; e2e suite owns it.

## Numbers bank (all recorded in progress.md)

| Path | Setup | Number |
|---|---|---|
| Read | dev box e2e gate | 8.4k TGS/s (gate 4000) |
| Read | sea1 3 KDCs, 262k dataset | **40.6k TGS/s aggregate** |
| Read | sea1 quorum-lost / split-brain | 9.2k / 8.7k TGS/s (stale fallback) |
| Read | stock krb5 db2 baseline (dev box) | 13.8k TGS/s |
| Write | AWS 3-region defaults | 984ms/op serial; 38/s @32w |
| Write | AWS 3-region, lead override 25ms | 826/s @32w; **3,241/s @128w** |
| Write | sea1 single-region REGIONAL table | 3,978/s @32w (defaults) |
| Load | 262,144 principals (4 /16s) | 65s (sea1) / 81s (AWS 3-region) |

## The ONE unfinished thing

**AWS 3-region READ burn never produced numbers.** Sequence: SG lacked
8888 (fixed in terraform module now), then us-east-2's c8g spot pool
reclaimed two nodes ~30min apart (recovery via runbook worked cleanly
both times), then teardown was called with the bench re-armed but unrun.
To redo (~30 min, ~$0.51/hr):
1. `cd terraform/aws && tofu apply -var "ssh_public_key=$(ssh-add -L | head -1)" -var instance_type=c8g.xlarge -var arch=arm64 -var crdb_arch=linux-arm64`
   (consider `-var 'instance_type_overrides={"us-east-2":"c7g.xlarge"}'`
   — pool diversity; use2 c8g churns)
2. `cd ansible && ansible-playbook -i inventory/aws/hosts.ini site.yml`
3. Follow progress.md "LIVE AWS burn" entry: nix on 6 nodes, build once,
   fan out ~/kdb, bootstrap realm, load /16s (lead override!), KDC per
   region via direct store path + setsid, tgsbench from sibling nodes.
   All exact commands are in the transcript-derived notes there.

## Sharp edges for the next session

- krb5's "plugin symbol 'kdb_function_table' not found" usually means
  the .so path is wrong (db_module_dir must CONTAIN kdb_crdb.so).
- Node certs pin private IPs: after any instance replacement, `rm
  ansible/secrets/<host>.node.*` then re-run site.yml.
- Never restart CRDB nodes in parallel; upgrade.yml is the only restart
  path (no handlers in crdb_node — deliberate).
- Ansible 2.21: no `x[-1]` in until: expressions; use `| last`.
- CRDB v25: under-replicated lives in kv_store_status `metrics` JSON.
- Unlicensed CRDB throttles concurrent txns after grace period
  (XXC02 as bare EIO) — recreate dev compose cluster when stress
  suddenly tanks.
- kurbu5 is VENDORED at main b52c19e with 2 accessor patches
  (`patches/`) — still need upstreaming to codeberg; then re-pin + drop
  vendor/.
- Secrets on this box (all chmod 600): k8s/.{registry,master,admin}-pass,
  k8s/.crdb-certs/, ansible/secrets/ (CA!), .env (AWS).

## Suggested next-session order

1. Redo the AWS read burn (above) — the missing number.
2. Decommission flow: add ansible/decommission.yml (runbook 3 is
   CLI-only), plus prune-certs task.
3. Upstream the two kurbu5 patches.
4. Excluded by user earlier (do NOT do unless asked): dump/restore
   round-trip CI test.

glhf, next-me. The litter box is clean. :3
