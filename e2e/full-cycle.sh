#!/usr/bin/env bash
# Full testing cycle from a completely clean state:
#
#   1. destroy + recreate the CRDB compose cluster (data volumes included)
#   2. wait for cluster init + schema.sql
#   3. cargo test        (marshal unit tests + store integration tests)
#   4. e2e/run.sh        (real krb5kdc/kadmind: kadmin, ktadd, kinit, kvno,
#                         backend validation, 1024+1024 stress — see run.sh)
#   5. e2e/chaos.sh      (CRDB node loss: auth + QPS floor with 1 node
#                         down, then with quorum GONE via the plugin's
#                         bounded-staleness fallback, then recovery)
#   6. e2e/region-death.sh    (one region dead is transparent WITHOUT the
#                              stale fallback: stale_reads_ms=0)
#   7. e2e/kvno-partition.sh  (key rotation across a real network
#                              partition: which kvno each side issues.
#                              Needs passwordless sudo for netns iptables;
#                              SKIPPED loudly if unavailable)
#
# Not in the cycle — measurement suites, run them when the numbers matter
# (they are slow and their output belongs in docs/progress.md):
#   e2e/staleness-bound.sh   how long bounded-stale auth survives, and
#                            what ends it (control: SB_STALE_MS)
#   e2e/worker-scaling.sh    TGS/s vs `krb5kdc -w N` + connection accounting
#
#   e2e/full-cycle.sh              # the works
#   STRESS_N=64 e2e/full-cycle.sh  # lighter stress phase
set -euo pipefail
cd "$(dirname "$0")/.."

CERTS="$PWD/e2e/.certs"
CRDB_URI_ROOT="postgresql://root:root-dev-pw@localhost:26257/krb5?sslmode=verify-full&sslrootcert=$CERTS/ca.crt"

say() { printf '\n\033[1;34m### %s\033[0m\n' "$*"; }

say "clean slate: tearing down compose cluster (volumes + certs too)"
docker compose down -v --remove-orphans
rm -rf "$CERTS"
mkdir -p "$CERTS"

say "bringing up 3-region CRDB + schema"
docker compose up -d
docker compose wait roach-init || {
    echo "roach-init failed:" >&2
    docker compose logs roach-init >&2
    exit 1
}
for _ in $(seq 30); do
    psql "$CRDB_URI_ROOT" -c 'SELECT 1 FROM principals LIMIT 1' >/dev/null 2>&1 && break
    sleep 1
done
psql "$CRDB_URI_ROOT" -c 'SELECT 1 FROM principals LIMIT 1' >/dev/null ||
    { echo "schema never became queryable" >&2; exit 1; }

say "cargo test (store + marshal against fresh cluster)"
nix develop --command cargo test

say "e2e: KDC/kadmind + stress + backend validation"
e2e/run.sh

say "chaos: CRDB node loss / quorum loss / recovery"
e2e/chaos.sh

say "region death: one region down, stale fallback disabled"
e2e/region-death.sh

if sudo -n true 2>/dev/null; then
    say "kvno across a network partition (majority vs minority gateway)"
    e2e/kvno-partition.sh
else
    say "SKIPPED e2e/kvno-partition.sh — needs passwordless sudo (nsenter/iptables)"
fi

say "FULL CYCLE PASS"
