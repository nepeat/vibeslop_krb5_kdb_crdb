#!/usr/bin/env bash
# Metal chaos suite for the tmp-crdb-krb5 deployment on sea1.
# Run from the dev box (needs KUBECONFIG for sea1 + the loadgen pod).
#
# Phases:
#   0. baseline: auth + aggregate QPS >= floor
#   1. ONE CRDB node down  (sts scaled 3->2): auth + QPS floor
#   2. TWO CRDB nodes down (sts scaled ->1): auth via bounded-staleness
#      fallback, QPS floor AT A SINGLE SURVIVING CRDB NODE, writes refused
#   3. recovery (sts ->3): primary reads + writes work again
#   4. split brain (NetworkPolicy isolates every CRDB node from its
#      peers, clients still reach all of them): auth + QPS floor,
#      writes refused; heal and verify
#
# CHAOS_QPS_FLOOR: aggregate TGS/s floor asserted in every phase
# (default 4000 = the 200K-machine worst-case sizing).
set -euo pipefail
cd "$(dirname "$0")/.."
export KUBECONFIG=${KUBECONFIG:-$HOME/.kube/config.sea1}
NS=tmp-crdb-krb5
CHAOS_QPS_FLOOR=${CHAOS_QPS_FLOOR:-4000}
BENCH_THREADS=${BENCH_THREADS:-64}
BENCH_PER=${BENCH_PER:-128}

say() { printf '\n\033[1m== k8s-chaos: %s\033[0m\n' "$*"; }
kx()  { kubectl -n $NS exec -i loadgen -- /bin/sh -s "$@"; }

cleanup() {
    kubectl -n $NS delete networkpolicy chaos-split-brain --ignore-not-found >/dev/null 2>&1 || true
    kubectl -n $NS scale statefulset crdb-cockroachdb --replicas=3 >/dev/null 2>&1 || true
}
trap cleanup EXIT
trap 'echo "K8S CHAOS FAILED (phase: ${PHASE:-?})" >&2' ERR

wait_crdb_ready() { # $1 = expected ready pod count
    until [ "$(kubectl -n $NS get pods -l app.kubernetes.io/component=cockroachdb --no-headers 2>/dev/null | grep -c '1/1')" = "$1" ]; do
        sleep 3
    done
}

auth_check() { # AS + TGS round trip through the kdc Service; $1 = tag
    kx "$1" <<'EOS'
set -e
export KRB5CCNAME=FILE:/tmp/chaos-cc
kdestroy 2>/dev/null || true
echo bench-pw | kinit bench
kvno host/10.100.7.$((RANDOM % 250)) >/dev/null
echo "AUTH-OK ($1)"
EOS
}

qps_check() { # aggregate pinned bench across all KDC pods; $1 = tag
    local ips tag=$1
    ips=$(kubectl -n $NS get pods -l app=kdc -o jsonpath='{range .items[*]}{.status.podIP} {end}')
    kx $ips <<EOS
set -e
export KRB5CCNAME=FILE:/tmp/chaos-cc
i=0
for ip in "\$@"; do
  printf '[libdefaults]\n default_realm = EXAMPLE.COM\n dns_lookup_kdc = false\n[realms]\n EXAMPLE.COM = {\n  kdc = %s:8888\n }\n' "\$ip" > /tmp/chaos-krb5-\$i.conf
  i=\$((i+1))
done
echo bench-pw | kinit bench 2>/dev/null
t0=\$EPOCHREALTIME
n=0; pids=""
for c in /tmp/chaos-krb5-*.conf; do
  KRB5_CONFIG=\$c tgsbench FILE:/tmp/chaos-cc $BENCH_THREADS $BENCH_PER 262144 ip:10.100 >/tmp/chaos-b.\$n 2>&1 &
  pids="\$pids \$!"
  n=\$((n+1))
done
wait \$pids
t1=\$EPOCHREALTIME
total=\$((n * $BENCH_THREADS * $BENCH_PER))
errs=\$(grep -ho 'err=[0-9]*' /tmp/chaos-b.* | grep -o '[0-9]*' | awk '{s+=\$1} END {print s+0}')
rm -f /tmp/chaos-krb5-*.conf /tmp/chaos-b.*
awk -v a=\$t0 -v b=\$t1 -v n=\$total -v e=\$errs -v f=$CHAOS_QPS_FLOOR -v tag="$tag" '
  BEGIN{r=n/(b-a); printf "%s: %.0f TGS/s aggregate (n=%d err=%d floor=%d)\n", tag, r, n, e, f;
        exit !(r >= f && e == 0)}'
EOS
}

write_should_fail() {
    if kx <<'EOS' | grep -q 'created\.'
timeout 40 kadmin.local -p admin/admin -q "addprinc -randkey chaos-canary" 2>/dev/null || true
EOS
    then echo "FAIL: write succeeded without quorum" >&2; return 1; fi
    echo "OK: writes refused without quorum"
}

write_should_work() {
    kx <<'EOS' | grep -q 'created\.' || { echo "FAIL: write did not recover" >&2; return 1; }
kadmin.local -p admin/admin -q "delprinc -force chaos-canary" >/dev/null 2>&1
kadmin.local -p admin/admin -q "addprinc -randkey chaos-canary" 2>&1
kadmin.local -p admin/admin -q "delprinc -force chaos-canary" >/dev/null 2>&1
EOS
    echo "OK: writes work"
}

PHASE=baseline
say "phase 0: baseline (3/3 CRDB, 3 KDCs)"
auth_check baseline
qps_check baseline

PHASE=one-down
say "phase 1: ONE CRDB node down (scale 3->2)"
kubectl -n $NS scale statefulset crdb-cockroachdb --replicas=2 >/dev/null
sleep 15
auth_check one-down
qps_check one-down

PHASE=two-down
say "phase 2: TWO CRDB nodes down (scale ->1, quorum GONE)"
kubectl -n $NS scale statefulset crdb-cockroachdb --replicas=1 >/dev/null
sleep 20
auth_check two-down
qps_check single-crdb-node
write_should_fail

PHASE=recovery
say "phase 3: recovery (scale ->3)"
kubectl -n $NS scale statefulset crdb-cockroachdb --replicas=3 >/dev/null
wait_crdb_ready 3
sleep 10
auth_check recovered
write_should_work

PHASE=split-brain
say "phase 4: split brain (CRDB nodes isolated from each other)"
kubectl apply -f k8s/split-brain-netpol.yaml >/dev/null
sleep 20
auth_check split-brain
qps_check split-brain
write_should_fail
kubectl -n $NS delete networkpolicy chaos-split-brain >/dev/null
sleep 15
auth_check healed
write_should_work

say "PASS: all k8s chaos phases green"
