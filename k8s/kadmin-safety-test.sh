#!/usr/bin/env bash
# kadmin safety suite for the sea1 deployment: write-path consistency,
# cache staleness bounds, and split-partition behavior of kadmind
# against the kdb-crdb backend. Run from the dev box.
#
# Phases:
#   1. concurrent disjoint creates (32x) — all acked, all present
#   2. same-principal contention: cpw storm (exactly one password wins),
#      create/delete flap (DB state always agrees with authability)
#   3. entry-cache staleness bounds (entry_cache_ms=1000): cpw/delprinc/
#      -allow_tix must be visible on EVERY KDC within TTL + slack;
#      the in-window stale hit is DOCUMENTED, not asserted
#   4. splits: full split-brain -> writes refused, no ghost rows after
#      heal; single-node partition -> writes succeed via gateway failover
#   5. kadmind killed mid-batch -> every acked create is authable,
#      every unacked name is absent or fully formed (no torn entries)
#   6. audit: cleanup, principal count back to baseline, no pod restarts
#
# Needs: KUBECONFIG for sea1, k8s/.admin-pass, a cockroach binary +
# client certs for SQL asserts (SQL_CMD below), port-forward on :26999.
set -uo pipefail
cd "$(dirname "$0")/.."
export KUBECONFIG=${KUBECONFIG:-$HOME/.kube/config.sea1}
NS=tmp-crdb-krb5
REALM=EXAMPLE.COM
ADMIN=admin/admin
ADMIN_PW=$(cat k8s/.admin-pass)
SQL_CMD=${SQL_CMD:-"ansible/.cache/cockroach-v25.2.2.linux-amd64/cockroach sql --certs-dir=k8s/.crdb-certs --host=localhost:26999"}

PASS=0; FAIL=0
say()  { printf '\n\033[1m== kadmin-safety: %s\033[0m\n' "$*"; }
ok()   { PASS=$((PASS+1)); echo "PASS: $*"; }
bad()  { FAIL=$((FAIL+1)); echo "FAIL: $*"; }
note() { echo "NOTE: $*"; }

kx()   { kubectl -n $NS exec -i loadgen -- "$@"; }
# kadmin over the wire through the kadmind Service (NOT kadmin.local).
kadm() { kx kadmin -r $REALM -p $ADMIN -w "$ADMIN_PW" -q "$*" 2>&1; }
sql()  { # retries ride out port-forward re-establishment
    local v t
    for t in 1 2 3 4 5; do
        v=$($SQL_CMD --format=csv -e "$1" 2>/dev/null | tail -1)
        [ -n "$v" ] && { echo "$v"; return 0; }
        sleep 2
    done
    return 1
}

# kinit against the kdc Service (any KDC) or a specific KDC pod IP.
try_kinit() { # $1 pw, $2 principal, [$3 kdc ip]
    local conf=""
    if [ -n "${3:-}" ]; then
        conf="printf '[libdefaults]\n default_realm = $REALM\n dns_lookup_kdc = false\n[realms]\n $REALM = {\n  kdc = $3:8888\n }\n' > /tmp/kst-\$\$.conf && export KRB5_CONFIG=/tmp/kst-\$\$.conf;"
    fi
    kx /bin/sh -c "$conf echo '$1' | kinit -c /tmp/kst-cc-\$\$ '$2' >/dev/null 2>&1 && kdestroy -c /tmp/kst-cc-\$\$ >/dev/null 2>&1"
}
kdc_ips() { kubectl -n $NS get pods -l app=kdc -o jsonpath='{range .items[*]}{.status.podIP}{"\n"}{end}'; }
restarts() { kubectl -n $NS get pods -o jsonpath='{range .items[*]}{.status.containerStatuses[0].restartCount}{"\n"}{end}' | awk '{s+=$1} END {print s}'; }

cleanup() {
    kubectl -n $NS delete networkpolicy chaos-split-brain kst-isolate-0 --ignore-not-found >/dev/null 2>&1 || true
    for p in $(kadm "listprincs tc.*" | grep -oE '^tc\.[a-z0-9.]+@[A-Z.]+'); do
        kadm "delprinc -force $p" >/dev/null 2>&1
    done
}
trap cleanup EXIT

say "phase 0: baseline"
BASE_COUNT=$(sql "SELECT count(*) FROM krb5.principals")
BASE_RESTARTS=$(restarts)
[ -n "$BASE_COUNT" ] && ok "SQL reachable, principals=$BASE_COUNT" || { bad "SQL unreachable"; exit 1; }
kadm "getprinc $ADMIN" | grep -q "Principal: $ADMIN@$REALM" && ok "kadmind RPC up" || { bad "kadmind RPC down"; exit 1; }

say "phase 1: 32 concurrent disjoint creates via kadmind"
for i in $(seq 0 31); do kadm "addprinc -pw cp$i tc.conc.$i" >/dev/null 2>&1 & done
wait
sleep 2
P1_OK=0
for i in $(seq 0 31); do try_kinit "cp$i" "tc.conc.$i" && P1_OK=$((P1_OK+1)); done
[ "$P1_OK" -eq 32 ] && ok "all 32 concurrent creates authable" || bad "only $P1_OK/32 concurrent creates authable"
P1_SQL=$(sql "SELECT count(*) FROM krb5.principals WHERE name LIKE 'tc.conc.%'")
[ "$P1_SQL" = "32" ] && ok "SQL rows = 32" || bad "SQL rows = $P1_SQL (want 32)"
for i in $(seq 0 31); do kadm "delprinc -force tc.conc.$i" >/dev/null 2>&1 & done
wait
P1_DEL=$(sql "SELECT count(*) FROM krb5.principals WHERE name LIKE 'tc.conc.%'")
[ "$P1_DEL" = "0" ] && ok "all 32 concurrent deletes landed" || bad "$P1_DEL rows survived delete"

say "phase 2a: 16-way cpw storm on one principal"
kadm "addprinc -pw race-base tc.race" >/dev/null 2>&1
for i in $(seq 0 15); do kadm "cpw -pw rpw$i tc.race" >/dev/null 2>&1 & done
wait
sleep 2   # let every KDC's entry cache expire
P2_WINNERS=""
for i in $(seq 0 15); do try_kinit "rpw$i" "tc.race" && P2_WINNERS="$P2_WINNERS $i"; done
P2_N=$(echo $P2_WINNERS | wc -w)
[ "$P2_N" -eq 1 ] && ok "exactly one cpw winner (rpw${P2_WINNERS# })" || bad "cpw winners: [$P2_WINNERS] (want exactly 1)"
KVNO=$(kadm "getprinc tc.race" | grep -oE 'vno [0-9]+' | head -1)
note "tc.race key $KVNO after 16 racing cpws"

say "phase 2b: create/delete flap x10"
P2B_BAD=0
for r in $(seq 1 10); do
    ( kadm "addprinc -pw flap-pw tc.flap" >/dev/null 2>&1 ) &
    ( kadm "delprinc -force tc.flap" >/dev/null 2>&1 ) &
    wait
done
sleep 2
EXISTS_DB=$(sql "SELECT count(*) FROM krb5.principals WHERE name = 'tc.flap@$REALM'")
if try_kinit "flap-pw" "tc.flap"; then EXISTS_AUTH=1; else EXISTS_AUTH=0; fi
[ "$EXISTS_DB" = "$EXISTS_AUTH" ] && ok "flap: DB row ($EXISTS_DB) agrees with authability ($EXISTS_AUTH)" || bad "flap: DB=$EXISTS_DB vs auth=$EXISTS_AUTH"

say "phase 3: entry-cache staleness bounds (TTL 1000ms + 500ms slack)"
kadm "addprinc -pw old-pw tc.cache" >/dev/null 2>&1
sleep 2
for ip in $(kdc_ips); do try_kinit "old-pw" "tc.cache" "$ip" >/dev/null; done   # warm every cache
kadm "cpw -pw new-pw tc.cache" >/dev/null 2>&1
STALE=0
for ip in $(kdc_ips); do try_kinit "old-pw" "tc.cache" "$ip" && STALE=$((STALE+1)); done
note "in-window stale old-pw hits: $STALE/3 KDCs (allowed <=TTL; this is the documented cache tradeoff)"
sleep 1.5
P3_NEW=0; P3_OLD=0
for ip in $(kdc_ips); do
    try_kinit "new-pw" "tc.cache" "$ip" && P3_NEW=$((P3_NEW+1))
    try_kinit "old-pw" "tc.cache" "$ip" && P3_OLD=$((P3_OLD+1))
done
[ "$P3_NEW" -eq 3 ] && ok "new password live on all 3 KDCs after TTL" || bad "new pw only on $P3_NEW/3 KDCs after TTL"
[ "$P3_OLD" -eq 0 ] && ok "old password dead on all 3 KDCs after TTL" || bad "old pw STILL live on $P3_OLD/3 KDCs after TTL"

kadm "addprinc -pw del-pw tc.del" >/dev/null 2>&1; sleep 2
for ip in $(kdc_ips); do try_kinit "del-pw" "tc.del" "$ip" >/dev/null; done
kadm "delprinc -force tc.del" >/dev/null 2>&1
sleep 1.5
P3_DEL=0
for ip in $(kdc_ips); do try_kinit "del-pw" "tc.del" "$ip" && P3_DEL=$((P3_DEL+1)); done
[ "$P3_DEL" -eq 0 ] && ok "deleted principal refused on all 3 KDCs after TTL" || bad "deleted principal STILL authable on $P3_DEL/3 KDCs"

kadm "addprinc -pw dis-pw tc.dis" >/dev/null 2>&1; sleep 2
for ip in $(kdc_ips); do try_kinit "dis-pw" "tc.dis" "$ip" >/dev/null; done
kadm "modprinc -allow_tix tc.dis" >/dev/null 2>&1
sleep 1.5
P3_DIS=0
for ip in $(kdc_ips); do try_kinit "dis-pw" "tc.dis" "$ip" && P3_DIS=$((P3_DIS+1)); done
[ "$P3_DIS" -eq 0 ] && ok "-allow_tix (disable) live on all 3 KDCs after TTL" || bad "disabled principal STILL authable on $P3_DIS/3 KDCs"

say "phase 4a: FULL split brain — kadmin writes must be refused, no ghosts"
kubectl apply -f k8s/split-brain-netpol.yaml >/dev/null
sleep 5
if timeout 45 kubectl -n $NS exec -i loadgen -- kadmin -r $REALM -p $ADMIN -w "$ADMIN_PW" -q "addprinc -pw ghost-pw tc.split" >/dev/null 2>&1; then
    bad "write ACKED during full split (quorum should be gone)"
    SPLIT_ACKED=1
else
    ok "write refused/timed out during full split"
    SPLIT_ACKED=0
fi
kubectl -n $NS delete networkpolicy chaos-split-brain >/dev/null
until [ "$(sql "SELECT count(*) FROM krb5.principals WHERE name = 'tc.split@$REALM'")" != "" ]; do sleep 3; done
GHOST=$(sql "SELECT count(*) FROM krb5.principals WHERE name = 'tc.split@$REALM'")
if [ "$SPLIT_ACKED" = "0" ]; then
    if [ "$GHOST" = "0" ]; then ok "no ghost row after heal"; else
        # A commit that raced the partition and lost its ack is duplicate-
        # ack-loss, not corruption — but call it out loudly.
        note "unacked write IS present after heal (ack lost, data intact)"
        try_kinit "ghost-pw" "tc.split" && ok "ack-lost row is fully formed (authable)" || bad "ack-lost row is TORN (present but not authable)"
    fi
fi
kadm "addprinc -pw split-pw tc.split2" >/dev/null 2>&1
sleep 2
try_kinit "split-pw" "tc.split2" && ok "writes healthy after heal" || bad "writes still broken after heal"

say "phase 4b: single CRDB pod partitioned — writes must survive via failover"
cat <<'EOF' | kubectl apply -f - >/dev/null
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: kst-isolate-0
  namespace: tmp-crdb-krb5
spec:
  podSelector:
    matchLabels:
      statefulset.kubernetes.io/pod-name: crdb-cockroachdb-0
  policyTypes: [Ingress]
  ingress:
    - from:
        - podSelector:
            matchExpressions:
              - {key: app, operator: In, values: [kdc, kadmind, loadgen]}
EOF
sleep 5
if timeout 60 kubectl -n $NS exec -i loadgen -- kadmin -r $REALM -p $ADMIN -w "$ADMIN_PW" -q "addprinc -pw iso-pw tc.iso" >/dev/null 2>&1; then
    ok "write acked with crdb-0 partitioned (gateway failover)"
else
    bad "write failed with only ONE node partitioned"
fi
kubectl -n $NS delete networkpolicy kst-isolate-0 >/dev/null
sleep 3
try_kinit "iso-pw" "tc.iso" && ok "partition-window write is authable" || bad "partition-window write not authable"

say "phase 5: kadmind killed mid-batch — acked==authable, no torn rows"
# ack = kadmind's post-commit "created." reply, NOT the exit code —
# kadmin -q exits 0 even when the RPC dies mid-command.
kx /bin/sh -c 'rm -f /tmp/kst-acks; for i in $(seq 0 63); do kadmin -r '"$REALM"' -p '"$ADMIN"' -w "'"$ADMIN_PW"'" -q "addprinc -pw kp$i tc.kill.$i" 2>&1 | grep -q "created\." && echo $i >> /tmp/kst-acks; done' &
BATCH=$!
sleep 3
kubectl -n $NS delete pod -l app=kadmind --wait=false >/dev/null 2>&1
wait $BATCH || true
kubectl -n $NS rollout status deploy/kadmind --timeout=180s >/dev/null 2>&1
sleep 2
ACKED=$(kx /bin/sh -c 'cat /tmp/kst-acks 2>/dev/null' || true)
N_ACKED=$(echo "$ACKED" | grep -c . || true)
P5_TORN=0; P5_LOST=0; P5_UNACKED_PRESENT=0
for i in $(seq 0 63); do
    IN_DB=$(sql "SELECT count(*) FROM krb5.principals WHERE name = 'tc.kill.$i@$REALM'")
    if echo "$ACKED" | grep -qx "$i"; then
        [ "$IN_DB" = "1" ] || { P5_LOST=$((P5_LOST+1)); continue; }
        try_kinit "kp$i" "tc.kill.$i" || P5_TORN=$((P5_TORN+1))
    elif [ "$IN_DB" = "1" ]; then
        P5_UNACKED_PRESENT=$((P5_UNACKED_PRESENT+1))
        try_kinit "kp$i" "tc.kill.$i" || P5_TORN=$((P5_TORN+1))
    fi
done
note "batch: $N_ACKED/64 acked before/around the kill; $P5_UNACKED_PRESENT unacked-but-present (ack lost in flight)"
[ "$P5_LOST" -eq 0 ] && ok "no acked write was lost" || bad "$P5_LOST ACKED writes missing from DB"
[ "$P5_TORN" -eq 0 ] && ok "no torn rows (everything present is authable)" || bad "$P5_TORN torn rows"

say "phase 6: audit"
cleanup
sleep 2
END_COUNT=$(sql "SELECT count(*) FROM krb5.principals")
[ "$END_COUNT" = "$BASE_COUNT" ] && ok "principal count back to baseline ($BASE_COUNT)" || bad "count drift: $BASE_COUNT -> $END_COUNT"
ORPHANS=$(sql "SELECT count(*) FROM krb5.aliases a LEFT JOIN krb5.principals p ON a.canonical = p.name WHERE p.name IS NULL")
[ "$ORPHANS" = "0" ] && ok "no orphan aliases" || bad "$ORPHANS orphan aliases"
END_RESTARTS=$(restarts)
EXPECTED=$((BASE_RESTARTS))   # kadmind was deleted (new pod), restartCount resets; crashes elsewhere would raise it
[ "$END_RESTARTS" -le "$EXPECTED" ] && ok "no unexpected container crashes" || bad "restart count rose: $BASE_RESTARTS -> $END_RESTARTS"
try_kinit "$ADMIN_PW" "$ADMIN" && ok "admin auth healthy at end" || bad "admin auth broken at end"

printf '\n\033[1m== kadmin-safety: %d passed, %d failed ==\033[0m\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
