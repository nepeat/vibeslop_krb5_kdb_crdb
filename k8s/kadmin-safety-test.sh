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
# kerberos pods only: phase 4c deliberately restarts a crdb container
restarts() { kubectl -n $NS get pods -l 'app in (kdc, kadmind, loadgen)' -o jsonpath='{range .items[*]}{.status.containerStatuses[0].restartCount}{"\n"}{end}' | awk '{s+=$1} END {print s}'; }

cleanup() {
    kubectl -n $NS delete networkpolicy chaos-split-brain kst-isolate-0 kst-shun-0 --ignore-not-found >/dev/null 2>&1 || true
    kubectl -n $NS label pod crdb-cockroachdb-0 crdb-cockroachdb-1 crdb-cockroachdb-2 kst-part- >/dev/null 2>&1 || true
    kubectl -n $NS delete deploy/kadmind-iso svc/kadmind-iso cm/kdc-config-iso --ignore-not-found >/dev/null 2>&1 || true
    for p in $(kadm "listprincs tc.*" | grep -oE '^tc\.[a-z0-9.]+@[A-Z.]+'); do
        kadm "delprinc -force $p" >/dev/null 2>&1
    done
}
trap cleanup EXIT

say "phase 0: baseline"
BASE_COUNT=$(sql "SELECT count(*) FROM krb5.principals WHERE name NOT LIKE 'tc.%'")
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
# an unacked delete RPC under concurrency is allowed to fail; the
# invariant is convergence — retries drive the set to zero.
for round in 1 2 3; do
    for i in $(seq 0 31); do kadm "delprinc -force tc.conc.$i" >/dev/null 2>&1 & done
    wait
    P1_DEL=$(sql "SELECT count(*) FROM krb5.principals WHERE name LIKE 'tc.conc.%'")
    [ "$P1_DEL" = "0" ] && break
done
[ "$P1_DEL" = "0" ] && ok "concurrent deletes converged to zero (round $round)" || bad "$P1_DEL rows survived 3 delete rounds"

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

say "phase 4b+4c: single-node partition — iso kadmind fails closed, multi-host survives"
# kadmind-iso talks ONLY to crdb-0; the multi-host kadmind can reach all
# three. crdb-0 is cut from its peers both ways (two ingress policies on
# a CUSTOM label — this CNI ignores per-pod statefulset.io/pod-name
# selectors and doesn't enforce egress; and label/policy churn leaves
# stale state, so this partition is applied exactly ONCE per run).
# Contract: the minority-gateway kadmind serves NO admin reads (stale
# fallback is deliberately KDC-role-only) and acks NO writes; the
# multi-host kadmind keeps working via gateway failover.
kubectl -n $NS get cm kdc-config -o jsonpath='{.data.kdc\.conf}' \
  | sed 's#connection_uri = postgresql://krb5kdc@[^/]*/#connection_uri = postgresql://krb5kdc@crdb-cockroachdb-0.crdb-cockroachdb.tmp-crdb-krb5.svc.cluster.local:26257/#' > /tmp/kst-iso-kdc.conf
kubectl -n $NS create configmap kdc-config-iso \
  --from-file=kdc.conf=/tmp/kst-iso-kdc.conf \
  --from-literal=krb5.conf="$(kubectl -n $NS get cm kdc-config -o jsonpath='{.data.krb5\.conf}')" \
  --from-literal=kadm5.acl="$(kubectl -n $NS get cm kdc-config -o jsonpath='{.data.kadm5\.acl}')" >/dev/null
kubectl -n $NS get deploy kadmind -o json | python3 -c '
import json, sys
d = json.load(sys.stdin)
for k in ("resourceVersion", "uid", "creationTimestamp", "generation", "annotations"):
    d["metadata"].pop(k, None)
d.pop("status", None)
d["metadata"]["name"] = "kadmind-iso"
d["metadata"]["labels"] = {"app": "kadmind-iso"}
d["spec"]["selector"]["matchLabels"] = {"app": "kadmind-iso"}
d["spec"]["template"]["metadata"]["labels"] = {"app": "kadmind-iso"}
for v in d["spec"]["template"]["spec"]["volumes"]:
    if v.get("configMap", {}).get("name") == "kdc-config":
        v["configMap"]["name"] = "kdc-config-iso"
print(json.dumps(d))' | kubectl apply -f - >/dev/null
kubectl -n $NS expose deploy kadmind-iso --port=749 --target-port=749 --name=kadmind-iso >/dev/null 2>&1 || true
kubectl -n $NS rollout status deploy/kadmind-iso --timeout=120s >/dev/null
ISO_S="kadmind-iso.$NS.svc.cluster.local"
kadm "delprinc -force tc.isobase" >/dev/null 2>&1   # idempotent re-runs
ISO_UP=0
for a in 1 2 3 4 5; do
    kx kadmin -s $ISO_S -r $REALM -p $ADMIN -w "$ADMIN_PW" -q "addprinc -pw ib-pw tc.isobase" 2>&1 | grep -q "created\." && { ISO_UP=1; break; }
    sleep 5
done
[ "$ISO_UP" = "1" ] && ok "kadmind-iso healthy pre-partition" || bad "kadmind-iso broken pre-partition"

kubectl -n $NS label pod crdb-cockroachdb-0 kst-part=zero --overwrite >/dev/null
kubectl -n $NS label pod crdb-cockroachdb-1 crdb-cockroachdb-2 kst-part=rest --overwrite >/dev/null
cat <<'EOF' | kubectl apply -f - >/dev/null
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata: {name: kst-isolate-0, namespace: tmp-crdb-krb5}
spec:
  podSelector: {matchLabels: {kst-part: zero}}
  policyTypes: [Ingress]
  ingress:
    - from:
        - podSelector:
            matchExpressions: [{key: app, operator: In, values: [kdc, kadmind, kadmind-iso, loadgen]}]
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata: {name: kst-shun-0, namespace: tmp-crdb-krb5}
spec:
  podSelector: {matchLabels: {kst-part: rest}}
  policyTypes: [Ingress]
  ingress:
    - from:
        - podSelector:
            matchExpressions: [{key: kst-part, operator: NotIn, values: [zero]}]
EOF
# Deterministic enforcement wait: poll until peer dials are cut both
# ways, then give leases a beat to decay.
P4_ENFORCED=0
for a in $(seq 1 24); do
    d10=$(kubectl -n $NS exec -c db crdb-cockroachdb-1 -- bash -c "timeout 2 bash -c 'echo > /dev/tcp/crdb-cockroachdb-0.crdb-cockroachdb/26257' 2>/dev/null && echo OPEN || echo BLOCKED")
    d01=$(kubectl -n $NS exec -c db crdb-cockroachdb-0 -- bash -c "timeout 2 bash -c 'echo > /dev/tcp/crdb-cockroachdb-1.crdb-cockroachdb/26257' 2>/dev/null && echo OPEN || echo BLOCKED")
    [ "$d10" = "BLOCKED" ] && [ "$d01" = "BLOCKED" ] && { P4_ENFORCED=1; break; }
    sleep 5
done
[ "$P4_ENFORCED" = "1" ] && ok "partition enforced (peer dials cut both ways)" || bad "partition never enforced by CNI"
sleep 15

if timeout 30 kubectl -n $NS exec -i loadgen -- kadmin -s $ISO_S -r $REALM -p $ADMIN -w "$ADMIN_PW" -q "getprinc tc.isobase" 2>/dev/null | grep -q "Principal: tc.isobase"; then
    bad "isolated kadmind served an admin READ from a minority gateway"
else
    ok "isolated kadmind refuses admin reads (no stale fallback for kadmind role)"
fi
if timeout 30 kubectl -n $NS exec -i loadgen -- kadmin -s $ISO_S -r $REALM -p $ADMIN -w "$ADMIN_PW" -q "addprinc -pw iw-pw tc.isowrite" 2>&1 | grep -q "created\."; then
    bad "isolated kadmind ACKED a write from a minority gateway"
else
    ok "isolated kadmind refuses write acks"
fi
# multi-host kadmind: first attempt may sit on the dead gateway before
# the plugin walks the host list — a retry must succeed.
P4B_OK=0
for a in 1 2 3; do
    if timeout 60 kubectl -n $NS exec -i loadgen -- kadmin -r $REALM -p $ADMIN -w "$ADMIN_PW" -q "addprinc -pw iso-pw tc.iso" 2>&1 | grep -q "created\."; then
        P4B_OK=$a; break
    fi
    sleep 3
done
[ "$P4B_OK" != "0" ] && ok "multi-host kadmind writes during the partition (attempt $P4B_OK)" || bad "multi-host kadmind never wrote during single-node partition"

kubectl -n $NS delete networkpolicy kst-isolate-0 kst-shun-0 >/dev/null
kubectl -n $NS label pod crdb-cockroachdb-0 crdb-cockroachdb-1 crdb-cockroachdb-2 kst-part- >/dev/null 2>&1
sleep 10
try_kinit "iso-pw" "tc.iso" && ok "partition-window write is authable" || bad "partition-window write not authable"
ISO_ROW=$(sql "SELECT count(*) FROM krb5.principals WHERE name = 'tc.isowrite@$REALM'")
if [ "$ISO_ROW" = "0" ]; then
    ok "no ghost row from the isolated kadmind after heal"
else
    note "isolated kadmind's unacked write committed after heal (ack lost, data intact)"
    try_kinit "iw-pw" "tc.isowrite" && ok "iso ack-lost row fully formed" || bad "iso ack-lost row TORN"
fi
G1=$(kadm "getprinc tc.isobase" | grep -c "Principal: tc.isobase@$REALM")
G2=$(kx kadmin -s $ISO_S -r $REALM -p $ADMIN -w "$ADMIN_PW" -q "getprinc tc.isobase" 2>/dev/null | grep -c "Principal: tc.isobase@$REALM")
[ "$G1" = "1" ] && [ "$G2" = "1" ] && ok "both kadminds agree after heal (no divergence)" || bad "kadminds disagree after heal ($G1 vs $G2)"
kubectl -n $NS delete deploy/kadmind-iso svc/kadmind-iso cm/kdc-config-iso >/dev/null 2>&1

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
END_COUNT=$(sql "SELECT count(*) FROM krb5.principals WHERE name NOT LIKE 'tc.%'")
[ "$END_COUNT" = "$BASE_COUNT" ] && ok "principal count back to baseline ($BASE_COUNT)" || bad "count drift: $BASE_COUNT -> $END_COUNT"
ORPHANS=$(sql "SELECT count(*) FROM krb5.aliases a LEFT JOIN krb5.principals p ON a.canonical = p.name WHERE p.name IS NULL")
[ "$ORPHANS" = "0" ] && ok "no orphan aliases" || bad "$ORPHANS orphan aliases"
END_RESTARTS=$(restarts)
EXPECTED=$((BASE_RESTARTS))   # kadmind was deleted (new pod), restartCount resets; crashes elsewhere would raise it
[ "$END_RESTARTS" -le "$EXPECTED" ] && ok "no unexpected container crashes" || bad "restart count rose: $BASE_RESTARTS -> $END_RESTARTS"
try_kinit "$ADMIN_PW" "$ADMIN" && ok "admin auth healthy at end" || bad "admin auth broken at end"

printf '\n\033[1m== kadmin-safety: %d passed, %d failed ==\033[0m\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
