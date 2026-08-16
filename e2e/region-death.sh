#!/usr/bin/env bash
# Region death under SURVIVE REGION FAILURE (compose cluster).
#
# Requires the realm set up by e2e/run.sh (state dir + stress principals).
#
# WHAT THIS TOPOLOGY CAN AND CANNOT PROVE
# ---------------------------------------
# schema.sql asks for SURVIVE REGION FAILURE across three regions, and the
# compose cluster has exactly ONE node per region — so region == node. The
# zone config the database derives from that goal wants num_voters = 5,
# but five voters cannot be placed on three stores (one replica per range
# per node), so every range runs with 3 voters and quorum 2. The suite
# PRINTS the applied config and the real replica counts rather than
# assuming, then proves the property this topology can actually express:
#
#   one region (== one node == one voter of three) dies
#   -> reads AND writes stay available, with no degraded fallback at all
#
# "No degraded fallback" is proven, not assumed: the KDC under test runs
# with stale_reads_ms = 0, so if losing a region needed bounded-staleness
# reads, auth would simply fail.
#
# Case A kills a non-primary region (europe-west4).
# Case B kills the PRIMARY region (us-west2), which also holds the lease
# preference — the KDC then has to work through a surviving region's
# gateway, which is what a real regional KDC fleet does.
#
# A real SURVIVE REGION FAILURE test needs >= 3 nodes per region (9 total)
# so that 5 voters can be placed 2/2/1 and a whole region can go without
# dropping below quorum; see terraform/aws + ansible for that shape.
set -euo pipefail
cd "$(dirname "$0")/.."

if ! command -v kdb5_util >/dev/null 2>&1; then
    exec nix develop --command "$0" "$@"
fi

STATE="$PWD/e2e/.state"
CERTS="$PWD/e2e/.certs"
QPS_FLOOR=${QPS_FLOOR:-1000}
WRITE_MAX_S=${WRITE_MAX_S:-15}
AUTH_MAX_S=${AUTH_MAX_S:-10}
CRDB_URI_ROOT="postgresql://root:root-dev-pw@localhost:26257/krb5?sslmode=verify-full&sslrootcert=$CERTS/ca.crt"
[[ -f "$STATE/kdc.conf" ]] || { echo "run e2e/run.sh first (no state)"; exit 1; }

say() { printf '\n\033[1m== region-death: %s\033[0m\n' "$*"; }
now() { date +%s.%N; }
since() { awk -v a="$1" -v b="$(now)" 'BEGIN{printf "%.2f", b - a}'; }
le() { awk -v a="$1" -v b="$2" 'BEGIN{exit !(a <= b)}'; }

export KRB5_CONFIG="$STATE/krb5-rd.conf"
export KRB5_KDC_PROFILE="$STATE/kdc-rd.conf"

cleanup() {
    pkill -x krb5kdc -u "$(id -u)" 2>/dev/null || true
    docker compose start roach-west roach-east roach-eu >/dev/null 2>&1 || true
    KRB5_KDC_PROFILE="$STATE/kdc-rd.conf" \
        kadmin.local -q "delprinc -force rd-canary" >/dev/null 2>&1 || true
}
trap cleanup EXIT
on_err() {
    echo "REGION-DEATH FAILED — kdc log tail:" >&2
    tail -5 "$STATE/kdc-rd.log" 2>/dev/null >&2 || true
}
trap on_err ERR

sed -e 's|^\[libdefaults\]|[libdefaults]\n    udp_preference_limit = 1\n    kdc_timeout = 20000|' \
    "$STATE/krb5.conf" >"$STATE/krb5-rd.conf"

# The KDC under test: NO degraded fallback, so any dependence on stale
# reads shows up as an outright auth failure.
render_kdc_conf() { # <gateway host:port>
    sed -e 's|stale_reads_ms = [0-9]*|stale_reads_ms = 0|' \
        -e "s|localhost:26257|$1|" \
        -e 's|kdc\.log|kdc-rd.log|' "$STATE/kdc.conf" >"$STATE/kdc-rd.conf"
    grep -q 'stale_reads_ms = 0' "$STATE/kdc-rd.conf" ||
        { echo "FAIL: could not disable stale_reads_ms" >&2; exit 1; }
}
start_kdc() {
    pkill -x krb5kdc -u "$(id -u)" 2>/dev/null || true
    sleep 0.5
    krb5kdc -n -w "${KDC_WORKERS:-16}" &
    for _ in $(seq 50); do
        (exec 3<>"/dev/tcp/127.0.0.1/10088") 2>/dev/null && break
        sleep 0.2
    done
}
auth_works() { # AS-REQ + TGS-REQ, timed
    local t0=$1
    kdestroy 2>/dev/null || true
    echo "pw-u0000" | timeout 30 kinit u0000 >/dev/null 2>&1
    timeout 30 kvno host/h0001.example.com >/dev/null 2>&1
    since "$t0"
}
write_works() { # a real kadmin write round trip, timed; prints secs or FAIL
    local t0
    t0=$(now)
    kadmin.local -q "delprinc -force rd-canary" >/dev/null 2>&1 || true
    if timeout "$WRITE_MAX_S" kadmin.local -q "addprinc -randkey rd-canary" \
        2>/dev/null | grep -q 'created\.'
    then since "$t0"; else echo FAIL; fi
}
qps_check() { # short tgsbench burst; prints the rate
    "$STATE/tgsbench" "$KRB5CCNAME" 64 128 1024 >/dev/null 2>&1 || true
    local t0 t1
    t0=$(now)
    "$STATE/tgsbench" "$KRB5CCNAME" 64 128 1024 >/dev/null
    t1=$(now)
    awk -v a="$t0" -v b="$t1" 'BEGIN{printf "%.0f", 8192/(b-a)}'
}
wait_healthy() { # <service...>
    until [[ "$(docker compose ps "$@" 2>/dev/null | grep -c healthy)" == "$#" ]]; do
        sleep 2
    done
}

say "what the cluster actually is (not what the DDL asked for)"
psql "$CRDB_URI_ROOT" -c 'SHOW REGIONS' \
    -c 'SHOW SURVIVAL GOAL FROM DATABASE krb5'
echo "  zone config derived from the survival goal:"
psql "$CRDB_URI_ROOT" -tAc \
    "SELECT raw_config_sql FROM [SHOW ZONE CONFIGURATION FOR TABLE principals]" |
    sed 's/^/    /'
echo "  replicas actually placed per range (num_voters=5 cannot fit on 3 stores):"
psql "$CRDB_URI_ROOT" -tAF'|' -c \
    "SELECT range_id, array_length(voting_replicas,1), array_to_string(replicas,',')
     FROM [SHOW RANGES FROM TABLE principals WITH DETAILS]" | sed 's/^/    range /'
NVOTERS=$(psql "$CRDB_URI_ROOT" -tAc \
    "SELECT max(array_length(voting_replicas,1))
     FROM [SHOW RANGES FROM TABLE principals WITH DETAILS]")
echo "  => quorum is $(( NVOTERS / 2 + 1 )) of $NVOTERS: this topology survives ONE node/region, not a region of many"

export KRB5CCNAME="FILE:$STATE/rd-cc"
cc -O2 -o "$STATE/tgsbench" e2e/tgsbench.c $(krb5-config --cflags --libs krb5)

say "case A: baseline, gateway roach-west, stale_reads_ms=0"
render_kdc_conf localhost:26257
start_kdc
A_BASE_AUTH=$(auth_works "$(now)")
A_BASE_QPS=$(qps_check)
A_BASE_WRITE=$(write_works)
echo "  auth ${A_BASE_AUTH}s · ${A_BASE_QPS} TGS/s · write ${A_BASE_WRITE}s"
[[ "$A_BASE_WRITE" != FAIL ]] || { echo "FAIL: baseline write failed" >&2; exit 1; }

say "case A: killing region europe-west4 (roach-eu)"
docker compose stop roach-eu >/dev/null
A_AUTH=$(auth_works "$(now)")
A_QPS=$(qps_check)
A_WRITE=$(write_works)
echo "  auth ${A_AUTH}s · ${A_QPS} TGS/s · write ${A_WRITE}s"
[[ "$A_WRITE" != FAIL ]] ||
    { echo "FAIL: writes stopped with one region down" >&2; exit 1; }
awk -v q="$A_QPS" -v f="$QPS_FLOOR" 'BEGIN{exit !(q >= f)}' ||
    { echo "FAIL: ${A_QPS} TGS/s below floor $QPS_FLOOR" >&2; exit 1; }
le "$A_AUTH" "$AUTH_MAX_S" ||
    { echo "FAIL: auth took ${A_AUTH}s with one region down" >&2; exit 1; }
echo "OK: one region dead is transparent — auth + writes, no stale fallback"

say "case A: restoring roach-eu"
docker compose start roach-eu >/dev/null
wait_healthy roach-eu

say "case B: killing the PRIMARY region us-west2 (roach-west); KDC moves to roach-east"
# A KDC in the dead region dies with it; the surviving regions' KDCs must
# keep serving. Point the gateway at roach-east and restart, exactly as a
# regional KDC fleet is deployed.
render_kdc_conf localhost:26258
start_kdc
B_BASE_AUTH=$(auth_works "$(now)")
B_BASE_WRITE=$(write_works)
echo "  pre-kill (3/3 nodes, east gateway): auth ${B_BASE_AUTH}s · write ${B_BASE_WRITE}s"
docker compose stop roach-west >/dev/null
B_AUTH=$(auth_works "$(now)")
B_QPS=$(qps_check)
B_WRITE=$(write_works)
echo "  auth ${B_AUTH}s · ${B_QPS} TGS/s · write ${B_WRITE}s"
[[ "$B_WRITE" != FAIL ]] ||
    { echo "FAIL: writes stopped with the primary region down" >&2; exit 1; }
awk -v q="$B_QPS" -v f="$QPS_FLOOR" 'BEGIN{exit !(q >= f)}' ||
    { echo "FAIL: ${B_QPS} TGS/s below floor $QPS_FLOOR" >&2; exit 1; }
le "$B_AUTH" "$AUTH_MAX_S" ||
    { echo "FAIL: auth took ${B_AUTH}s with the primary region down" >&2; exit 1; }
echo "OK: primary-region death is transparent too (leases move, no stale fallback)"

say "restoring roach-west"
docker compose start roach-west >/dev/null
wait_healthy roach-west roach-east roach-eu

printf '\n\033[1mRESULTS (one region dead, stale_reads_ms=0)\033[0m\n'
printf '  voters per range / quorum            : %s / %s\n' "$NVOTERS" "$(( NVOTERS / 2 + 1 ))"
printf '  A baseline  auth/QPS/write           : %ss / %s / %ss\n' \
    "$A_BASE_AUTH" "$A_BASE_QPS" "$A_BASE_WRITE"
printf '  A eu down   auth/QPS/write           : %ss / %s / %ss\n' \
    "$A_AUTH" "$A_QPS" "$A_WRITE"
printf '  B baseline  auth/write (east gw)     : %ss / %ss\n' \
    "$B_BASE_AUTH" "$B_BASE_WRITE"
printf '  B west down auth/QPS/write           : %ss / %s / %ss\n' \
    "$B_AUTH" "$B_QPS" "$B_WRITE"
say "PASS: single-region loss is transparent without the stale fallback"
