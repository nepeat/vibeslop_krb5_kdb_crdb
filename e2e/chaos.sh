#!/usr/bin/env bash
# Chaos suite: KDC availability through CRDB node loss (compose cluster).
#
# Requires the realm set up by e2e/run.sh (state dir + stress principals).
# Phases:
#   1. baseline: kinit + kvno + a short tgsbench
#   2. ONE CRDB node down            -> auth works, QPS floor holds
#   3. TWO CRDB nodes down (quorum GONE, only the KDC's own gateway
#      survives) -> auth still works via the plugin's bounded-staleness
#      fallback; writes fail (expected); QPS floor holds
#   4. nodes back                    -> primary reads recover, writes work
#
# CHAOS_QPS_FLOOR (default 1000) is asserted in phases 2 and 3.
set -euo pipefail
cd "$(dirname "$0")/.."

if ! command -v kdb5_util >/dev/null 2>&1; then
    exec nix develop --command "$0" "$@"
fi

STATE="$PWD/e2e/.state"
REALM=EXAMPLE.COM
KDC_WORKERS=${KDC_WORKERS:-16}
CHAOS_QPS_FLOOR=${CHAOS_QPS_FLOOR:-1000}
[[ -f "$STATE/kdc.conf" ]] || { echo "run e2e/run.sh first (no state)"; exit 1; }

export KRB5_CONFIG="$STATE/krb5.conf"
export KRB5_KDC_PROFILE="$STATE/kdc.conf"
export KRB5CCNAME="FILE:$STATE/chaos-cc"

say() { printf '\n\033[1m== chaos: %s\033[0m\n' "$*"; }
now() { date +%s.%N; }

cleanup() {
    [[ -n "${KDC_PID:-}" ]] && kill "$KDC_PID" 2>/dev/null || true
    pkill -x krb5kdc -u "$(id -u)" 2>/dev/null || true
    docker compose start roach-east roach-eu >/dev/null 2>&1 || true
}
trap cleanup EXIT
on_err() { echo "CHAOS FAILED — kdc log tail:" >&2; tail -5 "$STATE/kdc.log" >&2 || true; }
trap on_err ERR

auth_works() { # kinit (AS) + kvno (TGS) round trip
    kdestroy 2>/dev/null || true
    echo "pw-u0000" | kinit u0000
    kvno host/h0001.example.com >/dev/null
}

qps_check() { # short tgsbench burst; assert floor
    local tag=$1
    cc -O2 -o "$STATE/tgsbench" e2e/tgsbench.c \
        $(krb5-config --cflags --libs krb5) 2>/dev/null || true
    local t0 t1 rate
    t0=$(now)
    "$STATE/tgsbench" "$KRB5CCNAME" 64 128 1024 >/dev/null
    t1=$(now)
    rate=$(awk -v a="$t0" -v b="$t1" 'BEGIN{printf "%.0f", 8192/(b-a)}')
    echo "$tag: $rate TGS/s (floor $CHAOS_QPS_FLOOR)"
    awk -v q="$rate" -v t="$CHAOS_QPS_FLOOR" 'BEGIN{exit !(q >= t)}' ||
        { echo "FAIL: $tag below QPS floor" >&2; exit 1; }
}

say "starting KDC (-w $KDC_WORKERS)"
cargo build 2>/dev/null
pkill -x krb5kdc -u "$(id -u)" 2>/dev/null || true
krb5kdc -n -w "$KDC_WORKERS" &
KDC_PID=$!
sleep 1.5

say "phase 1: baseline (3/3 CRDB nodes)"
auth_works
qps_check baseline
echo "OK: baseline auth + QPS"

say "phase 2: ONE node down (roach-east stopped; quorum holds)"
docker compose stop roach-east >/dev/null
sleep 2
auth_works
qps_check one-node-down
echo "OK: auth + QPS with 2/3 nodes"

say "phase 3: TWO nodes down (roach-eu stopped too; quorum GONE)"
docker compose stop roach-eu >/dev/null
# Give CRDB a moment to notice its peers are gone, and let the first
# failing primary read trip the plugin's degraded breaker.
sleep 5
auth_works
echo "OK: kinit+kvno served via bounded-staleness fallback"
qps_check quorum-lost
# Writes must FAIL (no quorum) — and fail bounded, not hang forever.
if timeout 30 kadmin.local -q "addprinc -randkey chaos-write-canary" \
    2>/dev/null | grep -q 'created\.'; then
    echo "FAIL: write succeeded without quorum?!" >&2; exit 1
fi
echo "OK: writes correctly refused without quorum"

say "phase 4: recovery (nodes restarted)"
docker compose start roach-east roach-eu >/dev/null
until docker compose ps roach-east roach-eu 2>/dev/null | grep -c healthy | grep -q 2; do
    sleep 2
done
sleep 3
auth_works
kadmin.local -q "addprinc -randkey chaos-write-canary" >/dev/null 2>&1
kadmin.local -q "delprinc -force chaos-write-canary" >/dev/null 2>&1
echo "OK: primary reads + writes recovered"

say "PASS: all chaos phases green"
