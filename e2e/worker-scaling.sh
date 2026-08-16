#!/usr/bin/env bash
# Worker scaling curve: TGS throughput vs `krb5kdc -w N`.
#
# Requires the realm set up by e2e/run.sh (state dir + 1024 host principals).
#
# store.rs holds ONE synchronous CRDB connection per KdbModule instance,
# and `krb5kdc -w N` forks N processes that each open their own. This
# quantifies what that buys: QPS at N = 1,2,4,8,16,32 with a fixed client
# thread count, plus a direct check that the connection count really is
# per worker (crdb_internal.cluster_sessions, sampled UNDER load).
#
# Env: WORKER_CURVE (default "1 2 4 8 16 32"), TGS_THREADS (128).
set -euo pipefail
cd "$(dirname "$0")/.."

if ! command -v kdb5_util >/dev/null 2>&1; then
    exec nix develop --command "$0" "$@"
fi

STATE="$PWD/e2e/.state"
CERTS="$PWD/e2e/.certs"
WORKER_CURVE=${WORKER_CURVE:-"1 2 4 8 16 32"}
TGS_THREADS=${TGS_THREADS:-128}
NHOSTS=${NHOSTS:-1024}
QPS_LOG="$PWD/e2e/qps.log"
CRDB_URI_ROOT="postgresql://root:root-dev-pw@localhost:26257/krb5?sslmode=verify-full&sslrootcert=$CERTS/ca.crt"
[[ -f "$STATE/kdc.conf" ]] || { echo "run e2e/run.sh first (no state)"; exit 1; }

say() { printf '\n\033[1m== worker-scaling: %s\033[0m\n' "$*"; }
now() { date +%s.%N; }

export KRB5_CONFIG="$STATE/krb5.conf"
export KRB5_KDC_PROFILE="$STATE/kdc.conf"
export KRB5CCNAME="FILE:$STATE/ws-cc"

cleanup() { pkill -x krb5kdc -u "$(id -u)" 2>/dev/null || true; }
trap cleanup EXIT
on_err() {
    echo "WORKER-SCALING FAILED — kdc log tail:" >&2
    tail -5 "$STATE/kdc.log" 2>/dev/null >&2 || true
}
trap on_err ERR

sessions_now() { # krb5kdc SQL sessions across the whole cluster
    psql "$CRDB_URI_ROOT" -tAc \
        "SELECT count(*) FROM crdb_internal.cluster_sessions
         WHERE user_name = 'krb5kdc'" 2>/dev/null || echo -1
}

say "building bench + warming a TGT"
cargo build 2>/dev/null
cc -O2 -o "$STATE/tgsbench" e2e/tgsbench.c $(krb5-config --cflags --libs krb5)

RESULTS=()
for w in $WORKER_CURVE; do
    say "krb5kdc -w $w"
    pkill -x krb5kdc -u "$(id -u)" 2>/dev/null || true
    sleep 1
    krb5kdc -n -w "$w" &
    for _ in $(seq 50); do
        (exec 3<>"/dev/tcp/127.0.0.1/10088") 2>/dev/null && break
        sleep 0.2
    done
    kdestroy 2>/dev/null || true
    echo "pw-u0000" | kinit u0000 >/dev/null

    # Size the run so every point is a stable multi-second window without
    # making -w 1 take a minute.
    reqs=$((w * 4096))
    [[ "$reqs" -lt 8192 ]] && reqs=8192
    [[ "$reqs" -gt 65536 ]] && reqs=65536
    per=$((reqs / TGS_THREADS))
    reqs=$((per * TGS_THREADS))

    "$STATE/tgsbench" "$KRB5CCNAME" "$TGS_THREADS" 8 "$NHOSTS" >/dev/null # warm
    t0=$(now)
    "$STATE/tgsbench" "$KRB5CCNAME" "$TGS_THREADS" "$per" "$NHOSTS" >"$STATE/ws-$w.out" &
    BENCH=$!
    sleep 2
    sess=$(sessions_now)  # sampled UNDER load: one connection per worker?
    wait "$BENCH"
    t1=$(now)
    rate=$(awk -v a="$t0" -v b="$t1" -v n="$reqs" 'BEGIN{printf "%.0f", n/(b-a)}')
    secs=$(awk -v a="$t0" -v b="$t1" 'BEGIN{printf "%.1f", b-a}')
    procs=$(pgrep -c -x krb5kdc -u "$(id -u)" || echo 0)
    echo "  $(cat "$STATE/ws-$w.out") · ${rate} TGS/s · ${sess} krb5kdc SQL sessions · $procs krb5kdc processes"
    grep -q ' err=0$' "$STATE/ws-$w.out" ||
        { echo "FAIL: bench reported errors at -w $w" >&2; exit 1; }
    RESULTS+=("$w $rate $sess $procs $reqs $secs")
    printf '%s\t%s\tworker_scaling_w%s\tn=%s\t%ss\t%s/s\n' \
        "$(date -Is)" "$(git rev-parse --short HEAD 2>/dev/null || echo '-')" \
        "$w" "$reqs" "$secs" "$rate" >>"$QPS_LOG"
done

printf '\n\033[1mRESULTS (worker scaling, %s client threads, %s-host set)\033[0m\n' \
    "$TGS_THREADS" "$NHOSTS"
printf '  | -w | TGS/s | per-worker | CRDB sessions | procs | reqs |\n'
printf '  |---:|------:|-----------:|--------------:|------:|-----:|\n'
for r in "${RESULTS[@]}"; do
    read -r w rate sess procs reqs _ <<<"$r"
    printf '  | %2s | %5s | %10s | %13s | %5s | %5s |\n' \
        "$w" "$rate" "$((rate / w))" "$sess" "$procs" "$reqs"
done

# The contract under test: one synchronous CRDB connection PER WORKER.
say "connection accounting"
fail=0
for r in "${RESULTS[@]}"; do
    read -r w _ sess _ _ _ <<<"$r"
    # Measured: exactly w sessions for w+1 processes — the supervisor's
    # pre-fork handle is not a live session, each worker opens its own.
    # Anything below w means workers are sharing a socket.
    if [[ "$sess" -lt "$w" || "$sess" -gt $((w + 2)) ]]; then
        echo "FAIL: -w $w had $sess krb5kdc sessions (want $w..$((w + 2)))" >&2
        fail=1
    fi
done
[[ "$fail" -eq 0 ]] || exit 1
echo "OK: every worker holds its own CRDB connection"
say "PASS: scaling curve recorded (see e2e/qps.log)"
