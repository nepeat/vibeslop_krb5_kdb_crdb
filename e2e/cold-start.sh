#!/usr/bin/env bash
# Cold start during a total CRDB outage.
#
# Requires the realm set up by e2e/run.sh (state dir + stress principals).
#
# chaos.sh proves a RUNNING KDC survives quorum loss on its existing SQL
# session. This proves the harder case: the KDC PROCESS RESTARTS while the
# database is completely gone — the power-loss case — and still serves.
# It cannot lean on stale reads to do it: a NEW SQL session to a
# quorum-less node cannot even be established (CRDB's own user lookup and
# descriptor leasing need writes), which is exactly why the offline
# last-known-good cache exists.
#
# Phases:
#   1. healthy realm, warm the cache (incl. the K/M read krb5kdc does at
#      startup and the krbtgt read every request does)
#   2. stop ALL THREE roach nodes
#   3. restart krb5kdc with startup_retry_ms + the offline cache — it must
#      come up rather than exit and crash-loop
#   4. kinit + kvno must succeed from the cache, inside max age
#   5. a kadmin write and a lookup of an UNCACHED principal must fail —
#      and the lookup must NOT say "does not exist" (a partial cache may
#      never manufacture KDC_ERR_C_PRINCIPAL_UNKNOWN)
#   6. age out: restart with a max age the cached data cannot satisfy ->
#      auth fails closed
#   7. nodes back: the KDC converges to live reads, writes work again
#
# Everything is restored by the cleanup trap, including on failure.
set -euo pipefail
cd "$(dirname "$0")/.."

if ! command -v kdb5_util >/dev/null 2>&1; then
    exec nix develop --command "$0" "$@"
fi

STATE="$PWD/e2e/.state"
CERTS="$PWD/e2e/.certs"
REALM=EXAMPLE.COM
CACHE="$STATE/offline-cache.bin"
# Budget for the initial connect. Paid twice on a cold start (krb5kdc's
# supervisor opens the DB, then the worker re-opens after fork), and it is
# INCLUDED in the cold-start-to-first-ticket number reported at the end.
STARTUP_RETRY_MS=${STARTUP_RETRY_MS:-3000}
# Long enough that phases 4-5 can never age out by accident; phase 6 uses
# its own deliberately unsatisfiable value instead of sleeping it out.
MAX_AGE_MS=${MAX_AGE_MS:-900000}
STRICT_AGE_MS=${STRICT_AGE_MS:-1}
CONVERGE_MAX_S=${CONVERGE_MAX_S:-120}
COLD_USER=cold-user
COLD_PW=cold-pw
UNCACHED=cold-never-read
UNCACHED_PW=cold-never-read-pw
CRDB_URI_ROOT="postgresql://root:root-dev-pw@localhost:26257/krb5?sslmode=verify-full&sslrootcert=$CERTS/ca.crt"
[[ -f "$STATE/kdc.conf" ]] || { echo "run e2e/run.sh first (no state)"; exit 1; }

say() { printf '\n\033[1m== cold-start: %s\033[0m\n' "$*"; }
now() { date +%s.%N; }
since() { awk -v a="$1" -v b="$(now)" 'BEGIN{printf "%.2f", b - a}'; }
le() { awk -v a="$1" -v b="$2" 'BEGIN{exit !(a <= b)}'; }

# The profile under test = the e2e profile plus the three new knobs,
# spliced into the crdb stanza after stale_reads_ms (kept at its normal
# value: the point is that it CANNOT help across a restart).
mk_conf() { # mk_conf <outfile> <max_age_ms>
    sed -e "s|^\( *\)stale_reads_ms = .*|&\n\1startup_retry_ms = $STARTUP_RETRY_MS\n\1offline_cache_path = $CACHE\n\1offline_cache_max_age_ms = $2|" \
        "$STATE/kdc.conf" >"$1"
    grep -q offline_cache_path "$1" ||
        { echo "FAIL: could not splice knobs into kdc.conf" >&2; exit 1; }
}
mk_conf "$STATE/kdc-cold.conf" "$MAX_AGE_MS"
mk_conf "$STATE/kdc-cold-strict.conf" "$STRICT_AGE_MS"

export KRB5_CONFIG="$STATE/krb5.conf"
export KRB5_KDC_PROFILE="$STATE/kdc-cold.conf"
export KRB5CCNAME="FILE:$STATE/cold-cc"

start_kdc() { # start_kdc <profile>  -> KDC_PID; returns 1 if it never listens
    KRB5_KDC_PROFILE="$1" krb5kdc -n -w 1 &
    KDC_PID=$!
    for _ in $(seq 100); do
        (exec 3<>"/dev/tcp/127.0.0.1/10088") 2>/dev/null && return 0
        kill -0 "$KDC_PID" 2>/dev/null || return 1
        sleep 0.2
    done
    return 1
}
stop_kdc() {
    [[ -n "${KDC_PID:-}" ]] && kill "$KDC_PID" 2>/dev/null || true
    pkill -x krb5kdc -u "$(id -u)" 2>/dev/null || true
    wait "${KDC_PID:-}" 2>/dev/null || true
    KDC_PID=
}

cleanup() {
    stop_kdc
    docker compose start roach-west roach-east roach-eu >/dev/null 2>&1 || true
    rm -f "$CACHE"
}
trap cleanup EXIT
on_err() {
    echo "COLD-START FAILED — kdc log tail:" >&2
    tail -15 "$STATE/kdc.log" 2>/dev/null >&2 || true
}
trap on_err ERR

# -------------------------------------------------------------------------
say "phase 1: healthy realm, warm the offline cache"
# -------------------------------------------------------------------------
cargo build 2>/dev/null
pkill -x krb5kdc -u "$(id -u)" 2>/dev/null || true
rm -f "$CACHE"
sleep 0.5
# -w 1 on purpose: one worker == one offline cache == one connection ==
# one circuit breaker, so every number below is attributable.
start_kdc "$STATE/kdc-cold.conf" || { echo "FAIL: KDC did not start healthy" >&2; exit 1; }
kadmin.local -q "delprinc -force $COLD_USER" >/dev/null 2>&1 || true
kadmin.local -q "delprinc -force $UNCACHED" >/dev/null 2>&1 || true
kadmin.local -q "addprinc -pw $COLD_PW $COLD_USER" >/dev/null
# Deliberately created but NEVER looked up through the KDC: this is the
# principal that proves a partial cache does not answer "does not exist".
kadmin.local -q "addprinc -pw $UNCACHED_PW $UNCACHED" >/dev/null

kdestroy 2>/dev/null || true
echo "$COLD_PW" | kinit "$COLD_USER"           # AS: client + krbtgt
kvno host/h0001.example.com >/dev/null          # TGS: krbtgt + service
echo "OK: healthy auth, cache warming"

# The cache flushes the first change immediately and at most once per 10s
# after that (no background thread — flushes ride the request flow). Wait
# out one interval, then make one more request so the pending set lands.
sleep 11
kdestroy; echo "$COLD_PW" | kinit "$COLD_USER"
sleep 0.5
[[ -s "$CACHE" ]] || { echo "FAIL: no offline cache file at $CACHE" >&2; exit 1; }
mode=$(stat -c %a "$CACHE")
[[ "$mode" == 600 ]] || { echo "FAIL: cache mode $mode, want 600" >&2; exit 1; }
csize=$(stat -c %s "$CACHE")
# K/M is the one that decides whether a cold start is possible at all:
# krb5kdc reads it before it will listen on a socket.
grep -qa "K/M@$REALM" "$CACHE" ||
    { echo "FAIL: K/M not in the cache — a cold start cannot work" >&2; exit 1; }
grep -qa "krbtgt/$REALM@$REALM" "$CACHE" ||
    { echo "FAIL: krbtgt not in the cache" >&2; exit 1; }
grep -qa "$COLD_USER@$REALM" "$CACHE" ||
    { echo "FAIL: $COLD_USER not in the cache" >&2; exit 1; }
grep -qa "$UNCACHED@$REALM" "$CACHE" &&
    { echo "FAIL: $UNCACHED leaked into the cache; test is invalid" >&2; exit 1; }
echo "OK: cache warm ($csize bytes, 0600) with K/M + krbtgt + $COLD_USER"

# -------------------------------------------------------------------------
say "phase 2: stop ALL THREE CRDB nodes (total outage)"
# -------------------------------------------------------------------------
stop_kdc
docker compose stop roach-west roach-east roach-eu >/dev/null
T_OUTAGE=$(now)
# Nothing to fall back on inside CRDB: no node, no session, no quorum.
if timeout 10 psql "$CRDB_URI_ROOT" -c 'SELECT 1' >/dev/null 2>&1; then
    echo "FAIL: CRDB still answering after stopping every node" >&2; exit 1
fi
echo "OK: database is completely gone"

# -------------------------------------------------------------------------
say "phase 3: restart krb5kdc into the outage — it must come up"
# -------------------------------------------------------------------------
T_START=$(now)
start_kdc "$STATE/kdc-cold.conf" ||
    { echo "FAIL: krb5kdc did not come up without a database" >&2; exit 1; }
T_LISTEN=$(since "$T_START")
echo "OK: krb5kdc listening ${T_LISTEN}s after launch (no database at all)"

# -------------------------------------------------------------------------
say "phase 4: kinit + kvno from the offline cache"
# -------------------------------------------------------------------------
kdestroy 2>/dev/null || true
echo "$COLD_PW" | kinit "$COLD_USER"
T_TICKET=$(since "$T_START")
klist | grep -q "krbtgt/$REALM@$REALM" ||
    { echo "FAIL: no TGT in the ccache" >&2; exit 1; }
kvno host/h0001.example.com >/dev/null
echo "OK: AS-REQ and TGS-REQ both served with the database down"
echo "  cold start -> first ticket: ${T_TICKET}s (incl. ${STARTUP_RETRY_MS}ms retry budget, x2 for fork)"

# -------------------------------------------------------------------------
say "phase 5: writes and uncached lookups fail — with the RIGHT error"
# -------------------------------------------------------------------------
# Writes keep failing closed: no local buffering, no acks, no quorum.
if timeout 30 kadmin.local -q "addprinc -randkey cold-write-canary" \
    2>/dev/null | grep -q 'created\.'; then
    echo "FAIL: a write was acked with no database" >&2; exit 1
fi
echo "OK: kadmin write refused"

# The contract that matters: an uncached principal must NOT come back as
# "does not exist". The plugin returns KDC_ERR_SVC_UNAVAILABLE so a
# partial cache can never tell a client that a live principal is unknown.
kdestroy 2>/dev/null || true
uncached_err=$(echo "$UNCACHED_PW" | kinit "$UNCACHED" 2>&1 || true)
echo "  kinit $UNCACHED -> $uncached_err"
if echo "$UNCACHED_PW" | kinit "$UNCACHED" >/dev/null 2>&1; then
    echo "FAIL: an uncached principal authenticated offline" >&2; exit 1
fi
if grep -qiE "not found in kerberos database|principal unknown|does not exist" \
    <<<"$uncached_err"; then
    echo "FAIL: offline miss reported the principal as nonexistent" >&2
    echo "      ($uncached_err)" >&2
    exit 1
fi
echo "OK: offline miss is a service error, not 'does not exist'"

# The cached principal still works — the miss above was not collateral.
echo "$COLD_PW" | kinit "$COLD_USER"
echo "OK: cached principals unaffected"

# -------------------------------------------------------------------------
say "phase 6: age out — past offline_cache_max_age_ms auth fails closed"
# -------------------------------------------------------------------------
stop_kdc
kdestroy 2>/dev/null || true
# Same cache file, a max age it cannot possibly satisfy. Either krb5kdc
# refuses to start (it cannot read K/M) or it starts and refuses to
# authenticate: both are fail-closed, and neither may issue a ticket.
if start_kdc "$STATE/kdc-cold-strict.conf"; then
    echo "  KDC came up; checking that it refuses to authenticate"
    aged_err=$(echo "$COLD_PW" | kinit "$COLD_USER" 2>&1 || true)
    echo "  kinit $COLD_USER -> $aged_err"
    if echo "$COLD_PW" | kinit "$COLD_USER" >/dev/null 2>&1; then
        echo "FAIL: served principal data older than max_age" >&2; exit 1
    fi
else
    echo "  KDC refused to start (could not read K/M within max age)"
fi
echo "OK: expired cache data is refused, never served"
stop_kdc

# -------------------------------------------------------------------------
say "phase 7: nodes back — converge to live reads, writes work"
# -------------------------------------------------------------------------
start_kdc "$STATE/kdc-cold.conf" ||
    { echo "FAIL: KDC did not restart" >&2; exit 1; }
docker compose start roach-west roach-east roach-eu >/dev/null
until [[ "$(docker compose ps roach-west roach-east roach-eu 2>/dev/null | grep -c healthy)" == 3 ]]; do
    le "$(since "$T_OUTAGE")" 300 || { echo "FAIL: cluster never healthy" >&2; exit 1; }
    sleep 2
done
T_UP=$(now)
echo "  all three nodes healthy $(since "$T_OUTAGE")s after the outage began"

# Writes recovering is the definition of quorum being back; then chase
# that write through the KDC, same convention as staleness-bound.sh.
until kadmin.local -q "cpw -pw $COLD_PW-v2 $COLD_USER" 2>/dev/null | grep -q 'changed\.'; do
    le "$(since "$T_UP")" "$CONVERGE_MAX_S" ||
        { echo "FAIL: writes never recovered" >&2; exit 1; }
    sleep 1
done
T_WRITE=$(now)
echo "  writes recovered $(since "$T_UP")s after the nodes came back"
converged=ERR
while le "$(since "$T_WRITE")" "$CONVERGE_MAX_S"; do
    kdestroy 2>/dev/null || true
    if echo "$COLD_PW-v2" | kinit "$COLD_USER" >/dev/null 2>&1; then
        converged=$(since "$T_WRITE")
        break
    fi
    sleep 0.25
done
[[ "$converged" != ERR ]] ||
    { echo "FAIL: KDC never picked up the post-heal password" >&2; exit 1; }
echo "OK: KDC served the NEW password ${converged}s after the write"
# And it is genuinely reading live data again, not the cache: the cached
# blob still holds the OLD password.
kdestroy 2>/dev/null || true
if echo "$COLD_PW" | kinit "$COLD_USER" >/dev/null 2>&1; then
    echo "FAIL: still serving the pre-heal password from cache" >&2; exit 1
fi
# The principal the cache never had resolves again now that CRDB is back.
kdestroy 2>/dev/null || true
echo "$UNCACHED_PW" | kinit "$UNCACHED" >/dev/null ||
    { echo "FAIL: uncached principal still unavailable after recovery" >&2; exit 1; }
echo "OK: live reads restored (uncached principal resolves, cache superseded)"

kadmin.local -q "delprinc -force $COLD_USER" >/dev/null 2>&1 || true
kadmin.local -q "delprinc -force $UNCACHED" >/dev/null 2>&1 || true
kadmin.local -q "delprinc -force cold-write-canary" >/dev/null 2>&1 || true
kdestroy 2>/dev/null || true

printf '\n\033[1mRESULTS (cold start through a total CRDB outage)\033[0m\n'
printf '  startup_retry_ms / offline_cache_max_age_ms : %s / %s\n' \
    "$STARTUP_RETRY_MS" "$MAX_AGE_MS"
printf '  warm cache size                             : %s bytes (0600)\n' "$csize"
printf '  krb5kdc listening, no database              : %ss\n' "$T_LISTEN"
printf '  cold start -> first ticket                  : %ss\n' "$T_TICKET"
printf '  post-heal write -> KDC serves it            : %ss\n' "$converged"
say "PASS: KDC cold-started and served AS/TGS with CockroachDB entirely down"
