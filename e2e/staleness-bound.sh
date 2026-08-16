#!/usr/bin/env bash
# How stale is "bounded stale", and for how long does it hold?
#
# Requires the realm set up by e2e/run.sh (state dir + stress principals).
#
# chaos.sh proves auth SURVIVES quorum loss. This measures the two numbers
# that claim implies but never checked:
#   G3  how old is the data the stale path actually serves, over time —
#       and does anything older than stale_reads_ms ever get served?
#   G4  after heal, how long until KDCs serve fresh data again?
#
# Method: one KDC (-w 1: one cache, one breaker, one connection) pinned to
# roach-west. A canary principal is cpw'd right before the partition, then
# roach-east + roach-eu are stopped (quorum GONE, west survives). Two
# samplers run across the outage:
#   * auth sampler — kinit the canary every second through the KDC
#   * SQL sampler  — ONE psql session opened BEFORE the partition (a new
#     one cannot authenticate: CRDB's own user lookup needs quorum) that
#     issues exactly the bounded-staleness read the plugin issues.
#
# NB on measuring staleness: under `with_max_staleness` the SQL-level
# now() reports the UPPER bound of the negotiation, not the timestamp the
# KV layer settled on (verified: under a fixed `AS OF SYSTEM TIME '-10s'`
# now() does move back 10s, under with_max_staleness it does not). So the
# staleness bound is not measured by asking now() — it is measured by the
# fact that CockroachDB REFUSES the read rather than serving past the
# bound, and the refusal message carries both timestamps:
#   "minimum timestamp bound of <now - stale_reads_ms> could not be
#    satisfied by a local resolved timestamp of <frozen at quorum loss>"
# That is the real contract enforcement, and it is what this asserts.
# Actual data-level staleness (a row that CHANGED on the other side of a
# partition) is measured by e2e/kvno-partition.sh.
#
# Then heal, cpw the canary to a new password, and time how long the KDC
# keeps authenticating the OLD one (circuit-breaker hold + cache TTL).
set -euo pipefail
cd "$(dirname "$0")/.."

if ! command -v kdb5_util >/dev/null 2>&1; then
    exec nix develop --command "$0" "$@"
fi

STATE="$PWD/e2e/.state"
CERTS="$PWD/e2e/.certs"
REALM=EXAMPLE.COM
CANARY=stale-canary
PW_OLD=sb-pw-old
PW_NEW=sb-pw-new
OUTAGE_S=${OUTAGE_S:-90}      # sample window; must exceed stale_reads_ms
FRESH_MAX_S=${FRESH_MAX_S:-30} # allowed post-heal convergence
SB_STALE_MS=${SB_STALE_MS:-}   # override stale_reads_ms for this run
CRDB_URI_ROOT="postgresql://root:root-dev-pw@localhost:26257/krb5?sslmode=verify-full&sslrootcert=$CERTS/ca.crt"
[[ -f "$STATE/kdc.conf" ]] || { echo "run e2e/run.sh first (no state)"; exit 1; }

# The profile under test, optionally with stale_reads_ms overridden — the
# control that separates "the plugin's staleness bound" from "some CRDB
# lease timer" as the thing that ends the outage-survival window.
if [[ -n "$SB_STALE_MS" ]]; then
    sed -e "s/stale_reads_ms = [0-9]*/stale_reads_ms = $SB_STALE_MS/" \
        "$STATE/kdc.conf" >"$STATE/kdc-sb.conf"
else
    cp "$STATE/kdc.conf" "$STATE/kdc-sb.conf"
fi
STALE_MS=$(sed -n 's/.*stale_reads_ms *= *\([0-9]*\).*/\1/p' "$STATE/kdc-sb.conf")
CACHE_MS=$(sed -n 's/.*entry_cache_ms *= *\([0-9]*\).*/\1/p' "$STATE/kdc-sb.conf")
: "${STALE_MS:?no stale_reads_ms in kdc.conf}"

say() { printf '\n\033[1m== staleness: %s\033[0m\n' "$*"; }
now() { date +%s.%N; }
since() { awk -v a="$1" -v b="$(now)" 'BEGIN{printf "%.2f", b - a}'; }
le() { awk -v a="$1" -v b="$2" 'BEGIN{exit !(a <= b)}'; }

export KRB5_CONFIG="$STATE/krb5-sb.conf"
export KRB5_KDC_PROFILE="$STATE/kdc-sb.conf"

cleanup() {
    [[ -n "${SQL_PID:-}" ]] && kill "$SQL_PID" 2>/dev/null || true
    [[ -n "${AUTH_PID:-}" ]] && kill "$AUTH_PID" 2>/dev/null || true
    pkill -x krb5kdc -u "$(id -u)" 2>/dev/null || true
    docker compose start roach-east roach-eu >/dev/null 2>&1 || true
    kadmin.local -q "delprinc -force $CANARY" >/dev/null 2>&1 || true
}
trap cleanup EXIT
on_err() {
    echo "STALENESS RUN FAILED — kdc log tail:" >&2
    tail -5 "$STATE/kdc.log" 2>/dev/null >&2 || true
}
trap on_err ERR

# Force TCP and a long client timeout: while degraded the KDC re-probes
# the primary every DEGRADED_HOLD_MS and eats a statement_timeout per
# uncached lookup. That latency is the measurement, not a client failure.
sed -e 's|^\[libdefaults\]|[libdefaults]\n    udp_preference_limit = 1\n    kdc_timeout = 20000|' \
    "$STATE/krb5.conf" >"$STATE/krb5-sb.conf"

SQL_LOG="$STATE/sb-sql.log"
AUTH_LOG="$STATE/sb-auth.log"

auth_probe() { # -> "ok|fail <secs>"  (kinit == AS-REQ through the plugin)
    local t0 rc pw=${2:-$PW_OLD}
    t0=$(now)
    if echo "$pw" | KRB5CCNAME="FILE:$STATE/sb-cc.$1" \
        timeout 25 kinit "$CANARY" >/dev/null 2>&1
    then rc=ok; else rc=fail; fi
    echo "$rc $(since "$t0")"
}

say "starting KDC (-w 1) and creating $CANARY"
cargo build 2>/dev/null
pkill -x krb5kdc -u "$(id -u)" 2>/dev/null || true
sleep 0.5
krb5kdc -n -w 1 &
for _ in $(seq 50); do
    (exec 3<>"/dev/tcp/127.0.0.1/10088") 2>/dev/null && break
    sleep 0.2
done
kadmin.local -q "delprinc -force $CANARY" >/dev/null 2>&1 || true
kadmin.local -q "addprinc -pw $PW_OLD $CANARY" >/dev/null
read -r rc lat <<<"$(auth_probe base)"
[[ "$rc" == ok ]] || { echo "FAIL: baseline kinit failed" >&2; exit 1; }
echo "OK: baseline kinit ${lat}s"
echo "  stale_reads_ms=$STALE_MS  entry_cache_ms=$CACHE_MS"

say "arming samplers (SQL session opened while quorum still exists)"
# Same read the plugin issues, plus the read timestamp. extract(epoch)
# keeps the arithmetic in awk instead of date parsing.
{
    for _ in $(seq "$((OUTAGE_S + 20))"); do
        echo "SELECT 'W|'||extract(epoch from clock_timestamp());"
        echo "SELECT 'S|'||extract(epoch from clock_timestamp())||'|'|| \
              extract(epoch from now())||'|'||extract(epoch from updated_at) \
              FROM principals AS OF SYSTEM TIME \
              with_max_staleness('${STALE_MS}ms', true) \
              WHERE name = '$CANARY@$REALM';"
        echo "SELECT pg_sleep(1);"
    done
} >"$STATE/sb-sampler.sql"
: >"$SQL_LOG"
psql "$CRDB_URI_ROOT" -tA -f "$STATE/sb-sampler.sql" >>"$SQL_LOG" 2>&1 &
SQL_PID=$!
: >"$AUTH_LOG"
(
    i=0
    while :; do
        i=$((i + 1))
        read -r rc lat <<<"$(auth_probe loop)"
        printf '%s %s %s\n' "$(now)" "$rc" "$lat" >>"$AUTH_LOG"
        sleep 1
    done
) &
AUTH_PID=$!
sleep 3 # a few healthy samples for the baseline

say "cpw the canary (last write before the partition), then kill quorum"
kadmin.local -q "cpw -pw $PW_OLD $CANARY" >/dev/null
docker compose stop roach-east roach-eu >/dev/null
T_PART=$(now)
echo "  quorum lost at t=0; sampling for ${OUTAGE_S}s"
while le "$(since "$T_PART")" "$OUTAGE_S"; do sleep 2; done
kill "$SQL_PID" 2>/dev/null || true
kill "$AUTH_PID" 2>/dev/null || true
wait "$SQL_PID" 2>/dev/null || true
wait "$AUTH_PID" 2>/dev/null || true

say "analysis: how long the bounded-stale read kept being served"
awk -F'|' -v t0="$T_PART" -v cap="$STALE_MS" '
    /^S\|/ { n++; age = $2 - $4
             printf "  t+%6.1fs  served the canary row (written %.1fs ago)\n",
                    $2 - t0, age
             if ($2 - t0 > lastok) lastok = $2 - t0
             next }
    /bounded staleness read/ { bs++; next }
    /replica unavailable/    { ru++; next }
    END {
        printf "\n  samples=%d  (staleness bound %.1fs)\n", n, cap / 1000
        printf "  last successful stale read at t+%.1fs\n", lastok
        printf "  errors: %d bounded-staleness-unsatisfiable, %d replica-unavailable\n",
               bs, ru
        printf "AOSTERR %d\nRUERR %d\nLASTOK %.1f\n", bs, ru, lastok > "/dev/stderr"
    }' "$SQL_LOG" 2>"$STATE/sb-sql.summary"
AOSTERR=$(awk '/^AOSTERR/{print $2}' "$STATE/sb-sql.summary")
SQL_LASTOK=$(awk '/^LASTOK/{print $2}' "$STATE/sb-sql.summary")

# CRDB spells the whole mechanism out in the first refusal:
#   "minimum timestamp bound of <now - stale_reads_ms> could not be
#    satisfied by a local resolved timestamp of <frozen at quorum loss>"
# so the survival window is (resolved_ts_freeze + stale_reads_ms).
FIRST_BS=$(grep -m1 'bounded staleness read' "$SQL_LOG" || true)
[[ -n "$FIRST_BS" ]] ||
    { echo "FAIL: reads never hit the staleness bound in ${OUTAGE_S}s" >&2; exit 1; }
MINB=$(sed -n 's/.*minimum timestamp bound of \([0-9]*\.[0-9]*\).*/\1/p' <<<"$FIRST_BS")
RESV=$(sed -n 's/.*local resolved timestamp of \([0-9]*\.[0-9]*\).*/\1/p' <<<"$FIRST_BS")
FREEZE=$(awk -v t0="$T_PART" -v rv="$RESV" 'BEGIN{printf "%+.2f", rv - t0}')
REFUSED=$(awk -v t0="$T_PART" -v mb="$MINB" -v cap="$STALE_MS" \
    'BEGIN{printf "%.2f", mb + cap/1000 - t0}')
printf '  local resolved timestamp froze at t%ss (quorum loss)\n' "$FREEZE"
printf '  first refusal once now-%sms passed it: t+%ss\n' "$STALE_MS" "$REFUSED"
# Hard contract: nothing may be served past freeze + stale_reads_ms. CRDB
# refuses instead of serving older, so the *served window* is the proof.
le "$SQL_LASTOK" \
   "$(awk -v f="$FREEZE" -v m="$STALE_MS" 'BEGIN{print f + m/1000 + 2}')" ||
    { echo "FAIL: still serving at t+${SQL_LASTOK}s, past the bound" >&2; exit 1; }
echo "OK: reads stopped exactly at the bound; nothing older was served"

say "analysis: KDC auth availability across the outage"
awk -v t0="$T_PART" '
    { off = $1 - t0
      if (off < -0.5) { pre++; if ($2 != "ok") prefail++; next }
      n++
      printf "  t+%6.1fs  kinit %-4s %6.2fs\n", off, $2, $3
      if ($2 == "ok") { ok++; if (off > lastok) lastok = off }
      else if (firstfail == "") firstfail = off
      if ($3 + 0 > maxlat) maxlat = $3 + 0 }
    END {
        printf "\n  pre-partition: %d probes (%d failed)\n", pre, prefail
        printf "  post-partition: %d probes, %d ok, last ok at t+%.1fs\n", n, ok, lastok
        printf "  first failure at t+%s, worst latency %.2fs\n",
               (firstfail == "" ? "never" : sprintf("%.1fs", firstfail)), maxlat
        printf "LASTOK %.1f\nFIRSTFAIL %s\nMAXLAT %.2f\nOK %d\n",
               lastok, (firstfail == "" ? -1 : firstfail), maxlat, ok > "/dev/stderr"
    }' "$AUTH_LOG" 2>"$STATE/sb-auth.summary"
AUTH_LASTOK=$(awk '/^LASTOK/{print $2}' "$STATE/sb-auth.summary")
AUTH_FIRSTFAIL=$(awk '/^FIRSTFAIL/{print $2}' "$STATE/sb-auth.summary")
AUTH_MAXLAT=$(awk '/^MAXLAT/{print $2}' "$STATE/sb-auth.summary")
# Contract floor: bounded-stale auth must survive most of the window it
# advertises. (Whether it survives the WHOLE outage is the finding, not
# the assertion — CRDB refuses once the bound is exceeded.)
FLOOR=$(awk -v m="$STALE_MS" 'BEGIN{f = 0.8 * m / 1000; print (f > 10 ? 10 : f)}')
le "$FLOOR" "$AUTH_LASTOK" ||
    { echo "FAIL: auth died ${AUTH_LASTOK}s in, floor is ${FLOOR}s" >&2; exit 1; }
echo "OK: bounded-stale auth held to t+${AUTH_LASTOK}s"

say "phase 4: heal, then measure time-to-fresh"
docker compose start roach-east roach-eu >/dev/null
until [[ "$(docker compose ps roach-east roach-eu 2>/dev/null | grep -c healthy)" == 2 ]]; do
    sleep 2
done
# Wait for quorum to actually be back: the first write that succeeds is
# the definition, and it is also the write we then chase.
T_HEAL=$(now)
until kadmin.local -q "cpw -pw $PW_NEW $CANARY" 2>/dev/null | grep -q 'changed\.'; do
    le "$(since "$T_HEAL")" 120 || { echo "FAIL: writes never recovered" >&2; exit 1; }
    sleep 1
done
T_CPW=$(now)
echo "  writes recovered $(since "$T_HEAL")s after nodes came back"
fresh=ERR
while le "$(since "$T_CPW")" "$FRESH_MAX_S"; do
    read -r rc _ <<<"$(auth_probe fresh "$PW_NEW")"
    [[ "$rc" == ok ]] && { fresh=$(since "$T_CPW"); break; }
    sleep 0.25
done
[[ "$fresh" != ERR ]] ||
    { echo "FAIL: KDC never served the post-heal password" >&2; exit 1; }
echo "OK: KDC served the NEW password ${fresh}s after the write"
read -r rc _ <<<"$(auth_probe stale-check "$PW_OLD")"
[[ "$rc" == fail ]] ||
    { echo "FAIL: KDC still accepts the pre-heal password" >&2; exit 1; }
echo "OK: the pre-heal password is no longer accepted (serving fresh)"

printf '\n\033[1mRESULTS (staleness bound + convergence)\033[0m\n'
printf '  stale_reads_ms / entry_cache_ms      : %s / %s\n' "$STALE_MS" "$CACHE_MS"
printf '  resolved timestamp froze at          : t%ss\n' "$FREEZE"
printf '  bounded-stale reads served until     : t+%ss (%s later refused)\n' \
    "$SQL_LASTOK" "$AOSTERR"
printf '  == survival window under quorum loss : ~stale_reads_ms\n'
printf '  KDC auth last ok / first fail        : t+%ss / t+%ss\n' \
    "$AUTH_LASTOK" "$AUTH_FIRSTFAIL"
printf '  worst auth latency while degraded    : %ss\n' "$AUTH_MAXLAT"
printf '  post-heal time-to-fresh              : %ss\n' "$fresh"
say "PASS: staleness stayed inside the advertised bound"
