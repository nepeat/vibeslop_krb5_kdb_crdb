#!/usr/bin/env bash
# Key rotation ACROSS a CRDB network partition: which kvno does each side
# issue, and when do they converge? (compose cluster)
#
# Requires the realm set up by e2e/run.sh (state dir + stress principals).
#
# Topology: roach-eu is cut from roach-west + roach-east by iptables rules
# installed INSIDE roach-eu's own network namespace (nsenter, needs sudo).
# The host bridge has no br_netfilter here, so container<->container
# traffic never reaches the host filter tables — cutting inside the netns
# is the only thing that actually enforces. Host->container published
# ports are untouched, which is the whole point: a minority CRDB node that
# its peers cannot reach but its local KDC still can.
#
#   KDC-majority   gateway localhost:26257 (roach-west)  KDC port 10088
#   KDC-minority   gateway localhost:26259 (roach-eu)    KDC port 11088
#
# Both run -w 1 on purpose: one worker == one entry cache + one circuit
# breaker + one CRDB connection, so every observation is deterministic.
#
# Phases:
#   1. baseline    both KDCs issue kvno v_old
#   2. partition   verified by polling peer dials (never sleep blind)
#   3. rotate the key through the MAJORITY side (ktadd -> v_new)
#      a. majority must serve v_new within entry_cache_ms (+ slack)
#      b. minority must keep serving v_old and NOTHING ELSE
#      c. keytab kinit proves WHICH KEY each side holds, cryptographically
#   4. heal        minority converges to v_new; convergence time measured
#                  (circuit-breaker hold + entry cache TTL)
#
# MINORITY_WINDOW_S (default 20) is how long the partition is held while
# sampling. Keep it under stale_reads_ms (30s): past that bound CRDB stops
# serving bounded-staleness reads at all — see e2e/staleness-bound.sh.
set -euo pipefail
cd "$(dirname "$0")/.."

if ! command -v kdb5_util >/dev/null 2>&1; then
    exec nix develop --command "$0" "$@"
fi

STATE="$PWD/e2e/.state"
CANARY="host/kvcanary.example.com"
MINORITY_WINDOW_S=${MINORITY_WINDOW_S:-20}
CONVERGE_MAX_S=${CONVERGE_MAX_S:-45}
EU=kdc_db_crdb-roach-eu-1
PEERS=(kdc_db_crdb-roach-west-1 kdc_db_crdb-roach-east-1)
[[ -f "$STATE/kdc.conf" ]] || { echo "run e2e/run.sh first (no state)"; exit 1; }

say() { printf '\n\033[1m== kvno-partition: %s\033[0m\n' "$*"; }
now() { date +%s.%N; }
since() { awk -v a="$1" -v b="$(now)" 'BEGIN{printf "%.2f", b - a}'; }
le() { awk -v a="$1" -v b="$2" 'BEGIN{exit !(a <= b)}'; }

export KRB5_CONFIG="$STATE/krb5.conf"
export KRB5_KDC_PROFILE="$STATE/kdc-maj.conf"

# -- partition plumbing ------------------------------------------------------
eu_pid() { docker inspect -f '{{.State.Pid}}' "$EU"; }
peer_ips() {
    docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' \
        "${PEERS[@]}"
}
partition_on() {
    local pid ip
    pid=$(eu_pid)
    for ip in $(peer_ips); do
        sudo nsenter -t "$pid" -n iptables -I INPUT -s "$ip" -j DROP
        sudo nsenter -t "$pid" -n iptables -I OUTPUT -d "$ip" -j DROP
    done
}
partition_off() {
    local pid
    pid=$(eu_pid) || return 0
    sudo nsenter -t "$pid" -n iptables -F INPUT 2>/dev/null || true
    sudo nsenter -t "$pid" -n iptables -F OUTPUT 2>/dev/null || true
}
# Poll a real dial from a peer: established flows and conntrack make
# "sleep and hope" unreliable (same lesson as k8s/kadmin-safety-test.sh).
wait_dial() { # <blocked|open>
    local want=$1 rc
    for _ in $(seq 60); do
        if docker exec "${PEERS[1]}" bash -c \
            'timeout 2 bash -c "exec 3<>/dev/tcp/roach-eu/26257"' >/dev/null 2>&1
        then rc=open; else rc=blocked; fi
        [[ "$rc" == "$want" ]] && { echo "  peer dial: $rc"; return 0; }
        sleep 0.5
    done
    echo "FAIL: peer dial never became $want" >&2
    return 1
}

cleanup() {
    partition_off || true
    pkill -x krb5kdc -u "$(id -u)" 2>/dev/null || true
    KRB5_KDC_PROFILE="$STATE/kdc-maj.conf" \
        kadmin.local -q "delprinc -force $CANARY" >/dev/null 2>&1 || true
}
trap cleanup EXIT
on_err() {
    echo "KVNO-PARTITION FAILED — kdc log tails:" >&2
    tail -5 "$STATE"/kdc-maj.log "$STATE"/kdc-min.log 2>/dev/null >&2 || true
}
trap on_err ERR

# -- configs: two KDCs, two gateways ----------------------------------------
say "rendering majority/minority KDC configs"
sed -e 's|kdc\.log|kdc-maj.log|' "$STATE/kdc.conf" >"$STATE/kdc-maj.conf"
sed -e 's|kdc_ports = 10088|kdc_ports = 11088|' \
    -e 's|kdc_tcp_ports = 10088|kdc_tcp_ports = 11088|' \
    -e 's|localhost:26257|localhost:26259|' \
    -e 's|kdc\.log|kdc-min.log|' "$STATE/kdc.conf" >"$STATE/kdc-min.conf"
# TCP + a generous client timeout: while degraded the KDC re-probes the
# primary every DEGRADED_HOLD_MS and eats a statement_timeout (1.5s) per
# uncached lookup. That is server behaviour under test, not a client
# failure, so don't let krb5's 1s UDP retransmit default hide it.
tune_client() { # <src krb5.conf> <kdc port> <dst>
    sed -e "s|127.0.0.1:10088|127.0.0.1:$2|" \
        -e 's|^\[libdefaults\]|[libdefaults]\n    udp_preference_limit = 1\n    kdc_timeout = 15000|' \
        "$1" >"$3"
}
tune_client "$STATE/krb5.conf" 10088 "$STATE/krb5-maj.conf"
tune_client "$STATE/krb5.conf" 11088 "$STATE/krb5-min.conf"
grep -q 'localhost:26259' "$STATE/kdc-min.conf" ||
    { echo "FAIL: minority conf did not get the roach-eu gateway" >&2; exit 1; }

probe_kvno() { # <krb5.conf> -> kvno integer, or ERR
    local conf=$1 cc="$STATE/kvp-probe.cc" out
    cp "$STATE/kvp-tgt.cc" "$cc"
    out=$(KRB5_CONFIG="$conf" KRB5CCNAME="FILE:$cc" \
        timeout 30 kvno "$CANARY" 2>/dev/null |
        sed -n 's/.*kvno = \([0-9][0-9]*\).*/\1/p') || true
    echo "${out:-ERR}"
}
keytab_auth() { # <krb5.conf> <keytab>  — 0 iff the KDC holds that key
    KRB5_CONFIG="$1" KRB5CCNAME="FILE:$STATE/kvp-kt.cc" \
        timeout 30 kinit -kt "$2" "$CANARY" >/dev/null 2>&1
}

say "starting both KDCs (-w 1 each)"
cargo build 2>/dev/null
pkill -x krb5kdc -u "$(id -u)" 2>/dev/null || true
sleep 0.5
KRB5_KDC_PROFILE="$STATE/kdc-maj.conf" krb5kdc -n -w 1 &
KRB5_KDC_PROFILE="$STATE/kdc-min.conf" krb5kdc -n -w 1 &
for port in 10088 11088; do
    for _ in $(seq 50); do
        (exec 3<>"/dev/tcp/127.0.0.1/$port") 2>/dev/null && break
        sleep 0.2
    done
done

say "phase 1: baseline — create $CANARY, ktadd -> kvp-old.keytab"
kadmin.local -q "delprinc -force $CANARY" >/dev/null 2>&1 || true
rm -f "$STATE/kvp-old.keytab" "$STATE/kvp-new.keytab"
kadmin.local -q "addprinc -randkey $CANARY" >/dev/null
kadmin.local -q "ktadd -k $STATE/kvp-old.keytab $CANARY" >/dev/null
KRB5_CONFIG="$STATE/krb5-maj.conf" KRB5CCNAME="FILE:$STATE/kvp-tgt.cc" \
    bash -c 'echo pw-u0000 | kinit u0000' >/dev/null
sleep 1.2 # let both entry caches lapse so the baseline is honest
V_OLD=$(probe_kvno "$STATE/krb5-maj.conf")
V_MIN=$(probe_kvno "$STATE/krb5-min.conf")
echo "  majority kvno=$V_OLD  minority kvno=$V_MIN"
[[ "$V_OLD" =~ ^[0-9]+$ && "$V_OLD" == "$V_MIN" ]] ||
    { echo "FAIL: baseline kvnos disagree ($V_OLD vs $V_MIN)" >&2; exit 1; }
V_NEW=$((V_OLD + 1))
echo "OK: both sides issue kvno $V_OLD before the partition"

say "phase 2: partitioning roach-eu from its peers"
partition_on
wait_dial blocked
T_PART=$(now)
echo "OK: roach-eu isolated; quorum lives on west+east"

say "phase 3: rotating the key through the MAJORITY side"
# Warm the majority KDC's entry cache immediately before the write, so the
# lag below measures real TTL-bounded staleness and not a cold cache.
probe_kvno "$STATE/krb5-maj.conf" >/dev/null
t0=$(now)
kadmin.local -q "ktadd -k $STATE/kvp-new.keytab $CANARY" >/dev/null
T_WRITE=$(now)
W_LAT=$(since "$t0")
echo "  ktadd (write, quorum present) took ${W_LAT}s"

# 3a. the majority must pick the new kvno up within its entry-cache TTL.
t0=$(now)
K=ERR
for _ in $(seq 300); do
    K=$(probe_kvno "$STATE/krb5-maj.conf")
    [[ "$K" != "$V_OLD" && "$K" != ERR ]] && break
    sleep 0.1
done
MAJ_LAG=$(since "$t0")
echo "  majority converged to kvno=$K after ${MAJ_LAG}s"
[[ "$K" == "$V_NEW" ]] ||
    { echo "FAIL: majority kvno is $K, expected $V_NEW" >&2; exit 1; }
le "$MAJ_LAG" 2.5 ||
    { echo "FAIL: majority took ${MAJ_LAG}s > entry_cache_ms + slack" >&2; exit 1; }
echo "OK: majority issues the NEW kvno within the entry-cache TTL"

# 3b. cryptographic proof of which key material each side actually holds.
say "phase 3b: keytab proof (AS-REQ decrypts under which key?)"
keytab_auth "$STATE/krb5-min.conf" "$STATE/kvp-old.keytab" ||
    { echo "FAIL: minority KDC does not hold the OLD key" >&2; exit 1; }
echo "OK: minority authenticates the OLD keytab"
keytab_auth "$STATE/krb5-maj.conf" "$STATE/kvp-new.keytab" ||
    { echo "FAIL: majority KDC does not hold the NEW key" >&2; exit 1; }
echo "OK: majority authenticates the NEW keytab"
if keytab_auth "$STATE/krb5-maj.conf" "$STATE/kvp-old.keytab"; then
    echo "FAIL: majority still accepts the OLD key after rotation" >&2; exit 1
fi
echo "OK: majority rejects the OLD keytab (the key really rotated)"

# 3c. the minority must serve the OLD kvno, and only that, for the window.
say "phase 3c: sampling the MINORITY side to t+${MINORITY_WINDOW_S}s"
bad=0 errs=0 samples=0
while :; do
    off=$(since "$T_PART")
    le "$off" "$MINORITY_WINDOW_S" || break
    k=$(probe_kvno "$STATE/krb5-min.conf")
    samples=$((samples + 1))
    printf '  t+%6ss  minority kvno=%s\n' "$off" "$k"
    case "$k" in
        "$V_OLD") STALE_OBS=$(since "$T_WRITE") ;;
        ERR) errs=$((errs + 1)); echo "    ^ request failed (degraded re-probe?)" ;;
        *) bad=$((bad + 1)); echo "    ^ UNEXPECTED KVNO" ;;
    esac
    sleep 2
done
echo "  $samples samples: $((samples - bad - errs)) served kvno=$V_OLD, $errs failed, $bad wrong"
[[ "$bad" -eq 0 ]] ||
    { echo "FAIL: minority served a kvno other than $V_OLD" >&2; exit 1; }
[[ "$errs" -le $((samples / 4)) ]] ||
    { echo "FAIL: minority failed $errs/$samples requests while degraded" >&2; exit 1; }
echo "OK: minority served ONLY the pre-partition kvno ($V_OLD)"
# The data really was stale, and by no more than the advertised bound.
STALE_MS=$(sed -n 's/.*stale_reads_ms *= *\([0-9]*\).*/\1/p' "$STATE/kdc-min.conf")
le "$STALE_OBS" "$(awk -v m="$STALE_MS" 'BEGIN{print m / 1000}')" ||
    { echo "FAIL: served data ${STALE_OBS}s old, bound is ${STALE_MS}ms" >&2; exit 1; }
echo "OK: worst observed data staleness ${STALE_OBS}s <= stale_reads_ms"

say "phase 4: heal — measuring minority convergence"
partition_off
wait_dial open
T_HEAL=$(now)
conv=ERR
while :; do
    off=$(since "$T_HEAL")
    le "$off" "$CONVERGE_MAX_S" || break
    [[ "$(probe_kvno "$STATE/krb5-min.conf")" == "$V_NEW" ]] && { conv=$off; break; }
    sleep 0.25
done
[[ "$conv" != ERR ]] ||
    { echo "FAIL: minority never converged within ${CONVERGE_MAX_S}s" >&2; exit 1; }
echo "OK: minority converged to kvno $V_NEW ${conv}s after heal"
keytab_auth "$STATE/krb5-min.conf" "$STATE/kvp-new.keytab" ||
    { echo "FAIL: minority does not hold the NEW key after heal" >&2; exit 1; }
echo "OK: minority authenticates the NEW keytab after heal"

printf '\n\033[1mRESULTS (kvno across a partition)\033[0m\n'
printf '  write (ktadd) through the majority  : %ss\n' "$W_LAT"
printf '  majority fresh-kvno lag after write : %ss (bound: entry_cache_ms)\n' "$MAJ_LAG"
printf '  minority window sampled             : %ss, %s samples, %s failed, all served kvno=%s\n' \
    "$MINORITY_WINDOW_S" "$samples" "$errs" "$V_OLD"
printf '  observed DATA staleness (minority)  : %ss after the write (bound: stale_reads_ms)\n' \
    "${STALE_OBS:-n/a}"
printf '  minority convergence after heal     : %ss (bound: DEGRADED_HOLD_MS + entry_cache_ms)\n' "$conv"
say "PASS: kvno partition semantics hold"
