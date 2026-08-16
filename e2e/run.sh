#!/usr/bin/env bash
# End-to-end test: real krb5kdc + kadmind running on the kdb_crdb backend
# against the docker-compose CockroachDB cluster.
#
#   docker compose up -d        # once
#   e2e/run.sh                  # re-execs itself inside `nix develop`
#
# Exercises: kdb5_util create -s, kadmin (over the network) addprinc/ktadd,
# kinit with a password, kinit with the extracted keytab, and kvno (TGS-REQ).
# DESTRUCTIVE to the dev DB: truncates the principals/policies tables first.
set -euo pipefail
cd "$(dirname "$0")/.."

# All krb5 tools come from the pinned flake (same libkdb5 the plugin links).
if ! command -v kdb5_util >/dev/null 2>&1; then
    exec nix develop --command "$0" "$@"
fi

STATE="$PWD/e2e/.state"
CERTS="$PWD/e2e/.certs"
CRDB_URI_ROOT="postgresql://root:root-dev-pw@localhost:26257/krb5?sslmode=verify-full&sslrootcert=$CERTS/ca.crt"
REALM=EXAMPLE.COM
KDC_WORKERS=${KDC_WORKERS:-16}
MASTER_PW=e2e-master-pw
ADMIN_PW=e2e-admin-pw
ALICE_PW=e2e-alice-pw
HOSTPRINC=host/e2e.example.com

say() { printf '\n\033[1m== %s\033[0m\n' "$*"; }

say "building plugin"
cargo build

say "resetting state"
rm -rf "$STATE"
mkdir -p "$STATE/plugins/kdb"
ln -s "$PWD/target/debug/libkdb_crdb.so" "$STATE/plugins/kdb/kdb_crdb.so"
sed -e "s|@STATE@|$STATE|g" -e "s|@PLUGINS@|$STATE/plugins|g" \
    e2e/krb5.conf.in >"$STATE/krb5.conf"
sed -e "s|@STATE@|$STATE|g" -e "s|@PLUGINS@|$STATE/plugins|g" \
    -e "s|@CERTS@|$CERTS|g" e2e/kdc.conf.in >"$STATE/kdc.conf"
echo "admin/admin@$REALM *" >"$STATE/kadm5.acl"

export KRB5_CONFIG="$STATE/krb5.conf"
export KRB5_KDC_PROFILE="$STATE/kdc.conf"
export KRB5CCNAME="FILE:$STATE/ccache"

psql "$CRDB_URI_ROOT" -c 'TRUNCATE principals, policies; TRUNCATE aliases' >/dev/null ||
    { echo "cannot reach CRDB — run: docker compose up -d" >&2; exit 1; }

# GLOBAL-table writes commit-wait ~800ms so all regions can serve non-stale
# reads. On a single dev box there is no clock skew or WAN propagation to
# cover, so shrink the lead and make writes fast. TRUE_LATENCY=1 keeps the
# production commit-wait for honest write-latency numbers.
if [[ "${TRUE_LATENCY:-0}" != 1 ]]; then
    psql "$CRDB_URI_ROOT" -c "SET CLUSTER SETTING \
        kv.closed_timestamp.lead_for_global_reads_override = '25ms'" >/dev/null
    echo "dev mode: global-reads commit-wait override 25ms (TRUE_LATENCY=1 to disable)"
fi

cleanup() {
    [[ -n "${KDC_PID:-}" ]] && kill "$KDC_PID" 2>/dev/null || true
    [[ -n "${KADMIND_PID:-}" ]] && kill "$KADMIND_PID" 2>/dev/null || true
    pkill -x krb5kdc 2>/dev/null || true # -w worker children
}
on_err() {
    echo "FAILED — daemon logs:" >&2
    tail -n 25 "$STATE"/kdc.log "$STATE"/kadmind.log 2>/dev/null >&2 || true
}
trap cleanup EXIT
trap on_err ERR

say "kdb5_util create (master key -> stash + K/M into CRDB)"
kdb5_util create -s -P "$MASTER_PW"

say "starting krb5kdc (-w $KDC_WORKERS) + kadmind"
# -w forks worker processes that share the UDP port; each dlopens the
# plugin and holds its own CRDB connection. This is the supported way to
# scale KDC throughput, and what production would run.
krb5kdc -n -w "$KDC_WORKERS" &
KDC_PID=$!
kadmin.local -q "addprinc -pw $ADMIN_PW admin/admin" >/dev/null
kadmind -nofork &
KADMIND_PID=$!
for port in 10088 10749; do
    for _ in $(seq 50); do
        (exec 3<>"/dev/tcp/127.0.0.1/$port") 2>/dev/null && break
        sleep 0.2
    done
done

say "kadmin (network): addprinc alice, addprinc -randkey $HOSTPRINC"
kadmin -p admin/admin -w "$ADMIN_PW" -q "addprinc -pw $ALICE_PW alice"
kadmin -p admin/admin -w "$ADMIN_PW" -q "addprinc -randkey $HOSTPRINC"

say "kadmin (network): ktadd -> $STATE/e2e.keytab"
kadmin -p admin/admin -w "$ADMIN_PW" -q "ktadd -k $STATE/e2e.keytab $HOSTPRINC"
klist -kte "$STATE/e2e.keytab"

say "kinit alice (password, AS-REQ)"
echo "$ALICE_PW" | kinit alice
klist

say "kvno $HOSTPRINC (TGS-REQ)"
kvno "$HOSTPRINC"

say "kinit -kt (keytab, AS-REQ with keys from ktadd)"
kdestroy
kinit -kt "$STATE/e2e.keytab" "$HOSTPRINC"
klist

say "backend validation: kdb_crdb loaded, no BDB/LMDB fallback"
# The right plugin is mapped into both daemons, and none of the other
# KDB backends are.
grep -q 'libkdb_crdb\.so\|plugins/kdb/kdb_crdb\.so' "/proc/$KDC_PID/maps"
grep -q 'libkdb_crdb\.so\|plugins/kdb/kdb_crdb\.so' "/proc/$KADMIND_PID/maps"
if grep -qE 'kdb/(db2|klmdb|kldap)\.so' "/proc/$KDC_PID/maps"; then
    echo "FAIL: a local KDB backend (db2/klmdb/kldap) is loaded in the KDC" >&2
    exit 1
fi
# No local database files: BDB/LMDB would materialize principal* files.
if find "$STATE" /var/lib/krb5kdc -name 'principal*' 2>/dev/null | grep -q .; then
    echo "FAIL: local principal database files found — BDB/LMDB fallback?" >&2
    exit 1
fi

say "backend validation: KDC reads come from CRDB (SQL delete kills kinit)"
kadmin -p admin/admin -w "$ADMIN_PW" -q "addprinc -pw canary-pw canary" >/dev/null
echo canary-pw | kinit canary
kdestroy
psql "$CRDB_URI_ROOT" -c "DELETE FROM principals WHERE name = 'canary@$REALM'" >/dev/null
sleep 1.2 # KDC entry cache TTL (entry_cache_ms, default 1000) must lapse
if echo canary-pw | kinit canary 2>/dev/null; then
    echo "FAIL: kinit still works after deleting the row from CRDB" >&2
    exit 1
fi
echo "OK: principal deleted via SQL is immediately unknown to the KDC"

say "aliases: operator-managed alias resolution (LookupFlags)"
# Aliases live in an operator-managed SQL table (no kadmin verbs, like
# kldap's LDAP-side aliases). In-realm aliases resolve for both server
# (TGS) and client (AS, canonicalize) lookups; an out-of-realm canonical
# name is a referral and must NOT resolve without KRB5_KDB_FLAG_REFERRAL_OK.
psql "$CRDB_URI_ROOT" -c "UPSERT INTO aliases (alias, canonical) VALUES \
    ('websvc/e2e.example.com@$REALM', '$HOSTPRINC@$REALM'), \
    ('alicia@$REALM', 'alice@$REALM'), \
    ('ghost@$REALM', 'nobody@OTHER.REALM')" >/dev/null
echo "$ALICE_PW" | kinit alice
kvno websvc/e2e.example.com # server alias: resolves via the aliases table
kdestroy
echo "$ALICE_PW" | kinit -C alicia # client alias: AS-REQ w/ canonicalize
klist | grep -q "alice@$REALM" ||
    { echo "FAIL: kinit -C alicia did not canonicalize to alice" >&2; exit 1; }
kdestroy
# Since krb5 1.20 the KDC accepts AS requests for client aliases WITHOUT
# the canonicalize flag, issuing the ticket under the requested name.
echo "$ALICE_PW" | kinit alicia
kdestroy
if echo x | kinit ghost 2>/dev/null; then
    echo "FAIL: out-of-realm alias resolved on an AS client lookup" >&2
    exit 1
fi
echo "OK: in-realm aliases resolve (TGS + AS -C); out-of-realm gated on REFERRAL_OK"

say "renprinc: atomic rename, keys survive, no clobber of existing targets"
# Exercises the rename txn (read + rewrite + swap inside one serializable
# txn — see store.rs::rename_principal) through real kadmind RPC.
kadmin -p admin/admin -w "$ADMIN_PW" -q "addprinc -pw ren-pw renate" >/dev/null
kadmin -p admin/admin -w "$ADMIN_PW" -q "renprinc -force renate renate2"
echo ren-pw | kinit renate2 # same password: key data survived the rename
kdestroy
if echo ren-pw | kinit renate 2>/dev/null; then
    echo "FAIL: old name still authenticates after renprinc" >&2
    exit 1
fi
# Renaming onto an existing principal must be refused (kadm5 checks dups,
# and the backend independently returns EEXIST instead of clobbering).
kadmin -p admin/admin -w "$ADMIN_PW" -q "renprinc -force renate2 alice" \
    2>/dev/null || true
echo "$ALICE_PW" | kinit alice # victim entry intact (kadmin acks lie; kinit is truth)
kdestroy
[ "$(psql -tA "$CRDB_URI_ROOT" -c \
    "SELECT count(*) FROM principals WHERE name IN ('renate2@$REALM', 'alice@$REALM')")" = 2 ] ||
    { echo "FAIL: rename-onto-existing lost a principal row" >&2; exit 1; }
kadmin -p admin/admin -w "$ADMIN_PW" -q "delprinc -force renate2" >/dev/null
echo "OK: renprinc renames atomically and refuses to overwrite"

say "backend validation: TLS is enforced (plaintext SQL is rejected)"
if psql "postgresql://root:root-dev-pw@localhost:26257/krb5?sslmode=disable" \
    -c 'SELECT 1' >/dev/null 2>&1; then
    echo "FAIL: cluster accepted a plaintext connection" >&2
    exit 1
fi
echo "OK: cluster refuses sslmode=disable; KDC/kadmind sessions are verify-full TLS"

# ---------------------------------------------------------------------------
# Stress + QPS. Results append to e2e/qps.log (TSV: when, rev, phase, n,
# seconds, rate) so runs are comparable across code changes.
# ---------------------------------------------------------------------------
STRESS_N=${STRESS_N:-1024}
STRESS_WORKERS=${STRESS_WORKERS:-32}
TGS_TARGET_QPS=${TGS_TARGET_QPS:-4000}
TGS_N=${TGS_N:-32768}       # TGS bench volume: a stable multi-second window
TGS_THREADS=${TGS_THREADS:-64}
QPS_LOG="$PWD/e2e/qps.log"
now() { date +%s.%N; }
rec() { # rec <phase> <count> <t0>  — compute rate, print + append to log
    local secs rate
    secs=$(awk -v a="$3" -v b="$(now)" 'BEGIN{printf "%.1f", b - a}')
    rate=$(awk -v n="$2" -v s="$secs" 'BEGIN{printf "%.1f", n / s}')
    printf '%s\t%s\t%s\tn=%s\t%ss\t%s/s\n' \
        "$(date -Is)" "$(git rev-parse --short HEAD 2>/dev/null || echo '-')" \
        "$1" "$2" "$secs" "$rate" | tee -a "$QPS_LOG"
}

say "stress: $STRESS_N users + $STRESS_N hosts across $STRESS_WORKERS kadmin.local workers"
# GLOBAL-table writes each pay a commit-wait; that's latency, not
# throughput — independent rows don't conflict, so parallel workers scale.
t0=$(now)
worker_pids=()
for w in $(seq 0 $((STRESS_WORKERS - 1))); do
    for ((i = w; i < STRESS_N; i += STRESS_WORKERS)); do
        printf 'addprinc -pw pw-u%04d u%04d\naddprinc -randkey host/h%04d.example.com\n' \
            "$i" "$i" "$i"
    done | kadmin.local >"$STATE/stress-addprinc.$w.log" 2>&1 &
    worker_pids+=($!)
done
wait "${worker_pids[@]}"
rec write_addprinc $((STRESS_N * 2)) "$t0"

users=$(psql "$CRDB_URI_ROOT" -tAc \
    "SELECT count(*) FROM principals WHERE name ~ '^u[0-9]{4}@'")
hosts=$(psql "$CRDB_URI_ROOT" -tAc \
    "SELECT count(*) FROM principals WHERE name LIKE 'host/h%'")
[[ "$users" -eq "$STRESS_N" && "$hosts" -eq "$STRESS_N" ]] ||
    { echo "FAIL: CRDB has $users users / $hosts hosts, want $STRESS_N each" >&2; exit 1; }
echo "OK: all $((STRESS_N * 2)) rows present in CRDB"

say "qps: get_principal reads (batched getprinc)"
t0=$(now)
for ((i = 0; i < STRESS_N; i++)); do
    printf 'getprinc u%04d\n' "$i"
done | kadmin.local >"$STATE/stress-getprinc.log" 2>&1
rec read_getprinc "$STRESS_N" "$t0"

say "qps: paged iteration (listprincs crosses the 512-row page size)"
t0=$(now)
listed=$(kadmin.local -q listprincs 2>/dev/null | grep -c "@$REALM")
[[ "$listed" -ge $((STRESS_N * 2)) ]] ||
    { echo "FAIL: listprincs saw $listed principals" >&2; exit 1; }
rec iterate_listprincs "$listed" "$t0"

say "qps: TGS-REQ serial latency (256 tickets, one client)"
# Serial single-client number = per-request latency, NOT server capacity.
# Kept small: a FILE ccache grows per ticket and re-parsing it dominates
# past a few hundred entries (client-side artifact).
echo "pw-u0000" | kinit u0000
host_args=()
for ((i = 0; i < 256; i++)); do
    host_args+=("host/h$(printf '%04d' "$i").example.com")
done
t0=$(now)
kvno "${host_args[@]}" >"$STATE/stress-kvno.log" 2>&1
rec read_tgs_kvno_serial 256 "$t0"

say "qps: TGS-REQ throughput (tgsbench: $TGS_N reqs, $TGS_THREADS threads vs $KDC_WORKERS KDC workers)"
# This is the number that matters for the AS/TGS read path. kvno-based
# load benchmarks fork/exec + FILE-ccache re-parsing, not the KDC;
# tgsbench keeps threads hot on krb5_get_credentials(KRB5_GC_NO_STORE) —
# every call is a full TGS-REQ on the wire.
cc -O2 -o "$STATE/tgsbench" e2e/tgsbench.c \
    $(krb5-config --cflags --libs krb5)
kdestroy
echo "pw-u0000" | kinit u0000 # TGT-only ccache shared read-only by threads
t0=$(now)
"$STATE/tgsbench" "FILE:$STATE/ccache" "$TGS_THREADS" \
    $((TGS_N / TGS_THREADS)) "$STRESS_N"
rec read_tgs_bench "$TGS_N" "$t0"
tgs_qps=$(tail -1 "$QPS_LOG" | grep -o '[0-9.]*\/s' | tr -d '/s')
awk -v q="$tgs_qps" -v t="$TGS_TARGET_QPS" 'BEGIN{exit !(q >= t)}' ||
    { echo "FAIL: TGS throughput $tgs_qps/s < target $TGS_TARGET_QPS/s" >&2; exit 1; }
echo "OK: TGS throughput $tgs_qps/s >= $TGS_TARGET_QPS/s target"
kdestroy

say "qps: AS-REQs (64 serial password kinits, incl. client-side PBKDF2)"
t0=$(now)
for i in $(seq 0 63); do
    u="u$(printf '%04d' $((RANDOM % STRESS_N)))"
    echo "pw-$u" | kinit "$u"
done
rec as_kinit 64 "$t0"
kdestroy

say "stress: ktadd + keytab kinit still good under load"
kadmin -p admin/admin -w "$ADMIN_PW" \
    -q "ktadd -k $STATE/stress.keytab host/h0000.example.com" >/dev/null
kinit -kt "$STATE/stress.keytab" host/h0000.example.com
kdestroy
echo "OK"

say "safety: kprop-style full load is refused (temporary-db guard)"
# A misdeployed kprop/kpropd runs plain `kdb5_util load`, which would
# stream a dump over the LIVE GLOBAL tables. The plugin rejects the
# "temporary" open before any write; the iprop full-resync (-i) path
# dies the same way, so an iprop replica can never reach incremental
# replay either. Only `load -update` (documented restore) is allowed.
kdb5_util -r "$REALM" dump "$STATE/guard.dump"
if kdb5_util -r "$REALM" load "$STATE/guard.dump" 2>/dev/null; then
    echo "FAIL: plain kdb5_util load was ACCEPTED" >&2; exit 1
fi
n_before=$(wc -l < "$STATE/guard.dump")
kdb5_util -r "$REALM" dump "$STATE/guard2.dump"
n_after=$(wc -l < "$STATE/guard2.dump")
[ "$n_before" = "$n_after" ] || { echo "FAIL: refused load mutated data ($n_before -> $n_after)" >&2; exit 1; }
echo "OK (load refused, $n_after records intact)"

say "PASS: kadmin, ktadd, kinit, stress ($STRESS_N users + $STRESS_N hosts), backend validation all green on CRDB"
echo "QPS history: $QPS_LOG"
