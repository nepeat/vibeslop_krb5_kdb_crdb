#!/usr/bin/env bash
# kprop/iprop replica e2e: a REAL MIT db2 primary on this box propagates
# into the CRDB cluster through the plugin's opt-in replica mode.
#
#   docker compose up -d        # once
#   e2e/kprop-replica.sh        # re-execs itself inside `nix develop`
#
# Exercises the whole receiver story against krb5 1.22.2:
#   GATES. knob-off load refused, marker-less load refused, foreign
#          lease refused — each before a single live row changes
#   A. bootstrap full push:   kdb5_util dump -i + kprop -> kpropd ->
#                             gated load into staging -> promote (timed:
#                             this is also the bulk-load fast path)
#   B. replica serves auth:   kinit/kvno against a krb5kdc reading CRDB,
#                             with the PRIMARY's master key and principals
#   C. write-freeze:          local kadmin writes refused while replica
#                             mode is on
#   D. iprop incrementals:    addprinc/cpw/delprinc on the primary appear
#                             on the replica within the poll interval
#   E. forced full resync:    kproplog -R on the primary -> kadmind pushes
#                             a fresh dump -> re-promote, auth stays live
#   F. promote-to-primary:    marker off -> pushes refused, freeze lifted
#
# DESTRUCTIVE to the dev DB: truncates principals/policies/aliases and
# replaces the realm with the primary's content (that is what a replica
# IS). Also resets prop_control/prop_lease.
set -euo pipefail
cd "$(dirname "$0")/.."

if ! command -v kdb5_util >/dev/null 2>&1; then
    exec nix develop --command "$0" "$@"
fi

STATE="$PWD/e2e/.state-kprop"
CERTS="$PWD/e2e/.certs"
CRDB_URI_ROOT="postgresql://root:root-dev-pw@localhost:26257/krb5?sslmode=verify-full&sslrootcert=$CERTS/ca.crt"
REALM=EXAMPLE.COM
# kprop/kpropd canonicalize the local hostname to the FQDN for their
# client principals even with dns_canonicalize_hostname=false; cover the
# plausible spellings so the rig is robust across boxes.
HOSTFQDN=$(hostname -f 2>/dev/null || hostname)
HOSTSHORT=$(hostname)
STRESS_N=${STRESS_N:-512}

PKDC_PORT=12088      # primary krb5kdc (kprop kinits its host key here)
KDC_PORT=13088       # replica krb5kdc
KADMIND_PORT=12749   # primary kadmind (iprop source)
KPASSWD_PORT=12464
KPROP_PORT=13754     # replica kpropd listener; primary kprop target
IPROP_PORT=12750     # primary kadmind's iprop RPC (required with iprop_enable)
POLL=2               # iprop_replica_poll seconds

MASTER_PW=kprop-master-pw
ALICE_PW=mig-alice-pw
ALICE_PW2=mig-alice-pw2

P="$STATE/primary"
R="$STATE/replica"

say()  { printf '\n\033[1m== %s\033[0m\n' "$*"; }
fail() { printf '\033[31mFAIL: %s\033[0m\n' "$*" >&2; exit 1; }
pass() { printf '\033[32mok: %s\033[0m\n' "$*"; }

sql()  { psql "$CRDB_URI_ROOT" -qtA -c "$1"; }

# Per-role environments. Every krb5 tool call goes through one of these:
# the primary side talks to the db2 KDC/kadmind, the replica side to the
# CRDB-backed KDC; "prop" is the RECEIVER role (kpropd + its loads).
pri()  { KRB5_CONFIG="$P/krb5.conf" KRB5_KDC_PROFILE="$P/kdc.conf" "$@"; }
rep()  { KRB5_CONFIG="$R/krb5.conf" KRB5_KDC_PROFILE="$R/kdc-kdc.conf" "$@"; }
prop() { KRB5_CONFIG="$R/krb5.conf" KRB5_KDC_PROFILE="$R/kdc-prop.conf" "$@"; }

# Poll until a command succeeds (enforcement/convergence is polled, never
# assumed from sleeps — the chaos suites' lesson).
wait_for() { # <seconds> <desc> <cmd...>
    local deadline=$((SECONDS + $1)); local desc=$2; shift 2
    until "$@" >/dev/null 2>&1; do
        (( SECONDS < deadline )) || fail "timeout waiting for: $desc"
        sleep 0.3
    done
}

say "building plugin"
cargo build

say "resetting state ($STATE + CRDB realm tables + prop_control/prop_lease)"
# Kill stale daemons from a previous run FIRST: a zombie kpropd keeps the
# port bound with old (since-rerandomized) keytab keys, and every auth
# fails with "Service key not available" while the port check passes.
pkill -f "$STATE" 2>/dev/null || true
for port in $PKDC_PORT $KDC_PORT $KADMIND_PORT $KPROP_PORT; do
    deadline=$((SECONDS + 10))
    while (exec 3<>"/dev/tcp/127.0.0.1/$port") 2>/dev/null; do
        (( SECONDS < deadline )) || fail "port $port still bound by a stale daemon"
        sleep 0.5
    done
done
rm -rf "$STATE"
mkdir -p "$P" "$R" "$STATE/plugins/kdb"
ln -s "$PWD/target/debug/libkdb_crdb.so" "$STATE/plugins/kdb/kdb_crdb.so"
sql 'TRUNCATE principals, policies; TRUNCATE aliases; DELETE FROM principals_staging WHERE true; DELETE FROM policies_staging WHERE true; DELETE FROM prop_control WHERE true; UPDATE prop_lease SET holder = NULL, expires = NULL, last_promote_at = NULL WHERE true' \
    || fail "cannot reach CRDB — docker compose up -d"
if [[ "${TRUE_LATENCY:-0}" != 1 ]]; then
    sql "SET CLUSTER SETTING kv.closed_timestamp.lead_for_global_reads_override = '25ms'" >/dev/null
fi

# ---------------------------------------------------------------------------
# Config files, one krb5.conf per SIDE (each side talks to its own KDC —
# kprop/kpropd kinit their host/kiprop keys, so both sides need one);
# admin_server is the PRIMARY's kadmind on both (kpropd polls it there).
# Roles are separated by KRB5_KDC_PROFILE:
#   $P/kdc.conf        db2 primary (krb5kdc, kadmind, kadmin.local, kprop)
#   $R/kdc-prop.conf   crdb RECEIVER (kpropd + its kdb5_util loads):
#                      krb5prop identity + prop_receiver=iprop
#   $R/kdc-kdc.conf    crdb KDC/admin (krb5kdc, kadmin.local): krb5kdc
#                      identity, NO prop_receiver -> subject to the freeze
# ---------------------------------------------------------------------------
krb5_conf() { # <kdc-port>
    cat <<EOF
[libdefaults]
    default_realm = $REALM
    plugin_base_dir = $STATE/plugins
    dns_lookup_kdc = false
    dns_lookup_realm = false
    rdns = false
    dns_canonicalize_hostname = false

[realms]
    $REALM = {
        kdc = 127.0.0.1:$1
        admin_server = 127.0.0.1:$KADMIND_PORT
        kpasswd_server = 127.0.0.1:$KPASSWD_PORT
    }
EOF
}
krb5_conf "$PKDC_PORT" >"$P/krb5.conf"
krb5_conf "$KDC_PORT" >"$R/krb5.conf"

cat >"$P/kdc.conf" <<EOF
[kdcdefaults]
    kdc_ports = $PKDC_PORT
    kdc_tcp_ports = $PKDC_PORT
    kprop_port = $KPROP_PORT

[realms]
    $REALM = {
        database_module = primarydb2
        acl_file = $P/kadm5.acl
        key_stash_file = $P/master.stash
        kadmind_port = $KADMIND_PORT
        kpasswd_port = $KPASSWD_PORT
        max_life = 10h 0m 0s
        iprop_enable = true
        iprop_logfile = $P/principal.ulog
        iprop_port = $IPROP_PORT
        iprop_master_ulogsize = 1024
    }

[dbmodules]
    primarydb2 = {
        db_library = db2
        database_name = $P/principal
    }

[logging]
    kdc = FILE:$P/kdc.log
    admin_server = FILE:$P/kadmind.log
    default = FILE:$P/krb5.log
EOF

crdb_stanza_common="
        acl_file = $R/kadm5.acl
        key_stash_file = $R/master.stash
        max_life = 10h 0m 0s"

cat >"$R/kdc-prop.conf" <<EOF
[kdcdefaults]
    kprop_port = $KPROP_PORT

[realms]
    $REALM = {
        database_module = crdbprop
$crdb_stanza_common
        iprop_enable = true
        iprop_logfile = $R/principal.ulog
        iprop_port = $IPROP_PORT
        iprop_replica_poll = ${POLL}s
    }

[dbmodules]
    db_module_dir = $STATE/plugins/kdb
    crdbprop = {
        db_library = kdb_crdb
        connection_uri = postgresql://krb5prop@localhost:26257/krb5?sslmode=verify-full&sslrootcert=$CERTS/ca.crt&sslcert=$CERTS/client.krb5prop.crt&sslkey=$CERTS/client.krb5prop.key
        disable_last_success = true
        disable_lockout = true
        prop_receiver = iprop
    }

[logging]
    default = FILE:$R/kpropd.log
EOF

cat >"$R/kdc-kdc.conf" <<EOF
[kdcdefaults]
    kdc_ports = $KDC_PORT
    kdc_tcp_ports = $KDC_PORT

[realms]
    $REALM = {
        database_module = crdb
$crdb_stanza_common
    }

[dbmodules]
    db_module_dir = $STATE/plugins/kdb
    crdb = {
        db_library = kdb_crdb
        connection_uri = postgresql://krb5kdc@localhost:26257/krb5?sslmode=verify-full&sslrootcert=$CERTS/ca.crt&sslcert=$CERTS/client.krb5kdc.crt&sslkey=$CERTS/client.krb5kdc.key
        disable_last_success = true
        disable_lockout = true
        entry_cache_ms = 1000
    }

[logging]
    kdc = FILE:$R/kdc.log
    default = FILE:$R/krb5.log
EOF

{
    echo "admin/admin@$REALM *"
    echo "kiprop/$HOSTFQDN@$REALM p"
    echo "kiprop/$HOSTSHORT@$REALM p"
} >"$P/kadm5.acl"
echo "admin/admin@$REALM *" >"$R/kadm5.acl"
{
    echo "host/$HOSTFQDN@$REALM"
    echo "host/$HOSTSHORT@$REALM"
} >"$R/kpropd.acl"

export KRB5CCNAME="FILE:$STATE/ccache"

cleanup() {
    [[ -n "${KADMIND_PID:-}" ]] && kill "$KADMIND_PID" 2>/dev/null || true
    [[ -n "${KPROPD_PID:-}" ]] && kill "$KPROPD_PID" 2>/dev/null || true
    [[ -n "${KDC_PID:-}" ]] && kill "$KDC_PID" 2>/dev/null || true
    [[ -n "${PKDC_PID:-}" ]] && kill "$PKDC_PID" 2>/dev/null || true
    [[ -n "${LIVENESS_PID:-}" ]] && kill "$LIVENESS_PID" 2>/dev/null || true
    pkill -f "kpropd.*$STATE" 2>/dev/null || true
}
on_err() {
    echo "FAILED — logs:" >&2
    tail -n 15 "$P"/kadmind.log "$R"/kpropd.log "$R"/kdc.log \
        "$STATE"/kpropd.out 2>/dev/null >&2 || true
}
trap cleanup EXIT
trap on_err ERR

# ---------------------------------------------------------------------------
say "PRIMARY: bootstrap db2 realm ($((STRESS_N + 12)) principals)"
pri kdb5_util create -s -P "$MASTER_PW" >/dev/null
pri kadmin.local -q "addprinc -pw admin-pw admin/admin" >/dev/null
pri kadmin.local -q "addpol -minlength 6 mig-policy" >/dev/null
pri kadmin.local -q "addprinc -pw $ALICE_PW -policy mig-policy mig-alice" >/dev/null
pri kadmin.local -q "addprinc -randkey host/mig.example.com" >/dev/null
# Propagation identities. kprop authenticates as host/<its fqdn> to
# kpropd (checked against kpropd.acl + the AP-REQ service key from the
# replica keytab, service = host/<kprop's target arg>); kpropd's iprop
# poll authenticates as kiprop/<its fqdn> to kadmind (kadm5.acl 'p').
# Both daemons live on this one box, so cover every name spelling.
for h in "$HOSTFQDN" "$HOSTSHORT" localhost 127.0.0.1; do
    pri kadmin.local -q "addprinc -randkey host/$h" >/dev/null
    pri kadmin.local -q "addprinc -randkey kiprop/$h" >/dev/null
done
# ONE shared keytab for the propagation identities: primary and replica
# live on the same box here, and ktadd re-randomizes on every call — two
# per-side ktadds of the same host/<fqdn> principal would leave the
# first keytab holding a dead key. (kpropd only accepts service tickets
# for host/<its own canonical name>, so the fqdn key is load-bearing.)
pri kadmin.local -q "ktadd -k $STATE/prop.keytab host/$HOSTFQDN host/$HOSTSHORT host/localhost host/127.0.0.1 kiprop/$HOSTFQDN kiprop/$HOSTSHORT" >/dev/null
pri kadmin.local -q "ktadd -k $R/host.keytab host/mig.example.com" >/dev/null
for ((i = 0; i < STRESS_N; i++)); do
    printf 'addprinc -randkey host/h%04d.mig.example.com\n' "$i"
done | pri kadmin.local >/dev/null 2>&1
PRIMARY_COUNT=$(pri kadmin.local -q listprincs 2>/dev/null | grep -c "@$REALM$")
echo "primary realm: $PRIMARY_COUNT principals"
# The replica KDC serves the primary's realm, so it needs the primary's
# master key stash.
cp "$P/master.stash" "$R/master.stash"

say "PRIMARY: starting krb5kdc + kadmind (iprop source)"
# Inline env (NOT the pri/prop wrappers): $! must be the daemon itself or
# cleanup kills only a wrapper subshell; output goes to files or the
# daemons hold this script's stdout pipe open forever.
# KRB5_KTNAME is inherited by the kprop kadmind spawns for a full resync.
KRB5_CONFIG="$P/krb5.conf" KRB5_KDC_PROFILE="$P/kdc.conf" \
    krb5kdc -n >"$P/kdc.out" 2>&1 &
PKDC_PID=$!
KRB5_CONFIG="$P/krb5.conf" KRB5_KDC_PROFILE="$P/kdc.conf" \
    KRB5_KTNAME="$STATE/prop.keytab" kadmind -nofork >"$P/kadmind.out" 2>&1 &
KADMIND_PID=$!
wait_for 15 "primary KDC port" bash -c "exec 3<>/dev/tcp/127.0.0.1/$PKDC_PORT"
wait_for 15 "kadmind port" bash -c "exec 3<>/dev/tcp/127.0.0.1/$KADMIND_PORT"

# ---------------------------------------------------------------------------
say "GATES: plain load without prop_receiver must stay refused (EINVAL)"
pri kdb5_util dump "$STATE/gate.dump" >/dev/null
if rep kdb5_util load "$STATE/gate.dump" >/dev/null 2>&1; then
    fail "ungated plain load was ACCEPTED"
fi
[[ $(sql 'SELECT count(*) FROM principals') == 0 ]] ||
    fail "ungated load wrote rows"
pass "knob-off load refused before any write"

say "GATES: -x prop_receiver must NOT turn replica mode on (host-bound knob)"
# The knob is read from the host's [dbmodules] profile only. Honouring it
# from -x would let anyone who can run kdb5_util/kadmin.local self-grant
# replica powers on a cluster whose KDC hosts never opted in.
if rep kdb5_util -x prop_receiver=iprop load "$STATE/gate.dump" >/dev/null 2>&1; then
    fail "-x prop_receiver=iprop enabled replica mode from a KDC profile"
fi
[[ $(sql 'SELECT count(*) FROM principals') == 0 ]] ||
    fail "-x-gated load wrote rows"
pass "-x prop_receiver ignored"

say "GATES: gated load without the marker row must be refused (EPERM)"
if prop kdb5_util load "$STATE/gate.dump" >/dev/null 2>&1; then
    fail "gated load accepted WITHOUT the prop_control marker"
fi
pass "marker-less load refused"

say "GATES: enabling replica mode (operator marker, mode=iprop)"
sql "UPSERT INTO prop_control (singleton, enabled, mode) VALUES (true, true, 'iprop')" >/dev/null

say "GATES: foreign unexpired lease must refuse a load (EBUSY)"
sql "UPDATE prop_lease SET holder = 'other-kpropd', expires = now() + interval '1 hour' WHERE true" >/dev/null
if prop kdb5_util load "$STATE/gate.dump" >/dev/null 2>&1; then
    fail "load accepted despite a foreign receiver lease"
fi
sql "UPDATE prop_lease SET holder = NULL, expires = NULL WHERE true" >/dev/null
pass "foreign lease refused the load"

say "GATES: an aborted load must hand the receiver lease straight back"
# kdb5_util destroys the temporary db when a load fails; that is where the
# plugin releases the lease. Without it every kpropd retry would sit on
# EBUSY for the whole lease TTL.
{ head -1 "$STATE/gate.dump"; sed -n '2p' "$STATE/gate.dump" | cut -c1-80; } \
    >"$STATE/bad.dump"
if prop kdb5_util load "$STATE/bad.dump" >/dev/null 2>&1; then
    fail "a truncated dump loaded successfully"
fi
[[ $(sql 'SELECT count(*) FROM prop_lease WHERE holder IS NOT NULL') == 0 ]] ||
    fail "aborted load left the receiver lease held"
[[ $(sql 'SELECT count(*) FROM principals') == 0 ]] ||
    fail "aborted load reached the live tables"
prop kdb5_util load "$STATE/gate.dump" >/dev/null 2>&1 ||
    fail "load refused right after an aborted one (stuck lease?)"
sql 'TRUNCATE principals, policies' >/dev/null
sql "UPDATE prop_lease SET holder = NULL, expires = NULL, last_promote_at = NULL WHERE true" >/dev/null
pass "aborted load released the lease; the next load ran immediately"

# ---------------------------------------------------------------------------
start_kpropd() {
    # -p: the nixpkgs krb5 split-output build bakes a nonexistent
    # lib/sbin path into kpropd's default kdb5_util location (it then
    # logs "completed" over the exec failure — silent no-op loads).
    KRB5_CONFIG="$R/krb5.conf" KRB5_KDC_PROFILE="$R/kdc-prop.conf" \
        KRB5_KTNAME="$STATE/prop.keytab" kpropd -D -d -P "$KPROP_PORT" \
        -p "$(command -v kdb5_util)" \
        -f "$R/from_master" -a "$R/kpropd.acl" >>"$STATE/kpropd.out" 2>&1 &
    KPROPD_PID=$!
    wait_for 15 "kpropd port" bash -c "exec 3<>/dev/tcp/127.0.0.1/$KPROP_PORT"
}

say "REPLICA: starting kpropd (iprop mode, port $KPROP_PORT, poll ${POLL}s)"
start_kpropd

say "PHASE A: bootstrap full push (dump -i + kprop) — timed"
pri kdb5_util dump -i "$STATE/full.dump" >/dev/null
T0=$SECONDS
# Target the fqdn: kpropd only accepts tickets for host/<its own name>.
KRB5_KTNAME="$STATE/prop.keytab" pri kprop -f "$STATE/full.dump" \
    -P "$KPROP_PORT" "$HOSTFQDN"
wait_for 90 "promote to complete" bash -c \
    "[[ \$(psql '$CRDB_URI_ROOT' -qtA -c 'SELECT count(*) FROM prop_lease WHERE last_promote_at IS NOT NULL') == 1 ]]"
T_FULL=$((SECONDS - T0))
REPLICA_COUNT=$(sql 'SELECT count(*) FROM principals')
[[ "$REPLICA_COUNT" == "$PRIMARY_COUNT" ]] ||
    fail "principal count mismatch: primary=$PRIMARY_COUNT replica=$REPLICA_COUNT"
[[ $(sql 'SELECT count(*) FROM principals_staging') == 0 ]] ||
    fail "staging not cleared after promote"
[[ $(sql "SELECT count(*) FROM policies WHERE name = 'mig-policy'") == 1 ]] ||
    fail "policy did not propagate"
pass "full push: $REPLICA_COUNT principals + policy live in ${T_FULL}s (transfer+staging+promote)"

say "PHASE B: replica serves the primary's realm (krb5kdc on CRDB)"
KRB5_CONFIG="$R/krb5.conf" KRB5_KDC_PROFILE="$R/kdc-kdc.conf" \
    krb5kdc -n >"$R/kdc.out" 2>&1 &
KDC_PID=$!
wait_for 15 "replica KDC serves AS-REQ" \
    rep bash -c "echo '$ALICE_PW' | kinit mig-alice"
echo "$ALICE_PW" | rep kinit mig-alice >/dev/null
rep kvno host/mig.example.com >/dev/null
rep kinit -kt "$R/host.keytab" host/mig.example.com >/dev/null
rep kdestroy 2>/dev/null || true
pass "password AND keytab auth against the replica (primary's key material, bit-for-bit)"

# kpropd's iprop poll needs the replica KDC (it kinits kiprop/<host>
# from its keytab), which only just came up — its kadm5-init retry
# backoff may have grown to minutes by now. Restart it: init succeeds
# immediately and the poll interval applies from here on.
say "REPLICA: restarting kpropd now that the replica KDC is up"
kill "$KPROPD_PID" 2>/dev/null || true
wait "$KPROPD_PID" 2>/dev/null || true
start_kpropd
wait_for 30 "kpropd iprop poll online" \
    grep -q "KDC is synchronized" "$STATE/kpropd.out"

say "PHASE C: replica write-freeze (local kadmin writes refused)"
if rep kadmin.local -q "addprinc -pw x local-write-must-fail" 2>&1 | grep -qi "created"; then
    fail "local kadmin write succeeded on a frozen replica"
fi
[[ $(sql "SELECT count(*) FROM principals WHERE name LIKE 'local-write-must-fail%'") == 0 ]] ||
    fail "frozen write reached the database"
# …and a kadmin that claims to be the receiver on its command line is
# still frozen: the exemption comes from the host's profile, not from -x.
if rep kadmin.local -x prop_receiver=iprop \
        -q "addprinc -pw x xarg-must-fail" 2>&1 | grep -qi "created"; then
    fail "-x prop_receiver self-exempted a kadmin from the write-freeze"
fi
[[ $(sql "SELECT count(*) FROM principals WHERE name LIKE 'xarg-must-fail%'") == 0 ]] ||
    fail "-x prop_receiver write reached the database"
pass "local writes frozen while replica mode is on (-x cannot exempt)"

say "PHASE D: iprop incrementals (poll ${POLL}s)"
pri kadmin.local -q "addprinc -pw inc-bob-pw inc-bob" >/dev/null
wait_for $((POLL * 5 + 10)) "incremental addprinc" bash -c \
    "[[ \$(psql '$CRDB_URI_ROOT' -qtA -c \"SELECT count(*) FROM principals WHERE name = 'inc-bob@$REALM'\") == 1 ]]"
echo "inc-bob-pw" | rep kinit inc-bob >/dev/null
rep kdestroy 2>/dev/null || true
pass "addprinc propagated + authable"

pri kadmin.local -q "cpw -pw $ALICE_PW2 mig-alice" >/dev/null
wait_for $((POLL * 5 + 10)) "incremental cpw (new pw kinits)" \
    rep bash -c "echo '$ALICE_PW2' | kinit mig-alice"
if echo "$ALICE_PW" | rep kinit mig-alice >/dev/null 2>&1; then
    fail "OLD password still kinits after propagated cpw"
fi
rep kdestroy 2>/dev/null || true
pass "cpw propagated (old password dead, new one live)"

pri kadmin.local -q "delprinc -force inc-bob" >/dev/null
wait_for $((POLL * 5 + 10)) "incremental delprinc" bash -c \
    "[[ \$(psql '$CRDB_URI_ROOT' -qtA -c \"SELECT count(*) FROM principals WHERE name = 'inc-bob@$REALM'\") == 0 ]]"
pass "delprinc propagated"

say "PHASE E: full RE-push over the live realm, with auth liveness"
# The periodic re-prop case: a second full push over an already-loaded
# realm. Exercises the diff-promote fast path (almost every row is
# unchanged) and staging isolation — auth against the replica KDC must
# never fail while the dump streams and promotes.
#
# NOTE deliberately NOT tested: the kadmind-INITIATED full resync
# (replica ulog too far behind -> kadmind spawns kprop itself). The
# nixpkgs krb5 build bakes a nonexistent lib/sbin kprop path into
# kadmind and offers no override, so that leg cannot run under nix; the
# receiver side of it (kpropd + load) is identical to this manual push.
(
    export KRB5CCNAME="FILE:$STATE/liveness.cc"
    while :; do
        rep kinit -kt "$R/host.keytab" host/mig.example.com 2>/dev/null ||
            { touch "$STATE/liveness.failed"; exit 1; }
        sleep 0.5
    done
) &
LIVENESS_PID=$!
pri kadmin.local -q "addprinc -pw resync-pw resync-carol" >/dev/null
PROMOTE_T_BEFORE=$(sql 'SELECT COALESCE(last_promote_at::string, '"''"') FROM prop_lease')
pri kdb5_util dump -i "$STATE/repush.dump" >/dev/null
T0=$SECONDS
KRB5_KTNAME="$STATE/prop.keytab" pri kprop -f "$STATE/repush.dump" \
    -P "$KPROP_PORT" "$HOSTFQDN"
wait_for 90 "re-push promote" bash -c \
    "[[ \$(psql '$CRDB_URI_ROOT' -qtA -c \"SELECT count(*) FROM prop_lease WHERE last_promote_at IS NOT NULL AND last_promote_at::string != '$PROMOTE_T_BEFORE'\") == 1 ]]"
T_REPUSH=$((SECONDS - T0))
kill "$LIVENESS_PID" 2>/dev/null || true; wait "$LIVENESS_PID" 2>/dev/null || true
[[ ! -f "$STATE/liveness.failed" ]] ||
    fail "auth failed during the full re-push"
echo "resync-pw" | rep kinit resync-carol >/dev/null
rep kdestroy 2>/dev/null || true
FINAL_PRIMARY=$(pri kadmin.local -q listprincs 2>/dev/null | grep -c "@$REALM$")
FINAL_REPLICA=$(sql 'SELECT count(*) FROM principals')
[[ "$FINAL_PRIMARY" == "$FINAL_REPLICA" ]] ||
    fail "post-repush count mismatch: primary=$FINAL_PRIMARY replica=$FINAL_REPLICA"
pass "re-push converged ($FINAL_REPLICA principals) in ${T_REPUSH}s, auth never failed"

say "PHASE F: marker off -> pushes refused again, freeze lifted"
sql "UPDATE prop_control SET enabled = false WHERE true" >/dev/null
pri kdb5_util dump -i "$STATE/off.dump" >/dev/null
if KRB5_KTNAME="$STATE/prop.keytab" pri kprop -f "$STATE/off.dump" \
    -P "$KPROP_PORT" "$HOSTFQDN" >/dev/null 2>&1; then
    fail "kprop push succeeded with replica mode disabled"
fi
rep kadmin.local -q "addprinc -pw thaw-pw thaw-test" >/dev/null
[[ $(sql "SELECT count(*) FROM principals WHERE name = 'thaw-test@$REALM'") == 1 ]] ||
    fail "write still frozen after disabling replica mode"
rep kadmin.local -q "delprinc -force thaw-test" >/dev/null
pass "promote-to-primary: marker off refuses pushes and lifts the freeze"

say "ALL PHASES PASSED"
echo "full push (${PRIMARY_COUNT} principals): ${T_FULL}s end-to-end"
echo "note: the dev krb5 DB now holds the primary's realm content"
