# kdb-crdb — project instructions for agents

MIT Kerberos KDB backend on CockroachDB. See README.md for the design
rationale (GLOBAL tables, why lockout/last-auth must stay off, etc.) —
don't duplicate that here, read it.

## Goal

End state: a **functional** Kerberos KDB backend (real KDC + kadmind can
run against it, not just unit tests of isolated functions) with an
automated test suite proving it, and with attention paid to **read QPS**
(the AS-REQ/TGS-REQ `get_principal` path) once correctness is in place.
Don't optimize for QPS before the thing works end-to-end.

## Progress log — read this first, every session

`docs/progress.md` is the running log of what's been done, what's in
flight, and what's next. **Before starting work, read it.** **While
working and before ending a session, update it** — this is how the next
agent (possibly you, possibly not) picks up where you left off. Treat it
as a log, not a polished doc: append dated entries, don't rewrite history.
Record: what changed, why, what's still broken/stubbed, and the next
concrete step. If it doesn't exist yet, create it.

## Environment

- **Docker Compose** is available for running a multi-node CockroachDB
  cluster (with `--locality=region=...`) and eventually a real krb5kdc/
  kadmind, for integration testing. Prefer it over asking the user to spin
  up infra by hand.
- **Nix** is available for packages not otherwise on the box (e.g. krb5
  dev headers/binaries, cockroach CLI). Reach for it instead of raw
  system package managers.
- **Use Nix flakes**, not shell.nix/nix-shell: the dev environment is
  `flake.nix` (nixpkgs-unstable, pinned via `flake.lock`). Build and test
  through it: `nix develop --command cargo build`. One-off tools:
  `nix run nixpkgs#<pkg>` / `nix shell nixpkgs#<pkg>`.

## Known gaps (from README — check off / update as fixed)

- ~~TLS is stubbed~~ Done: verify-full TLS in store.rs (only explicit
  `sslmode=disable` skips it); compose cluster runs secure mode and the
  e2e asserts plaintext is rejected. Client-cert auth too (`sslcert`/
  `sslkey` in the URI) — the e2e kdc.conf carries no password.
- BEWARE: an unlicensed CRDB v25.2 cluster starts throttling concurrent
  transactions (SQLSTATE XXC02) once its grace period lapses — stress
  phases fail with bare "Input/output error" while serial ones pass.
  Recreate the cluster (`docker compose down -v` / `e2e/full-cycle.sh`)
  to reset the clock. See docs/progress.md 2026-08-16.
- Test suite: store+marshal covered against live CRDB (`cargo test` with
  the compose cluster up) AND full e2e with real krb5kdc/kadmind
  (`e2e/run.sh`), incl. a 4000 TGS QPS gate (last measured 8402/s via
  e2e/tgsbench.c; stock db2 baseline on this box ~13.8k/s). Read QPS
  comes from the KDC-only TTL entry cache (`entry_cache_ms`, lib.rs
  EntryCache) — see docs/progress.md 2026-08-16 evening entry before
  touching get_principal or the cache semantics.
- Chaos suites are part of the standard cycle: `e2e/chaos.sh` (compose,
  step 5 of full-cycle.sh) and `k8s/chaos-test.sh` (sea1 metal). They
  assert auth + QPS floors through 1-node loss, full quorum loss, and
  (k8s) split brain, using the plugin's `stale_reads_ms` bounded-
  staleness fallback and multi-host connection_uri failover. Writes must
  FAIL without quorum — that's asserted, not a bug.
- ~~Alias/referral `LookupFlags`~~ Done: aliases table + REFERRAL_OK
  gating; e2e covers TGS alias, AS alias (with and without -C), and
  out-of-realm rejection.
- ~~Policy `tl_data` dropped~~ / ~~`has_salt` inferred~~ Done via two
  accessor patches on a vendored kurbu5 (main branch; see `patches/`,
  `vendor/kurbu5/.vendored-commit`, and the `[patch]` in Cargo.toml).
  Patches still need to be sent upstream.
- Dump-vs-restore round-trip CI test: deliberately excluded (user call,
  2026-08-16).

## Working conventions

- This crate is `unsafe`-free by design (only kurbu5's glue is unsafe) —
  keep it that way.
- `panic = "abort"` in the release profile is deliberate: never unwind
  across the C vtable boundary. Don't introduce panics on error paths in
  `lib.rs`/`store.rs`; return `KdbError` instead.
- Schema changes belong in `schema.sql`, applied by an operator — not
  issued as DDL from inside the plugin.
