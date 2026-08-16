# KDB Rust API — Implementation Log

<!-- START doctoc generated TOC please keep comment here to allow auto update -->
<!-- DON'T EDIT THIS SECTION, INSTEAD RE-RUN doctoc TO UPDATE -->
**Table of Contents**  *generated with [DocToc](https://github.com/thlorenz/doctoc)*

- [Completed iterations](#completed-iterations)

<!-- END doctoc generated TOC please keep comment here to allow auto update -->

All planned iterations are complete.  See [`kdb/README.md`](README.md) for the
current API reference and [`../README.md`](../README.md) for the workspace
overview, known limitations, and roadmap.

## Completed iterations

| Iteration | Scope |
|-----------|-------|
| 0 | Repository scaffolding — workspace, `kurbu5-sys`, `kurbu5-kdb-sys`, `kurbu5-kdb-rs`, `kurbu5-kdb-example` |
| 1 | Error and type primitives (`KdbError`, `Timestamp`, `OpenMode`, `LockMode`, `LookupFlags`, `IterFlags`, `PrincipalAttributes`, `TlDataType`) |
| 2 | Zero-copy read views (`PrincipalEntryRef`, `TlDataRef`, `TlDataIter`, `KeyDataSlice`) |
| 3 | Owned write types (`PrincipalEntry`, `OwnedPrincipal`, `TlDataBuilder`, `KeyDataBuilder`) |
| 4 | Policy types (`PolicyEntryRef`, `PolicyEntry`) |
| 5 | `KdbContext` utilities (`realm`, `unparse_principal`, `parse_principal`, `get/set_string_attr`, timestamp helpers) |
| 6 | `KdbModule` trait and complete `glue.rs` vtable dispatch |
| 7 | `kdb_plugin!` macro and `kdb_function_table` C symbol export |
| 8 | `kurbu5-kdb-example` — working example plugin |
| 9 | Build system integration (`Makefile.in`, configure fragment, `make check` hooks) |
| 10 | `kurbu5-kdb-derive` — `#[derive(KdbModule)]` with `#[kdb_impl]` selective-override support |
