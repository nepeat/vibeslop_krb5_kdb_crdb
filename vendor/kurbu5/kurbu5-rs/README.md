# kurbu5-rs — Safe Rust API for MIT Kerberos Non-KDB Plugin Modules

<!-- START doctoc generated TOC please keep comment here to allow auto update -->
<!-- DON'T EDIT THIS SECTION, INSTEAD RE-RUN doctoc TO UPDATE -->
**Table of Contents**  *generated with [DocToc](https://github.com/thlorenz/doctoc)*

- [Overview](#overview)
- [Crate layout](#crate-layout)
- [Shared infrastructure](#shared-infrastructure)
  - [TL-data types](#tl-data-types)
  - [PluginContext](#plugincontext)
  - [Profile](#profile)
  - [Krb5Error](#krb5error)
  - [initvt_plugin! macro](#initvt_plugin-macro)
- [Interface reference](#interface-reference)
  - [PWQUAL — password quality](#pwqual-password-quality)
  - [HOSTREALM — host-to-realm mapping](#hostrealm-host-to-realm-mapping)
  - [LOCALAUTH — principal-to-local-account mapping](#localauth-principal-to-local-account-mapping)
  - [CCSELECT — credential cache selection](#ccselect-credential-cache-selection)
  - [KDCPOLICY — KDC policy hooks](#kdcpolicy-kdc-policy-hooks)
  - [CERTAUTH — PKINIT certificate authorisation](#certauth-pkinit-certificate-authorisation)
  - [KDCPREAUTH — KDC preauthentication](#kdcpreauth-kdc-preauthentication)
  - [CLPREAUTH — client preauthentication](#clpreauth-client-preauthentication)
  - [AUDIT — KDC audit records](#audit-kdc-audit-records)
- [Derive macros](#derive-macros)
- [Safety model](#safety-model)
- [Integration tests](#integration-tests)
- [Feature flags](#feature-flags)

<!-- END doctoc generated TOC please keep comment here to allow auto update -->

## Overview

MIT Kerberos supports a rich set of plugin interfaces beyond the KDB database
driver.  Each interface is loaded by libkrb5 at runtime: the loader calls a C
function `<name>_initvt(ctx, maj_ver, min_ver, vtable)` exported from the
shared library, which fills in a caller-allocated vtable struct.

`kurbu5-rs` provides:

* A safe Rust trait for each of the nine supported interfaces.
* A glue layer (`glue.rs` per interface) that bridges between the C vtable
  and the trait — all `unsafe` code is confined there.
* The `initvt_plugin!` macro that generates and exports the `<name>_initvt`
  C function.
* Optional `#[derive(...)]` macros (via `kurbu5-derive`) for delegation
  overlay patterns.

---

## Crate layout

```
kurbu5-rs/
  Cargo.toml
  src/
    lib.rs           # public API surface + initvt_plugin! macro
    error.rs         # Krb5Error enum
    context.rs       # PluginContext<'ctx> wrapper
    profile.rs       # Profile — RAII handle to krb5.conf / kdc.conf
    crypto.rs        # krb5 symmetric-key crypto wrappers (encrypt, decrypt, random)
    tl_data.rs       # TlDataRef, TlDataIter, TlDataBuilder, OwnedTlDataList<P>,
                     # TlDataFreePolicy, GenericFree, TlDataList — shared across
                     # all plugin families (KDB, KADM5, and non-KDB interfaces)
    pwqual.rs        # PwqualModule trait + PwqualError + CheckRequest
    pwqual/
      glue.rs        # make_pwqual_vtable::<M>() — all unsafe
    hostrealm.rs     # HostrealmModule trait
    hostrealm/
      glue.rs        # make_hostrealm_vtable::<M>()
    localauth.rs     # LocalauthModule trait
    localauth/
      glue.rs        # make_localauth_vtable::<M>()
    ccselect.rs      # CcselectModule trait + CcacheHandle
    ccselect/
      glue.rs        # make_ccselect_vtable::<M>()
    kdcpolicy.rs     # KdcpolicyModule trait + PolicyError + AsRequest + TgsRequest
    kdcpolicy/
      glue.rs        # make_kdcpolicy_vtable::<M>()
    certauth.rs      # CertauthModule trait + CertauthDecision + CertRef
    certauth/
      glue.rs        # make_certauth_vtable::<M>()
    kdcpreauth.rs    # KdcpreauthModule trait + KdcpreauthCallbacks + PaData + VerifyResponse
    kdcpreauth/
      glue.rs        # make_kdcpreauth_vtable::<M>()
    clpreauth.rs     # ClpreauthModule trait + ClpreauthCallbacks + PaData
    clpreauth/
      glue.rs        # make_clpreauth_vtable::<M>()
    audit.rs         # AuditModule trait + AuditStateRef
    audit/
      glue.rs        # make_audit_vtable::<M>()
  examples/
    pwqual_example.rs  # runnable binary; cdylib template in doc comment
```

---

## Shared infrastructure

### TL-data types

`krb5_tl_data` tagged-list records appear across all Kerberos plugin families
(KDB, KADM5, string attributes, mod-princ records, etc.).  The primary
definitions live in `kurbu5-rs` and are re-exported by the downstream crates.

```rust
/// Zero-copy reference to one node in a krb5_tl_data linked list.
pub struct TlDataRef<'a> {
    pub ty: u16,       // tl_data_type
    pub data: &'a [u8], // tl_data_contents
}

/// Zero-allocation iterator over a krb5_tl_data linked list.
pub struct TlDataIter<'a> { /* … */ }

/// Builder for constructing a krb5_tl_data linked list.
///
/// Call push() for each record, then build() to obtain an OwnedTlDataList.
pub struct TlDataBuilder { /* … */ }
impl TlDataBuilder {
    pub fn push(&mut self, ty: impl Into<u16>, data: impl Into<Vec<u8>>) -> &mut Self;
    pub fn build(self) -> TlDataList;  // allocates; aborts on OOM (handle_alloc_error)
}
```

**Owned list types** are parameterised by a free policy `P: TlDataFreePolicy`
that controls how the list is freed on `Drop`.  The policy is a zero-sized
type resolved at compile time — no dynamic dispatch overhead.

```rust
pub unsafe trait TlDataFreePolicy: Send + 'static {
    unsafe fn free(head: *mut krb5_tl_data);
}

pub struct OwnedTlDataList<P: TlDataFreePolicy> { /* … */ }
impl<P: TlDataFreePolicy> OwnedTlDataList<P> {
    pub fn len(&self) -> i16;
    pub fn is_empty(&self) -> bool;
    pub fn iter(&self) -> TlDataIter<'_>;
    pub fn into_raw(self) -> (*mut krb5_tl_data, i16);   // transfers to C
    pub fn with_policy<Q: TlDataFreePolicy>(self) -> OwnedTlDataList<Q>;  // zero-copy convert
}
```

The **default policy** `GenericFree` walks the linked list freeing each
`tl_data_contents` buffer and node with `libc::free`.  This is correct on
POSIX/glibc systems because both Rust and MIT Kerberos use the same underlying
allocator.  `TlDataList = OwnedTlDataList<GenericFree>` is the type produced
by `TlDataBuilder::build()`.

KDB-specific code (`kurbu5-kdb-rs`) defines a `KdbFree` policy type and the
`KdbTlDataList` alias.  `PrincipalEntry::set_tl_data` accepts any
`OwnedTlDataList<P>`, so a `TlDataList` from `TlDataBuilder::build()` can be
passed directly without an explicit policy conversion.

### PluginContext

`PluginContext<'ctx>` is a safe wrapper over a borrowed `*mut krb5_context`.
It is passed to every trait method that needs to call back into libkrb5.

```rust
impl<'ctx> PluginContext<'ctx> {
    /// Unparse a principal into a display string ("user@REALM").
    pub fn unparse_principal(&self, princ: &krb5_principal_data) -> Result<String, Krb5Error>;

    /// Return the default realm from the context.
    pub fn realm(&self) -> Result<String, Krb5Error>;

    /// The raw krb5_context pointer (for calling libkrb5 C functions directly).
    pub fn as_raw(&self) -> krb5_context;

    /// Open an RAII handle to the Kerberos profile (krb5.conf / kdc.conf).
    pub fn profile(&self) -> Result<profile::Profile, Krb5Error>;
}
```

### Profile

`Profile` is an RAII handle to the Kerberos configuration file (`krb5.conf` /
`kdc.conf`).  Obtain one from `PluginContext::profile()` or, in crates that
hold a raw `krb5_context`, from `Profile::from_raw_context(ctx)`.

Methods: `get_string`, `get_integer`, `get_boolean`, `get_subsection_names`,
`get_values`.  The handle is released via `profile_abandon` on `Drop`.

### Krb5Error

`Krb5Error` is the common error type for all non-KDB interfaces:

| Variant | Meaning | `krb5_error_code` |
|---------|---------|-------------------|
| `NoHandle` | "try next plugin" | `KRB5_PLUGIN_NO_HANDLE` |
| `VersionNotSupported` | Vtable version mismatch | `KRB5_PLUGIN_VER_NOTSUPP` |
| `OperationNotSupported` | Operation not implemented | `KRB5_PLUGIN_OP_NOTSUPP` |
| `OutOfMemory` | Allocation failed | `ENOMEM` |
| `LnameNotrans` | No local-name translation | `KRB5_LNAME_NOTRANS` |
| `Custom(i32)` | Arbitrary error code | as-is |

Return `Krb5Error::NoHandle` from optional methods to pass control to the
next registered plugin.

### initvt_plugin! macro

```rust
initvt_plugin!(prefix, major_version, ModuleType, make_vtable_fn);
```

Generates and exports the C function `<prefix>_initvt`.  The function:

1. Checks `maj_ver` against `major_version`; returns
   `KRB5_PLUGIN_VER_NOTSUPP` on mismatch.
2. Calls `make_vtable_fn::<ModuleType>()` to build the vtable at compile time.
3. Copies the vtable into the caller-supplied pointer.

Every interface has its own `make_<interface>_vtable` in the corresponding
`glue` sub-module.

---

## Interface reference

### PWQUAL — password quality

**Header:** `krb5/pwqual_plugin.h`
**Major version:** 1
**Crate feature:** `pwqual`

A PWQUAL plugin is called by kadmind before accepting a password change.
Multiple plugins may be registered; any rejection fails the operation.

```rust
pub trait PwqualModule: Sized + Send + 'static {
    /// Module name reported to libkrb5 (null-terminated `CStr` literal; use `c"..."` syntax).
    const NAME: &'static CStr;

    /// Initialise the module.  The `dict_file` is the path to the
    /// password dictionary configured in krb5.conf, if any.
    fn open(ctx: &PluginContext<'_>, dict_file: Option<&str>) -> Result<Self, PwqualError>;

    /// Check a password candidate.  Return `Ok(())` to accept or an
    /// appropriate `PwqualError` variant to reject.
    fn check(&self, ctx: &PluginContext<'_>, req: &CheckRequest<'_>) -> Result<(), PwqualError>;

    /// Release the module.  Default: drops `self`.
    fn close(self, _ctx: &PluginContext<'_>) {}
}
```

`CheckRequest<'a>` fields: `password: &'a str`, `principal: krb5_principal`,
`policy_name: Option<&'a str>`.

`PwqualError` variants: `TooShort`, `InsufficientClass`, `DictionaryHit`,
`Palindrome`, `Generic`, `Custom(i32)`.

**Export:**

```rust
initvt_plugin!(pwqual_myplugin, 1, MyPlugin, kurbu5_rs::pwqual::glue::make_pwqual_vtable);
// Exports: pwqual_myplugin_initvt
```

---

### HOSTREALM — host-to-realm mapping

**Header:** `krb5/hostrealm_plugin.h`
**Major version:** 1
**Crate feature:** `hostrealm`

Maps hostnames to Kerberos realm names.  Three query types; all default to
`Err(Krb5Error::NoHandle)`.

```rust
pub trait HostrealmModule: Sized + Send + 'static {
    const NAME: &'static CStr;

    fn init_module(ctx: &PluginContext<'_>) -> Result<Self, Krb5Error>;
    fn fini_module(self, _ctx: &PluginContext<'_>) {}

    /// Authoritative realm(s) for a hostname (secure mechanisms, e.g. DNS SRV).
    fn host_realm(&self, ctx: &PluginContext<'_>, host: &str)
        -> Result<Vec<String>, Krb5Error> { Err(Krb5Error::NoHandle) }

    /// Fallback realm(s) for a hostname (heuristic mechanisms).
    fn fallback_realm(&self, ctx: &PluginContext<'_>, host: &str)
        -> Result<Vec<String>, Krb5Error> { Err(Krb5Error::NoHandle) }

    /// The default realm of the local host.
    fn default_realm(&self, ctx: &PluginContext<'_>)
        -> Result<Vec<String>, Krb5Error> { Err(Krb5Error::NoHandle) }
}
```

The glue layer allocates a null-terminated `**char` realm list from the
`Vec<String>` and exposes `free_realmlist` so libkrb5 can release it.

**Export:**

```rust
initvt_plugin!(hostrealm_myplugin, 1, MyPlugin, kurbu5_rs::hostrealm::glue::make_hostrealm_vtable);
```

---

### LOCALAUTH — principal-to-local-account mapping

**Header:** `krb5/localauth_plugin.h`
**Major version:** 1
**Crate feature:** `localauth`

Determines whether a Kerberos principal may log in as a local account.

```rust
pub trait LocalauthModule: Sized + Send + 'static {
    const NAME: &'static CStr;

    fn init_module(ctx: &PluginContext<'_>) -> Result<Self, Krb5Error>;
    fn fini_module(self, _ctx: &PluginContext<'_>) {}

    /// Return the set of `krb5_atype_*` constants this module handles.
    /// `None` means "all types".
    fn an2ln_types() -> Option<&'static [i32]> { None }

    /// Check whether `principal` may log in as `local_user`.
    /// Return `Ok(())` for yes, `Err(Krb5Error::NoHandle)` for "don't know".
    fn userok(
        &self, ctx: &PluginContext<'_>,
        principal: krb5_principal, local_user: &str,
    ) -> Result<(), Krb5Error> { Err(Krb5Error::NoHandle) }

    /// Translate `principal` to the corresponding local account name.
    /// Return `Ok(Some(name))`, `Ok(None)` for no mapping, or
    /// `Err(Krb5Error::NoHandle)` to pass to the next plugin.
    fn an2ln(
        &self, ctx: &PluginContext<'_>,
        atype: i32, principal: krb5_principal,
    ) -> Result<Option<String>, Krb5Error> { Err(Krb5Error::NoHandle) }
}
```

The `String` returned from `an2ln` is heap-allocated via `CString::into_raw`
and freed through the `free_string` vtable slot.

**Export:**

```rust
initvt_plugin!(localauth_myplugin, 1, MyPlugin, kurbu5_rs::localauth::glue::make_localauth_vtable);
```

---

### CCSELECT — credential cache selection

**Header:** `krb5/ccselect_plugin.h`
**Major version:** 1
**Crate feature:** `ccselect`

Selects a credential cache for a given server principal.

```rust
pub trait CcselectModule: Sized + Send + 'static {
    const NAME: &'static CStr;

    fn init_module() -> Result<Self, Krb5Error>;
    fn fini_module(&mut self) {}

    /// Selection priority.  Higher values are consulted first.
    /// Use `CCSELECT_PRIORITY_AUTHORITATIVE` (10) or
    /// `CCSELECT_PRIORITY_HEURISTIC` (5).
    fn priority(&self) -> i32;

    /// Return a `CcacheHandle` for `server`, or `Err(Krb5Error::NoHandle)`
    /// to defer to the next plugin.
    fn ccache(
        &self, ctx: &PluginContext<'_>,
        server: krb5_principal,
    ) -> Result<CcacheHandle, Krb5Error>;
}
```

`CcacheHandle` is a newtype over `(krb5_ccache, krb5_principal)`.  The glue
layer passes it back to libkrb5 as an opaque `*mut c_void`; libkrb5 calls the
`ccache` vtable slot again with the same pointer to retrieve the values.

**Export:**

```rust
initvt_plugin!(ccselect_myplugin, 1, MyPlugin, kurbu5_rs::ccselect::glue::make_ccselect_vtable);
```

---

### KDCPOLICY — KDC policy hooks

**Header:** `krb5/kdcpolicy_plugin.h`
**Major version:** 1
**Crate feature:** `kdcpolicy`

Applies additional authorisation policy to AS and TGS requests.  The default
implementations allow everything (`Ok(())`).

```rust
pub trait KdcpolicyModule: Sized + Send + 'static {
    const NAME: &'static CStr;

    fn init_module(ctx: &PluginContext<'_>) -> Result<Self, Krb5Error>;
    fn fini_module(self, _ctx: &PluginContext<'_>) -> Result<(), Krb5Error> { Ok(()) }

    /// Called for every AS-REQ.  Return `Ok(())` to allow or a
    /// `PolicyError` to reject.
    fn check_as(&self, ctx: &PluginContext<'_>, req: AsRequest<'_>)
        -> Result<(), PolicyError> { Ok(()) }

    /// Called for every TGS-REQ.
    fn check_tgs(&self, ctx: &PluginContext<'_>, req: TgsRequest<'_>)
        -> Result<(), PolicyError> { Ok(()) }
}
```

`PolicyError` carries a `&'static CStr` status string logged by the KDC,
an optional `Vec<u8>` error data (`e_data`) reserved for future use (the
KDCPOLICY vtable has no `free_data` slot, so the glue layer drops this value
after each call), and optional `lifetime`/`renew_lifetime` fields that
restrict ticket lifetimes on denial.

`AsRequest<'a>` exposes: `msg_type()`, `kdc_options()`, `client_is_null()`,
`server_is_null()`, `client_is_anonymous()`, `auth_indicators()`.

`TgsRequest<'a>` exposes: `msg_type()`, `kdc_options()`, `server_is_null()`,
`ticket_is_null()`, `auth_indicators()`, and the following principal accessors:

| Method | Returns | Source field |
|--------|---------|--------------|
| `ticket_client()` | `Option<&'a krb5_principal_data>` | `ticket->enc_part2->client` |
| `ticket_server()` | `Option<&'a krb5_principal_data>` | `ticket->server` |
| `request_server()` | `Option<&'a krb5_principal_data>` | `request->server` |

`ticket_client()` is the correct field for TGS log records: in a TGS-REQ the
outer `krb5_kdc_req.client` is NULL; the authenticating client is in the
decrypted TGT body.  Pass the returned reference to
`PluginContext::unparse_principal` to obtain a display string.

**Export:**

```rust
initvt_plugin!(kdcpolicy_myplugin, 1, MyPlugin, kurbu5_rs::kdcpolicy::glue::make_kdcpolicy_vtable);
```

---

### CERTAUTH — PKINIT certificate authorisation

**Header:** `krb5/certauth_plugin.h`
**Major version:** 1
**Crate feature:** `certauth`

Authorises a client certificate presented during PKINIT.

```rust
pub trait CertauthModule: Sized + Send + 'static {
    const NAME: &'static CStr;

    fn init_module(ctx: &PluginContext<'_>) -> Result<Self, Krb5Error>;

    /// Called once with a list of realm names the module will serve
    /// (minor version >= 2).  Default: calls `init_module`.
    fn init_module_ex(ctx: &PluginContext<'_>, realms: &[&str]) -> Result<Self, Krb5Error> {
        Self::init_module(ctx)
    }

    fn fini_module(self) {}
    fn free_modreq(&self) {}

    /// Authorise `cert` for `principal`.  Return a `CertauthDecision`.
    fn authorize(
        &self, ctx: &PluginContext<'_>,
        cert: CertRef<'_>, princ: krb5_principal,
        opts: *const krb5_responder_pkinit_opts,
    ) -> CertauthDecision;

    /// Called when PKINIT fails (for auditing/logging).
    fn notify_pkinit_failure(&self, _ctx: &PluginContext<'_>, ...) {}
}
```

`CertRef<'a>` is a zero-copy view of the DER-encoded certificate bytes.

`CertauthDecision` variants:

| Variant | Meaning |
|---------|---------|
| `Authorized` | Accept; no extra indicators |
| `AuthorizedWithIndicators(Vec<String>)` | Accept; add auth indicators |
| `AuthorizedHwauth` | Accept; mark as hardware-based |
| `NoOpinion` | Defer to next plugin |
| `Rejected(i32)` | Reject with error code |

**Export:**

```rust
initvt_plugin!(certauth_myplugin, 1, MyPlugin, kurbu5_rs::certauth::glue::make_certauth_vtable);
```

---

### KDCPREAUTH — KDC preauthentication

**Header:** `krb5/kdcpreauth_plugin.h`
**Major version:** 1
**Crate feature:** `kdcpreauth`

The most complex interface; implements server-side preauthentication
mechanisms (e.g. FAST, OTP, PKINIT).

```rust
pub trait KdcpreauthModule: Sized + Send + 'static {
    const NAME: &'static CStr;

    /// PA-DATA types this module handles.
    fn pa_type_list() -> &'static [i32];

    fn init_module(ctx: &PluginContext<'_>, realmnames: &[&str]) -> Result<Self, Krb5Error>;
    fn fini_module(self) {}

    /// Return flags for a given PA type (PA_REQUIRED, PA_SUFFICIENT, etc.).
    fn flags_for_type(_ctx: &PluginContext<'_>, _pa_type: i32) -> i32 { 0 }

    /// Produce PA-DATA to include in a PREAUTH_REQUIRED error reply.
    /// Call `cb.send_pa(pa_data)` to enqueue output PA-DATA; the
    /// callback is asynchronous by design (bridged synchronously here).
    fn get_edata(
        &self, ctx: &PluginContext<'_>,
        pa_type: i32, cb: &KdcpreauthCallbacks<'_>,
        modreq: Option<&(dyn Any + Send + 'static)>,
    ) -> Result<(), Krb5Error> { Ok(()) }

    /// Verify a PA-DATA element from the client's AS-REQ.
    /// Return a `VerifyResponse` — which may carry a new `ModReq`
    /// (per-request state) and/or output PA-DATA.
    fn verify(
        &self, ctx: &PluginContext<'_>,
        pa_data: &PaData, cb: &KdcpreauthCallbacks<'_>,
    ) -> VerifyResponse { VerifyResponse::err(KRB5KDC_ERR_PREAUTH_FAILED) }

    /// Produce PA-DATA to include in the AS-REP.
    fn return_padata(
        &self, ctx: &PluginContext<'_>,
        cb: &KdcpreauthCallbacks<'_>,
        req: ReturnPadataRequest<'_>,
    ) -> Result<Option<PaData>, Krb5Error> { Ok(None) }
}
```

`KdcpreauthCallbacks<'a>` provides: `max_time_skew()`, `have_client_keys()`,
`get_string(key)`, `send_freshness_token()`, `add_auth_indicator(indicator)`,
`replace_reply_key(keyblock)`.

`VerifyResponse` constructors: `ok()`, `ok_with_modreq(Box<dyn Any + Send>)`,
`err(code)`, `err_with_edata(code, Vec<PaData>)`.

PA type flag constants: `PA_REQUIRED`, `PA_SUFFICIENT`, `PA_REPLACES_KEY`,
`PA_PSEUDO`, `PA_HARDWARE`, `PA_TYPED_E_DATA`.

**Export:**

```rust
initvt_plugin!(kdcpreauth_myplugin, 1, MyPlugin, kurbu5_rs::kdcpreauth::glue::make_kdcpreauth_vtable);
```

---

### CLPREAUTH — client preauthentication

**Header:** `krb5/clpreauth_plugin.h`
**Major version:** 1
**Crate feature:** `clpreauth`

Client-side mirror of KDCPREAUTH; handles PA-DATA elements in AS-REPs.

```rust
pub trait ClpreauthModule: Sized + Send + 'static {
    const NAME: &'static CStr;

    fn pa_type_list() -> &'static [i32];

    fn init_module(_ctx: &PluginContext<'_>) -> Result<Self, Krb5Error> { Ok(Self) }
    fn fini_module(self) {}

    /// Return flags for a given PA type (PA_REAL, PA_INFO).
    fn flags(_ctx: &PluginContext<'_>, _pa_type: i32) -> i32 { PA_REAL }

    /// Called before the first AS-REQ to collect etype info.
    fn init_etype_info(
        &self, ctx: &PluginContext<'_>,
        cb: &mut ClpreauthCallbacks<'_>,
        req: EtypeInfoRequest<'_>,
    ) -> Result<(), Krb5Error> { Ok(()) }

    /// Process a PA-DATA element from the KDC and produce output PA-DATA
    /// for the next AS-REQ.  Output is returned via `padata_out`.
    fn process(
        &self, ctx: &PluginContext<'_>,
        cb: &mut ClpreauthCallbacks<'_>,
        req: ProcessRequest<'_>,
        padata_out: &mut Vec<PaData>,
    ) -> Result<(), Krb5Error>;

    /// Retry processing after a preauth failure.
    fn tryagain(
        &self, ctx: &PluginContext<'_>,
        cb: &mut ClpreauthCallbacks<'_>,
        req: TryagainRequest<'_>,
        padata_out: &mut Vec<PaData>,
    ) -> Result<(), Krb5Error> { Err(Krb5Error::NoHandle) }

    /// Encryption types this module can handle.
    fn enctype_list() -> Option<&'static [i32]> { None }

    fn free_modreq(&mut self) {}
}
```

`ClpreauthCallbacks<'a>` provides: `get_etype()`, `get_as_key()`,
`set_as_key(keyblock)`, `need_as_key()`, `disable_fallback()`,
`get_preauth_time(allow_unauth)`, `ask_responder_question(q, challenge)`,
`get_responder_answer(q)`, `get_cc_config(key)`, `set_cc_config(key, val)`.

**Export:**

```rust
initvt_plugin!(clpreauth_myplugin, 1, MyPlugin, kurbu5_rs::clpreauth::glue::make_clpreauth_vtable);
```

---

### AUDIT — KDC audit records

**Header:** `krb5/audit_plugin.h` (private; vendored under `kurbu5-sys/include/krb5/`)
**Major version:** 1
**Crate feature:** `audit`

> **Stability warning:** This is a **private** MIT Kerberos interface and may
> change incompatibly between versions.  The upstream header states: "NOTE: This
> is a private interface and may change incompatibly between versions."  This
> crate vendors the header at the version in use when the crate was built;
> shipping a plugin against a different MIT Kerberos minor release may require a
> rebuild.

An AUDIT plugin allows the MIT KDC to produce log output or audit records in any
desired form.  Multiple AUDIT plugins can be registered; the KDC calls each in
turn for every auditable event.

Unlike all other plugin interfaces, **audit callbacks do not receive a
`krb5_context`**.  The only Kerberos state available to callbacks is what the
plugin stored in `Self` during `open`.

```rust
pub trait AuditModule: Sized + Send + 'static {
    /// Module name written into the vtable `name` field.
    const NAME: &'static CStr;

    /// Open a connection to the audit subsystem.  Called once at KDC startup.
    fn open() -> Result<Self, Krb5Error>;

    /// Close the connection.  Consumes `self`.  Default: drops `self`.
    fn close(self) -> Result<(), Krb5Error> { Ok(()) }

    /// KDC process started.  `success` is false if the KDC is about to abort.
    fn kdc_start(&self, success: bool) -> Result<(), Krb5Error> { Ok(()) }

    /// KDC process stopped.  `success` is false for abnormal termination.
    fn kdc_stop(&self, success: bool) -> Result<(), Krb5Error> { Ok(()) }

    /// AS exchange completed.
    fn as_req(&self, success: bool, state: AuditStateRef<'_>) -> Result<(), Krb5Error> { Ok(()) }

    /// TGS exchange completed.
    fn tgs_req(&self, success: bool, state: AuditStateRef<'_>) -> Result<(), Krb5Error> { Ok(()) }

    /// S4U2SELF TGS exchange completed.
    fn tgs_s4u2self(&self, success: bool, state: AuditStateRef<'_>) -> Result<(), Krb5Error> { Ok(()) }

    /// S4U2PROXY TGS exchange completed.
    fn tgs_s4u2proxy(&self, success: bool, state: AuditStateRef<'_>) -> Result<(), Krb5Error> { Ok(()) }

    /// User-to-User TGS exchange completed.
    fn tgs_u2u(&self, success: bool, state: AuditStateRef<'_>) -> Result<(), Krb5Error> { Ok(()) }
}
```

Only `open` is mandatory; all other methods default to a silent `Ok(())`.

`AuditStateRef<'a>` is a zero-copy view of the KDC audit state structure.  All
fields are valid for the lifetime of the callback; do not store the reference
beyond the call.

| Method | Return type | C field | Notes |
|--------|-------------|---------|-------|
| `stage()` | `i32` | `stage` | Current KDC processing stage (see constants below) |
| `status()` | `Option<&'a str>` | `status` | KDC status string, e.g. `"ISSUE"`, `"CLIENT_NOT_FOUND"` |
| `req_id()` | `&'a str` | `req_id` | Alphanumeric request ID (up to 32 chars); correlate log entries |
| `cl_port()` | `u32` | `cl_port` | Client port number; 0 when unavailable |
| `violation()` | `i32` | `violation` | Policy violation type; 0 = none |
| `tkt_in_id()` | `Option<&'a str>` | `tkt_in_id` | Primary TGT ticket ID |
| `tkt_out_id()` | `Option<&'a str>` | `tkt_out_id` | Derived (service or referral TGT) ticket ID |
| `evid_tkt_id()` | `Option<&'a str>` | `evid_tkt_id` | Evidence ticket ID (S4U2PROXY) or second ticket ID (U2U) |
| `request_raw()` | `*const krb5_kdc_req` | `request` | Raw request pointer; may be null |
| `reply_raw()` | `*const krb5_kdc_rep` | `reply` | Raw reply pointer; null before `ENCR_REP` stage |
| `cl_addr_raw()` | `*const krb5_address` | `cl_addr` | Client address; may be null |
| `cl_realm_raw()` | `*const krb5_data` | `cl_realm` | Client realm (referrals only); may be null |
| `s4u2self_user_raw()` | `krb5_principal` | `s4u2self_user` | Impersonated user (S4U2SELF only); may be null |

Stage constants from `kurbu5_sys`:

| Constant | Value | Meaning |
|----------|-------|---------|
| `AUTHN_REQ_CL` | 1 | Authenticate request and client |
| `SRVC_PRINC` | 2 | Determine service principal |
| `VALIDATE_POL` | 3 | Validate local and protocol policies |
| `ISSUE_TKT` | 4 | Issue ticket |
| `ENCR_REP` | 5 | Encrypt reply |

Policy violation constants from `kurbu5_sys`: `PROT_CONSTRAINT` (1) for a
Kerberos protocol constraint, `LOCAL_POLICY` (2) for a local policy violation.

**Export:**

```rust
initvt_plugin!(audit_myplugin, 1, MyPlugin, kurbu5_rs::audit::glue::make_audit_vtable);
// Exports: audit_myplugin_initvt
```

---

## Derive macros

When the `derive` feature is enabled, all nine traits gain a corresponding
`#[derive(...)]` macro via `kurbu5-derive`.  The derive is designed for
**delegation (overlay) plugins** that wrap another implementation and only
override selected methods.

Every derive requires exactly one field annotated with `#[plugin(delegate)]`
and a `#[plugin(name = "...")]` attribute on the struct:

```rust
use kurbu5_rs::pwqual::PwqualModule;

#[derive(PwqualModule)]
#[plugin(name = "my_overlay")]
pub struct MyOverlay {
    #[plugin(delegate)]
    inner: SomeOtherPlugin,

    // ... additional fields ...
}

// Only override the methods you need; everything else forwards to `inner`.
impl PwqualModule for MyOverlay {
    fn check(&self, ctx: &PluginContext<'_>, req: &CheckRequest<'_>) -> Result<(), PwqualError> {
        // custom check logic...
        self.inner.check(ctx, req)
    }
}
```

Without the `derive` feature, write a full manual `impl` block.

---

## Safety model

* All `unsafe` code is confined to the `glue.rs` sub-module of each interface.
* Every `unsafe` block carries a `// SAFETY:` comment.
* Memory ownership contracts:
  - Strings returned to C: `CString::into_raw` → freed via `free_string` slot.
  - Realm lists: null-terminated `**char` allocated via `Box::into_raw` for
    each element + a `*mut *mut c_char` array; freed via `free_realmlist`.
  - PA-DATA arrays: allocated via `libc::malloc`; freed by the caller
    (libkrb5) using its own `free`.
  - Auth indicators: null-terminated `**char` allocated via `CString::into_raw`
    per element; freed via `free_indicators`.
  - Per-request state (`ModReq`): `Box<dyn Any + Send + 'static>` stored as
    `*mut c_void`; recovered and dropped via `free_modreq`.
* Plugin authors never write `unsafe`.

---

## Integration tests

Each interface module (`pwqual.rs`, `hostrealm.rs`, …) contains an
`#[cfg(test)] mod tests { mod integration_tests { … } }` block that exercises
the C vtable function pointers directly — not the Rust trait methods.

These tests cover:
* All vtable slots are non-null after `make_<interface>_vtable::<M>()`.
* The vtable `name` field points to the module's `NAME` constant.
* Full alloc→use→free cycles for every memory-owning operation (realm lists,
  CString names, auth indicators, PA-DATA arrays, ModReq boxes).
* Both the success path and the error/rejection path for each operation.

Run with:

```sh
cargo test -p kurbu5-rs --features full
```

---

## Feature flags

| Feature | Enables | Notes |
|---------|---------|-------|
| `pwqual` | PWQUAL interface (default on) | |
| `hostrealm` | HOSTREALM interface | |
| `localauth` | LOCALAUTH interface | |
| `ccselect` | CCSELECT interface | |
| `kdcpolicy` | KDCPOLICY interface | |
| `certauth` | CERTAUTH interface | |
| `kdcpreauth` | KDCPREAUTH interface | |
| `clpreauth` | CLPREAUTH interface | |
| `audit` | KDC audit records | `krb5/audit_plugin.h` (private) |
| `derive` | `#[derive(...)]` macros for all nine interfaces | |
| `full` | All nine interfaces (not `derive`) | |
