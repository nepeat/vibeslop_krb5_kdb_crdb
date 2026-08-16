//! Proc-macro crate for `kurbu5-kdb-rs`.
//!
//! Do not depend on this crate directly; use `kurbu5-kdb-rs` with the
//! `derive` feature instead.

use proc_macro::TokenStream;
use proc_macro2::TokenStream as TokenStream2;
use quote::{format_ident, quote};
use syn::{
    Data, DeriveInput, Error, Fields, Ident, Meta, Token, Type,
    parse_macro_input, punctuated::Punctuated,
};

// ---------------------------------------------------------------------------
// #[kdb(...)] attribute parsing
// ---------------------------------------------------------------------------

/// Capability flags parsed from `#[kdb(...)]` `supports_*` options.
///
/// Each flag is stored as a bit in a `u8` to avoid triggering the
/// `clippy::struct_excessive_bools` pedantic lint.
#[derive(Default, Clone, Copy)]
struct KdbCapabilities(u8);

impl KdbCapabilities {
    const CREATE: u8 = 1 << 0;
    const DESTROY: u8 = 1 << 1;
    const PROMOTE_DB: u8 = 1 << 2;
    const DECRYPT_KEY_DATA: u8 = 1 << 3;
    const ENCRYPT_KEY_DATA: u8 = 1 << 4;

    fn create(self) -> bool {
        self.0 & Self::CREATE != 0
    }

    fn destroy(self) -> bool {
        self.0 & Self::DESTROY != 0
    }

    fn promote_db(self) -> bool {
        self.0 & Self::PROMOTE_DB != 0
    }

    fn decrypt_key_data(self) -> bool {
        self.0 & Self::DECRYPT_KEY_DATA != 0
    }

    fn encrypt_key_data(self) -> bool {
        self.0 & Self::ENCRYPT_KEY_DATA != 0
    }
}

#[derive(Default)]
struct KdbArgs {
    /// Field to delegate non-overridden methods to.
    delegate: Option<Ident>,
    /// If set, emits a `kdb_function_table` symbol (absorbs `kdb_plugin!`).
    plugin: Option<String>,
    /// Optional methods the user overrides via `fn kdb_impl_<name>`.
    overrides: Vec<Ident>,
    capabilities: KdbCapabilities,
    /// Override for the crate root path; defaults to `::kurbu5_kdb_rs`.
    krate: Option<syn::Path>,
}

fn parse_kdb_args(attr: &syn::Attribute) -> Result<KdbArgs, Error> {
    let mut args = KdbArgs::default();

    let nested =
        attr.parse_args_with(Punctuated::<Meta, Token![,]>::parse_terminated)?;

    for meta in &nested {
        match meta {
            Meta::NameValue(nv) if nv.path.is_ident("delegate") => {
                if let syn::Expr::Path(ep) = &nv.value {
                    if let Some(ident) = ep.path.get_ident() {
                        args.delegate = Some(ident.clone());
                    } else {
                        return Err(Error::new_spanned(
                            &nv.value,
                            "expected a field name",
                        ));
                    }
                } else {
                    return Err(Error::new_spanned(
                        &nv.value,
                        "expected a field name",
                    ));
                }
            },
            Meta::NameValue(nv) if nv.path.is_ident("plugin") => {
                if let syn::Expr::Lit(el) = &nv.value {
                    if let syn::Lit::Str(ls) = &el.lit {
                        args.plugin = Some(ls.value());
                    } else {
                        return Err(Error::new_spanned(
                            &el.lit,
                            "plugin value must be a string literal",
                        ));
                    }
                } else {
                    return Err(Error::new_spanned(
                        &nv.value,
                        "expected a string literal",
                    ));
                }
            },
            Meta::List(ml) if ml.path.is_ident("overrides") => {
                let methods = ml.parse_args_with(
                    Punctuated::<Ident, Token![,]>::parse_terminated,
                )?;
                args.overrides = methods.into_iter().collect();
            },
            Meta::Path(p) if p.is_ident("supports_create") => {
                args.capabilities.0 |= KdbCapabilities::CREATE;
            },
            Meta::Path(p) if p.is_ident("supports_destroy") => {
                args.capabilities.0 |= KdbCapabilities::DESTROY;
            },
            Meta::Path(p) if p.is_ident("supports_promote_db") => {
                args.capabilities.0 |= KdbCapabilities::PROMOTE_DB;
            },
            Meta::Path(p) if p.is_ident("supports_decrypt_key_data") => {
                args.capabilities.0 |= KdbCapabilities::DECRYPT_KEY_DATA;
            },
            Meta::Path(p) if p.is_ident("supports_encrypt_key_data") => {
                args.capabilities.0 |= KdbCapabilities::ENCRYPT_KEY_DATA;
            },
            Meta::NameValue(nv) if nv.path.is_ident("crate") => {
                if let syn::Expr::Path(ep) = &nv.value {
                    args.krate = Some(ep.path.clone());
                } else {
                    return Err(Error::new_spanned(
                        &nv.value,
                        "expected a path",
                    ));
                }
            },
            other => {
                return Err(Error::new_spanned(
                    other,
                    "unknown #[kdb(...)] option",
                ));
            },
        }
    }

    Ok(args)
}

// ---------------------------------------------------------------------------
// #[derive(KdbModule)]
// ---------------------------------------------------------------------------

/// Derive `KdbModule` for an overlay plugin that delegates to a backing field.
///
/// The primary use case is the **overlay pattern**: a plugin that wraps
/// another KDB module (the *backing database*) and only overrides a handful
/// of methods.  The derive generates a complete `impl KdbModule` block that
/// forwards every non-overridden method to a nominated field using
/// fully-qualified trait syntax, so there is no ambiguity even when the
/// delegate type has inherent methods with the same names.
///
/// The delegate field's type must implement `KdbModule`.  `BackingDb` (from
/// `kurbu5_kdb_rs`) implements `KdbModule` and is the natural choice for
/// overlays that wrap `klmdb` or any other installed KDB module.
///
/// # Attributes
///
/// Place `#[kdb(...)]` on the struct alongside `#[derive(KdbModule)]`:
///
/// | Option | Description |
/// |--------|-------------|
/// | `delegate = field` | **Required.** Field to forward non-overridden methods to. |
/// | `plugin = "name"` | Emit `kdb_function_table` symbol (replaces `kdb_plugin!`). |
/// | `overrides(m1, m2)` | Optional methods implemented via `fn kdb_impl_<m>`. |
/// | `supports_create` | Set `SUPPORTS_CREATE = true`. |
/// | `supports_destroy` | Set `SUPPORTS_DESTROY = true`. |
/// | `supports_promote_db` | Set `SUPPORTS_PROMOTE_DB = true`. |
/// | `supports_decrypt_key_data` | Set `SUPPORTS_DECRYPT_KEY_DATA = true`. |
/// | `supports_encrypt_key_data` | Set `SUPPORTS_ENCRYPT_KEY_DATA = true`. |
/// | `crate = path` | Crate root path; defaults to `::kurbu5_kdb_rs`. |
///
/// # Required inherent methods
///
/// Because `open` and `get_principal` have no defaults in `KdbModule`, they
/// are always dispatched to `Self::kdb_impl_open` and
/// `self.kdb_impl_get_principal`.  Use [`kdb_method`] to rename your
/// implementations automatically.
///
/// # Optional method overrides
///
/// For optional methods with custom logic (e.g. `create`, `destroy`,
/// `promote_db`), list them in `overrides(...)` and mark them with
/// `#[kdb_method]` inside a `#[kdb_impl]` block.  Methods *not* listed in
/// `overrides` are automatically forwarded to the delegate field via
/// `<DelegateType as KdbModule>::method(&self.field, ctx, ...)`.
///
/// # Example
///
/// ```rust,ignore
/// use kurbu5_kdb_rs::{
///     kdb_impl, kdb_method, BackingDb, KdbContext, KdbError, KdbModule,
///     LookupFlags, OpenMode, PrincipalEntry, PrincipalRef,
/// };
///
/// /// Overlay that intercepts get_principal; all other operations delegate
/// /// to the backing klmdb database loaded from the same conf_section.
/// #[derive(KdbModule)]
/// #[kdb(delegate = backing, plugin = "my_overlay")]
/// struct MyOverlay {
///     backing: BackingDb,
/// }
///
/// #[kdb_impl]
/// impl MyOverlay {
///     #[kdb_method]
///     fn open(
///         ctx: &KdbContext<'_>,
///         conf_section: &str,
///         db_args: &[&str],
///         mode: OpenMode,
///     ) -> Result<Self, KdbError> {
///         let backing = BackingDb::open(ctx, "klmdb", db_args, mode)?;
///         Ok(MyOverlay { backing })
///     }
///
///     #[kdb_method]
///     fn get_principal(
///         &self,
///         ctx: &KdbContext<'_>,
///         search_for: PrincipalRef<'_>,
///         flags: LookupFlags,
///     ) -> Result<Option<PrincipalEntry>, KdbError> {
///         // Custom lookup logic; fall back to klmdb on miss.
///         if let Some(entry) = self.backing.get_principal(search_for, flags)? {
///             return Ok(Some(entry));
///         }
///         // ... additional fallback ...
///         Ok(None)
///     }
/// }
/// // All other KdbModule methods (put_principal, iterate_principals,
/// // policy CRUD, check_policy_as, audit_as_req, …) are auto-generated
/// // and forward to self.backing via <BackingDb as KdbModule>::method(…).
/// ```
#[proc_macro_derive(KdbModule, attributes(kdb))]
pub fn derive_kdb_module(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    derive_impl(&input)
        .unwrap_or_else(|e| e.to_compile_error())
        .into()
}

fn derive_impl(input: &DeriveInput) -> Result<TokenStream2, Error> {
    let kdb_attr = input
        .attrs
        .iter()
        .find(|a| a.path().is_ident("kdb"))
        .ok_or_else(|| {
            Error::new_spanned(
                &input.ident,
                "#[derive(KdbModule)] requires a #[kdb(delegate = field, ...)] attribute",
            )
        })?;

    let args = parse_kdb_args(kdb_attr)?;

    let krate: syn::Path = args.krate.clone().unwrap_or_else(|| {
        syn::parse_str("::kurbu5_kdb_rs").expect("valid path")
    });

    let delegate_name = args.delegate.as_ref().ok_or_else(|| {
        Error::new_spanned(
            kdb_attr,
            "#[kdb(...)] requires `delegate = field_name`",
        )
    })?;

    let delegate_ty = find_field_type(input, delegate_name)?;
    let struct_name = &input.ident;

    let impl_block =
        generate_impl(struct_name, delegate_name, delegate_ty, &args, &krate);
    let symbol = if args.plugin.is_some() {
        generate_symbol(struct_name, &krate)
    } else {
        quote! {}
    };

    Ok(quote! {
        #impl_block
        #symbol
    })
}

fn find_field_type<'a>(
    input: &'a DeriveInput,
    field_name: &Ident,
) -> Result<&'a Type, Error> {
    let fields = match &input.data {
        Data::Struct(ds) => &ds.fields,
        _ => {
            return Err(Error::new_spanned(
                &input.ident,
                "#[derive(KdbModule)] only applies to structs",
            ));
        },
    };
    match fields {
        Fields::Named(named) => named
            .named
            .iter()
            .find(|f| f.ident.as_ref() == Some(field_name))
            .map(|f| &f.ty)
            .ok_or_else(|| {
                Error::new_spanned(
                    field_name,
                    format!("field `{field_name}` not found in struct"),
                )
            }),
        _ => Err(Error::new_spanned(
            &input.ident,
            "#[derive(KdbModule)] requires named fields",
        )),
    }
}

// ---------------------------------------------------------------------------
// impl block generation
// ---------------------------------------------------------------------------

fn has_override(args: &KdbArgs, name: &str) -> bool {
    args.overrides.iter().any(|id| id == name)
}

/// For an instance method: either delegate to `self.f.method(args)` or
/// dispatch to `self.kdb_impl_method(args)`.
fn inst<F, G>(args: &KdbArgs, name: &str, delegate: F, ovr: G) -> TokenStream2
where
    F: FnOnce() -> TokenStream2,
    G: FnOnce() -> TokenStream2,
{
    if has_override(args, name) {
        ovr()
    } else {
        delegate()
    }
}

/// For a static/associated method: delegate to `<Dt as KdbModule>::method(args)`
/// or dispatch to `Self::kdb_impl_method(args)`.
fn stat<F, G>(args: &KdbArgs, name: &str, delegate: F, ovr: G) -> TokenStream2
where
    F: FnOnce() -> TokenStream2,
    G: FnOnce() -> TokenStream2,
{
    if has_override(args, name) {
        ovr()
    } else {
        delegate()
    }
}

fn generate_impl(
    name: &Ident,
    f: &Ident,
    dt: &Type,
    args: &KdbArgs,
    kr: &syn::Path,
) -> TokenStream2 {
    let supports_create = args.capabilities.create();
    let supports_destroy = args.capabilities.destroy();
    let supports_promote_db = args.capabilities.promote_db();
    let supports_decrypt = args.capabilities.decrypt_key_data();
    let supports_encrypt = args.capabilities.encrypt_key_data();

    let lifecycle = gen_lifecycle_methods(f, dt, args, kr);
    let principal = gen_principal_methods(f, dt, args, kr);
    let policy = gen_policy_methods(f, dt, args, kr);
    let key = gen_key_methods(f, dt, args, kr);
    let kdc_as_tgs = gen_kdc_as_tgs_methods(f, dt, args, kr);
    let kdc_delegation = gen_kdc_delegation_methods(f, dt, args, kr);
    let audit_refresh = gen_audit_refresh_methods(f, dt, args, kr);
    let s4u_pac = gen_s4u_pac_methods(f, dt, args, kr);

    quote! {
        impl #kr::KdbModule for #name {
            const SUPPORTS_CREATE: bool = #supports_create;
            const SUPPORTS_DESTROY: bool = #supports_destroy;
            const SUPPORTS_PROMOTE_DB: bool = #supports_promote_db;
            const SUPPORTS_DECRYPT_KEY_DATA: bool = #supports_decrypt;
            const SUPPORTS_ENCRYPT_KEY_DATA: bool = #supports_encrypt;

            #lifecycle
            #principal
            #policy
            #key
            #kdc_as_tgs
            #kdc_delegation
            #audit_refresh
            #s4u_pac
        }
    }
}

/// Generate static library/db lifecycle methods (`init_library`, `fini_library`,
/// `create`, `destroy`, `promote_db`) and instance methods (`open`,
/// `get_principal`, `close`, `lock`, `unlock`).
fn gen_lifecycle_methods(
    f: &Ident,
    dt: &Type,
    args: &KdbArgs,
    kr: &syn::Path,
) -> TokenStream2 {
    let static_methods = gen_static_lifecycle_methods(dt, args, kr);
    let instance_methods = gen_instance_lifecycle_methods(f, dt, args, kr);
    quote! {
        #static_methods
        #instance_methods
    }
}

/// Generate the `init_library` and `fini_library` static methods.
fn gen_library_init_methods(
    dt: &Type,
    args: &KdbArgs,
    kr: &syn::Path,
) -> TokenStream2 {
    let init = stat(
        args,
        "init_library",
        || {
            quote! {
                fn init_library() -> ::std::result::Result<(), #kr::KdbError> {
                    <#dt as #kr::KdbModule>::init_library()
                }
            }
        },
        || {
            quote! {
                fn init_library() -> ::std::result::Result<(), #kr::KdbError> {
                    Self::kdb_impl_init_library()
                }
            }
        },
    );
    let fini = stat(
        args,
        "fini_library",
        || {
            quote! {
                fn fini_library() -> ::std::result::Result<(), #kr::KdbError> {
                    <#dt as #kr::KdbModule>::fini_library()
                }
            }
        },
        || {
            quote! {
                fn fini_library() -> ::std::result::Result<(), #kr::KdbError> {
                    Self::kdb_impl_fini_library()
                }
            }
        },
    );
    quote! { #init #fini }
}

/// Generate the `create`, `destroy`, and `promote_db` static methods.
/// All three share the same signature `(ctx, conf_section, db_args)`.
fn gen_db_management_methods(
    dt: &Type,
    args: &KdbArgs,
    kr: &syn::Path,
) -> TokenStream2 {
    let methods: &[(&str, Ident)] = &[
        ("create", format_ident!("kdb_impl_create")),
        ("destroy", format_ident!("kdb_impl_destroy")),
        ("promote_db", format_ident!("kdb_impl_promote_db")),
    ];
    let tokens: Vec<TokenStream2> = methods
        .iter()
        .map(|(name, impl_fn)| {
            let fn_ident = format_ident!("{name}");
            stat(
                args,
                name,
                || quote! {
                    fn #fn_ident(
                        ctx: &#kr::KdbContext<'_>,
                        conf_section: &str,
                        db_args: &[&str],
                    ) -> ::std::result::Result<(), #kr::KdbError> {
                        <#dt as #kr::KdbModule>::#fn_ident(ctx, conf_section, db_args)
                    }
                },
                || quote! {
                    fn #fn_ident(
                        ctx: &#kr::KdbContext<'_>,
                        conf_section: &str,
                        db_args: &[&str],
                    ) -> ::std::result::Result<(), #kr::KdbError> {
                        Self::#impl_fn(ctx, conf_section, db_args)
                    }
                },
            )
        })
        .collect();
    quote! { #(#tokens)* }
}

/// Generate static (associated) library/db lifecycle methods:
/// `init_library`, `fini_library`, `create`, `destroy`, `promote_db`.
fn gen_static_lifecycle_methods(
    dt: &Type,
    args: &KdbArgs,
    kr: &syn::Path,
) -> TokenStream2 {
    let lib = gen_library_init_methods(dt, args, kr);
    let db = gen_db_management_methods(dt, args, kr);
    quote! { #lib #db }
}

/// Generate instance lifecycle methods: `open`, `get_principal`, `close`,
/// `lock`, `unlock`.
fn gen_instance_lifecycle_methods(
    f: &Ident,
    dt: &Type,
    args: &KdbArgs,
    kr: &syn::Path,
) -> TokenStream2 {
    let open = quote! {
        fn open(
            ctx: &#kr::KdbContext<'_>,
            conf_section: &str,
            db_args: &[&str],
            mode: #kr::OpenMode,
        ) -> ::std::result::Result<Self, #kr::KdbError> {
            Self::kdb_impl_open(ctx, conf_section, db_args, mode)
        }
    };
    let get_principal = quote! {
        fn get_principal(
            &self,
            ctx: &#kr::KdbContext<'_>,
            search_for: #kr::PrincipalRef<'_>,
            flags: #kr::LookupFlags,
        ) -> ::std::result::Result<
            ::std::option::Option<#kr::PrincipalEntry>,
            #kr::KdbError,
        > {
            self.kdb_impl_get_principal(ctx, search_for, flags)
        }
    };
    let close = inst(
        args,
        "close",
        || {
            quote! {
                fn close(self) -> ::std::result::Result<(), #kr::KdbError> {
                    <#dt as #kr::KdbModule>::close(self.#f)
                }
            }
        },
        || {
            quote! {
                fn close(self) -> ::std::result::Result<(), #kr::KdbError> {
                    Self::kdb_impl_close(self)
                }
            }
        },
    );
    let lock = inst(
        args,
        "lock",
        || {
            quote! {
                fn lock(
                    &self,
                    mode: #kr::LockMode,
                ) -> ::std::result::Result<(), #kr::KdbError> {
                    <#dt as #kr::KdbModule>::lock(&self.#f, mode)
                }
            }
        },
        || {
            quote! {
                fn lock(
                    &self,
                    mode: #kr::LockMode,
                ) -> ::std::result::Result<(), #kr::KdbError> {
                    self.kdb_impl_lock(mode)
                }
            }
        },
    );
    let unlock = inst(
        args,
        "unlock",
        || {
            quote! {
                fn unlock(&self) -> ::std::result::Result<(), #kr::KdbError> {
                    <#dt as #kr::KdbModule>::unlock(&self.#f)
                }
            }
        },
        || {
            quote! {
                fn unlock(&self) -> ::std::result::Result<(), #kr::KdbError> {
                    self.kdb_impl_unlock()
                }
            }
        },
    );
    quote! { #open #close #lock #unlock #get_principal }
}

/// Generate principal CRUD methods: `put_principal`, `delete_principal`,
/// `rename_principal`, `iterate_principals`.
fn gen_principal_methods(
    f: &Ident,
    dt: &Type,
    args: &KdbArgs,
    kr: &syn::Path,
) -> TokenStream2 {
    let m1 = gen_principal_write_methods(f, dt, args, kr);
    let m2 = gen_principal_iter_methods(f, dt, args, kr);
    quote! { #m1 #m2 }
}

/// Generate `put_principal`, `delete_principal`, `rename_principal`.
fn gen_principal_write_methods(
    f: &Ident,
    dt: &Type,
    args: &KdbArgs,
    kr: &syn::Path,
) -> TokenStream2 {
    let put = inst(
        args,
        "put_principal",
        || {
            quote! {
                fn put_principal(
                    &self,
                    ctx: &#kr::KdbContext<'_>,
                    entry: #kr::PrincipalEntryRef<'_>,
                    db_args: &[&str],
                ) -> ::std::result::Result<(), #kr::KdbError> {
                    <#dt as #kr::KdbModule>::put_principal(&self.#f, ctx, entry, db_args)
                }
            }
        },
        || {
            quote! {
                fn put_principal(
                    &self,
                    ctx: &#kr::KdbContext<'_>,
                    entry: #kr::PrincipalEntryRef<'_>,
                    db_args: &[&str],
                ) -> ::std::result::Result<(), #kr::KdbError> {
                    self.kdb_impl_put_principal(ctx, entry, db_args)
                }
            }
        },
    );
    let delete = inst(
        args,
        "delete_principal",
        || {
            quote! {
                fn delete_principal(
                    &self,
                    ctx: &#kr::KdbContext<'_>,
                    search_for: #kr::PrincipalRef<'_>,
                ) -> ::std::result::Result<(), #kr::KdbError> {
                    <#dt as #kr::KdbModule>::delete_principal(&self.#f, ctx, search_for)
                }
            }
        },
        || {
            quote! {
                fn delete_principal(
                    &self,
                    ctx: &#kr::KdbContext<'_>,
                    search_for: #kr::PrincipalRef<'_>,
                ) -> ::std::result::Result<(), #kr::KdbError> {
                    self.kdb_impl_delete_principal(ctx, search_for)
                }
            }
        },
    );
    let rename = inst(
        args,
        "rename_principal",
        || {
            quote! {
                fn rename_principal(
                    &self,
                    ctx: &#kr::KdbContext<'_>,
                    source: #kr::PrincipalRef<'_>,
                    target: #kr::PrincipalRef<'_>,
                ) -> ::std::result::Result<(), #kr::KdbError> {
                    <#dt as #kr::KdbModule>::rename_principal(&self.#f, ctx, source, target)
                }
            }
        },
        || {
            quote! {
                fn rename_principal(
                    &self,
                    ctx: &#kr::KdbContext<'_>,
                    source: #kr::PrincipalRef<'_>,
                    target: #kr::PrincipalRef<'_>,
                ) -> ::std::result::Result<(), #kr::KdbError> {
                    self.kdb_impl_rename_principal(ctx, source, target)
                }
            }
        },
    );
    quote! { #put #delete #rename }
}

/// Generate `iterate_principals`.
fn gen_principal_iter_methods(
    f: &Ident,
    dt: &Type,
    args: &KdbArgs,
    kr: &syn::Path,
) -> TokenStream2 {
    inst(
        args,
        "iterate_principals",
        || {
            quote! {
                fn iterate_principals(
                    &self,
                    ctx: &#kr::KdbContext<'_>,
                    match_entry: ::std::option::Option<&str>,
                    flags: #kr::IterFlags,
                    callback: &mut dyn ::std::ops::FnMut(
                        #kr::PrincipalEntryRef<'_>,
                    ) -> ::std::result::Result<(), #kr::KdbError>,
                ) -> ::std::result::Result<(), #kr::KdbError> {
                    <#dt as #kr::KdbModule>::iterate_principals(
                        &self.#f, ctx, match_entry, flags, callback,
                    )
                }
            }
        },
        || {
            quote! {
                fn iterate_principals(
                    &self,
                    ctx: &#kr::KdbContext<'_>,
                    match_entry: ::std::option::Option<&str>,
                    flags: #kr::IterFlags,
                    callback: &mut dyn ::std::ops::FnMut(
                        #kr::PrincipalEntryRef<'_>,
                    ) -> ::std::result::Result<(), #kr::KdbError>,
                ) -> ::std::result::Result<(), #kr::KdbError> {
                    self.kdb_impl_iterate_principals(ctx, match_entry, flags, callback)
                }
            }
        },
    )
}

/// Generate policy CRUD methods: `create_policy`, `get_policy`, `put_policy`,
/// `iter_policy`, `delete_policy`.
fn gen_policy_methods(
    f: &Ident,
    dt: &Type,
    args: &KdbArgs,
    kr: &syn::Path,
) -> TokenStream2 {
    let m1 = gen_policy_rw_methods(f, dt, args, kr);
    let m2 = gen_policy_iter_delete_methods(f, dt, args, kr);
    quote! { #m1 #m2 }
}

/// Generate `create_policy`, `get_policy`, `put_policy`.
fn gen_policy_rw_methods(
    f: &Ident,
    dt: &Type,
    args: &KdbArgs,
    kr: &syn::Path,
) -> TokenStream2 {
    let create = inst(
        args,
        "create_policy",
        || {
            quote! {
                fn create_policy(
                    &self,
                    ctx: &#kr::KdbContext<'_>,
                    policy: &#kr::PolicyEntry,
                ) -> ::std::result::Result<(), #kr::KdbError> {
                    <#dt as #kr::KdbModule>::create_policy(&self.#f, ctx, policy)
                }
            }
        },
        || {
            quote! {
                fn create_policy(
                    &self,
                    ctx: &#kr::KdbContext<'_>,
                    policy: &#kr::PolicyEntry,
                ) -> ::std::result::Result<(), #kr::KdbError> {
                    self.kdb_impl_create_policy(ctx, policy)
                }
            }
        },
    );
    let get = inst(
        args,
        "get_policy",
        || {
            quote! {
                fn get_policy(
                    &self,
                    ctx: &#kr::KdbContext<'_>,
                    name: &str,
                ) -> ::std::result::Result<
                    ::std::option::Option<#kr::PolicyEntry>,
                    #kr::KdbError,
                > {
                    <#dt as #kr::KdbModule>::get_policy(&self.#f, ctx, name)
                }
            }
        },
        || {
            quote! {
                fn get_policy(
                    &self,
                    ctx: &#kr::KdbContext<'_>,
                    name: &str,
                ) -> ::std::result::Result<
                    ::std::option::Option<#kr::PolicyEntry>,
                    #kr::KdbError,
                > {
                    self.kdb_impl_get_policy(ctx, name)
                }
            }
        },
    );
    let put = inst(
        args,
        "put_policy",
        || {
            quote! {
                fn put_policy(
                    &self,
                    ctx: &#kr::KdbContext<'_>,
                    policy: &#kr::PolicyEntry,
                ) -> ::std::result::Result<(), #kr::KdbError> {
                    <#dt as #kr::KdbModule>::put_policy(&self.#f, ctx, policy)
                }
            }
        },
        || {
            quote! {
                fn put_policy(
                    &self,
                    ctx: &#kr::KdbContext<'_>,
                    policy: &#kr::PolicyEntry,
                ) -> ::std::result::Result<(), #kr::KdbError> {
                    self.kdb_impl_put_policy(ctx, policy)
                }
            }
        },
    );
    quote! { #create #get #put }
}

/// Generate `iter_policy` and `delete_policy`.
fn gen_policy_iter_delete_methods(
    f: &Ident,
    dt: &Type,
    args: &KdbArgs,
    kr: &syn::Path,
) -> TokenStream2 {
    let iter = inst(
        args,
        "iter_policy",
        || {
            quote! {
                fn iter_policy(
                    &self,
                    ctx: &#kr::KdbContext<'_>,
                    match_entry: ::std::option::Option<&str>,
                    callback: &mut dyn ::std::ops::FnMut(
                        &#kr::PolicyEntry,
                    ) -> ::std::result::Result<(), #kr::KdbError>,
                ) -> ::std::result::Result<(), #kr::KdbError> {
                    <#dt as #kr::KdbModule>::iter_policy(
                        &self.#f, ctx, match_entry, callback,
                    )
                }
            }
        },
        || {
            quote! {
                fn iter_policy(
                    &self,
                    ctx: &#kr::KdbContext<'_>,
                    match_entry: ::std::option::Option<&str>,
                    callback: &mut dyn ::std::ops::FnMut(
                        &#kr::PolicyEntry,
                    ) -> ::std::result::Result<(), #kr::KdbError>,
                ) -> ::std::result::Result<(), #kr::KdbError> {
                    self.kdb_impl_iter_policy(ctx, match_entry, callback)
                }
            }
        },
    );
    let delete = inst(
        args,
        "delete_policy",
        || {
            quote! {
                fn delete_policy(
                    &self,
                    ctx: &#kr::KdbContext<'_>,
                    name: &str,
                ) -> ::std::result::Result<(), #kr::KdbError> {
                    <#dt as #kr::KdbModule>::delete_policy(&self.#f, ctx, name)
                }
            }
        },
        || {
            quote! {
                fn delete_policy(
                    &self,
                    ctx: &#kr::KdbContext<'_>,
                    name: &str,
                ) -> ::std::result::Result<(), #kr::KdbError> {
                    self.kdb_impl_delete_policy(ctx, name)
                }
            }
        },
    );
    quote! { #iter #delete }
}

/// Generate key-related methods: `fetch_master_key`, `dbe_search_enctype`,
/// `decrypt_key_data`, `encrypt_key_data`.
fn gen_key_methods(
    f: &Ident,
    dt: &Type,
    args: &KdbArgs,
    kr: &syn::Path,
) -> TokenStream2 {
    let m1 = gen_key_fetch_search_methods(f, dt, args, kr);
    let m2 = gen_key_crypto_methods(f, dt, args, kr);
    quote! { #m1 #m2 }
}

/// Generate `fetch_master_key` and `dbe_search_enctype`.
fn gen_key_fetch_search_methods(
    f: &Ident,
    dt: &Type,
    args: &KdbArgs,
    kr: &syn::Path,
) -> TokenStream2 {
    let fetch = inst(
        args,
        "fetch_master_key",
        || {
            quote! {
                fn fetch_master_key(
                    &self,
                    ctx: &#kr::KdbContext<'_>,
                    mname: #kr::PrincipalRef<'_>,
                    db_args: &str,
                ) -> ::std::result::Result<(#kr::KeyBlock, u32), #kr::KdbError> {
                    <#dt as #kr::KdbModule>::fetch_master_key(&self.#f, ctx, mname, db_args)
                }
            }
        },
        || {
            quote! {
                fn fetch_master_key(
                    &self,
                    ctx: &#kr::KdbContext<'_>,
                    mname: #kr::PrincipalRef<'_>,
                    db_args: &str,
                ) -> ::std::result::Result<(#kr::KeyBlock, u32), #kr::KdbError> {
                    self.kdb_impl_fetch_master_key(ctx, mname, db_args)
                }
            }
        },
    );
    let search = inst(
        args,
        "dbe_search_enctype",
        || {
            quote! {
                fn dbe_search_enctype<'entry>(
                    &self,
                    ctx: &#kr::KdbContext<'_>,
                    entry: #kr::PrincipalEntryRef<'entry>,
                    start: &mut i32,
                    ktype: i32,
                    stype: i32,
                    kvno: i32,
                ) -> ::std::result::Result<
                    ::std::option::Option<#kr::KeyDataRef<'entry>>,
                    #kr::KdbError,
                > {
                    <#dt as #kr::KdbModule>::dbe_search_enctype(
                        &self.#f, ctx, entry, start, ktype, stype, kvno,
                    )
                }
            }
        },
        || {
            quote! {
                fn dbe_search_enctype<'entry>(
                    &self,
                    ctx: &#kr::KdbContext<'_>,
                    entry: #kr::PrincipalEntryRef<'entry>,
                    start: &mut i32,
                    ktype: i32,
                    stype: i32,
                    kvno: i32,
                ) -> ::std::result::Result<
                    ::std::option::Option<#kr::KeyDataRef<'entry>>,
                    #kr::KdbError,
                > {
                    self.kdb_impl_dbe_search_enctype(ctx, entry, start, ktype, stype, kvno)
                }
            }
        },
    );
    quote! { #fetch #search }
}

/// Generate `decrypt_key_data` and `encrypt_key_data`.
fn gen_key_crypto_methods(
    f: &Ident,
    dt: &Type,
    args: &KdbArgs,
    kr: &syn::Path,
) -> TokenStream2 {
    let decrypt = inst(
        args,
        "decrypt_key_data",
        || {
            quote! {
                fn decrypt_key_data(
                    &self,
                    ctx: &#kr::KdbContext<'_>,
                    req: #kr::DecryptKeyRequest<'_>,
                ) -> ::std::result::Result<
                    (#kr::KeyBlock, ::std::option::Option<#kr::KeySalt>),
                    #kr::KdbError,
                > {
                    <#dt as #kr::KdbModule>::decrypt_key_data(&self.#f, ctx, req)
                }
            }
        },
        || {
            quote! {
                fn decrypt_key_data(
                    &self,
                    ctx: &#kr::KdbContext<'_>,
                    req: #kr::DecryptKeyRequest<'_>,
                ) -> ::std::result::Result<
                    (#kr::KeyBlock, ::std::option::Option<#kr::KeySalt>),
                    #kr::KdbError,
                > {
                    self.kdb_impl_decrypt_key_data(ctx, req)
                }
            }
        },
    );
    let encrypt = inst(
        args,
        "encrypt_key_data",
        || {
            quote! {
                fn encrypt_key_data(
                    &self,
                    ctx: &#kr::KdbContext<'_>,
                    req: #kr::EncryptKeyRequest<'_>,
                ) -> ::std::result::Result<#kr::KeyDataOwned, #kr::KdbError> {
                    <#dt as #kr::KdbModule>::encrypt_key_data(&self.#f, ctx, req)
                }
            }
        },
        || {
            quote! {
                fn encrypt_key_data(
                    &self,
                    ctx: &#kr::KdbContext<'_>,
                    req: #kr::EncryptKeyRequest<'_>,
                ) -> ::std::result::Result<#kr::KeyDataOwned, #kr::KdbError> {
                    self.kdb_impl_encrypt_key_data(ctx, req)
                }
            }
        },
    );
    quote! { #decrypt #encrypt }
}

/// Generate AS/TGS policy check methods: `check_policy_as`, `check_policy_tgs`.
fn gen_kdc_as_tgs_methods(
    f: &Ident,
    dt: &Type,
    args: &KdbArgs,
    kr: &syn::Path,
) -> TokenStream2 {
    let check_policy_as = inst(
        args,
        "check_policy_as",
        || {
            quote! {
                fn check_policy_as(
                    &self,
                    ctx: &#kr::KdbContext<'_>,
                    req: #kr::AsPolicyRequest<'_>,
                ) -> ::std::result::Result<(), #kr::PolicyDenied> {
                    <#dt as #kr::KdbModule>::check_policy_as(&self.#f, ctx, req)
                }
            }
        },
        || {
            quote! {
                fn check_policy_as(
                    &self,
                    ctx: &#kr::KdbContext<'_>,
                    req: #kr::AsPolicyRequest<'_>,
                ) -> ::std::result::Result<(), #kr::PolicyDenied> {
                    self.kdb_impl_check_policy_as(ctx, req)
                }
            }
        },
    );
    let check_policy_tgs = inst(
        args,
        "check_policy_tgs",
        || {
            quote! {
                fn check_policy_tgs(
                    &self,
                    ctx: &#kr::KdbContext<'_>,
                    req: #kr::TgsPolicyRequest<'_>,
                ) -> ::std::result::Result<(), #kr::PolicyDenied> {
                    <#dt as #kr::KdbModule>::check_policy_tgs(&self.#f, ctx, req)
                }
            }
        },
        || {
            quote! {
                fn check_policy_tgs(
                    &self,
                    ctx: &#kr::KdbContext<'_>,
                    req: #kr::TgsPolicyRequest<'_>,
                ) -> ::std::result::Result<(), #kr::PolicyDenied> {
                    self.kdb_impl_check_policy_tgs(ctx, req)
                }
            }
        },
    );
    quote! { #check_policy_as #check_policy_tgs }
}

/// Generate delegation check methods: `check_transited_realms`,
/// `check_allowed_to_delegate`, `allowed_to_delegate_from`.
fn gen_kdc_delegation_methods(
    f: &Ident,
    dt: &Type,
    args: &KdbArgs,
    kr: &syn::Path,
) -> TokenStream2 {
    let check_transited_realms = inst(
        args,
        "check_transited_realms",
        || {
            quote! {
                fn check_transited_realms(
                    &self,
                    ctx: &#kr::KdbContext<'_>,
                    tr_contents: &[u8],
                    client_realm: &[u8],
                    server_realm: &[u8],
                ) -> ::std::result::Result<(), #kr::KdbError> {
                    <#dt as #kr::KdbModule>::check_transited_realms(
                        &self.#f, ctx, tr_contents, client_realm, server_realm,
                    )
                }
            }
        },
        || {
            quote! {
                fn check_transited_realms(
                    &self,
                    ctx: &#kr::KdbContext<'_>,
                    tr_contents: &[u8],
                    client_realm: &[u8],
                    server_realm: &[u8],
                ) -> ::std::result::Result<(), #kr::KdbError> {
                    self.kdb_impl_check_transited_realms(
                        ctx, tr_contents, client_realm, server_realm,
                    )
                }
            }
        },
    );
    let check_allowed_to_delegate = inst(
        args,
        "check_allowed_to_delegate",
        || {
            quote! {
                fn check_allowed_to_delegate(
                    &self,
                    ctx: &#kr::KdbContext<'_>,
                    req: #kr::DelegationRequest<'_>,
                ) -> ::std::result::Result<(), #kr::KdbError> {
                    <#dt as #kr::KdbModule>::check_allowed_to_delegate(&self.#f, ctx, req)
                }
            }
        },
        || {
            quote! {
                fn check_allowed_to_delegate(
                    &self,
                    ctx: &#kr::KdbContext<'_>,
                    req: #kr::DelegationRequest<'_>,
                ) -> ::std::result::Result<(), #kr::KdbError> {
                    self.kdb_impl_check_allowed_to_delegate(ctx, req)
                }
            }
        },
    );
    let allowed_to_delegate_from = inst(
        args,
        "allowed_to_delegate_from",
        || {
            quote! {
                fn allowed_to_delegate_from(
                    &self,
                    ctx: &#kr::KdbContext<'_>,
                    req: #kr::ResourceDelegationRequest<'_>,
                ) -> ::std::result::Result<(), #kr::KdbError> {
                    <#dt as #kr::KdbModule>::allowed_to_delegate_from(&self.#f, ctx, req)
                }
            }
        },
        || {
            quote! {
                fn allowed_to_delegate_from(
                    &self,
                    ctx: &#kr::KdbContext<'_>,
                    req: #kr::ResourceDelegationRequest<'_>,
                ) -> ::std::result::Result<(), #kr::KdbError> {
                    self.kdb_impl_allowed_to_delegate_from(ctx, req)
                }
            }
        },
    );
    quote! {
        #check_transited_realms
        #check_allowed_to_delegate
        #allowed_to_delegate_from
    }
}

/// Generate audit and config refresh methods: `audit_as_req`, `refresh_config`.
fn gen_audit_refresh_methods(
    f: &Ident,
    dt: &Type,
    args: &KdbArgs,
    kr: &syn::Path,
) -> TokenStream2 {
    let audit_as_req = inst(
        args,
        "audit_as_req",
        || {
            quote! {
                fn audit_as_req(
                    &self,
                    ctx: &#kr::KdbContext<'_>,
                    event: #kr::AsAuditEvent<'_>,
                ) {
                    <#dt as #kr::KdbModule>::audit_as_req(&self.#f, ctx, event)
                }
            }
        },
        || {
            quote! {
                fn audit_as_req(
                    &self,
                    ctx: &#kr::KdbContext<'_>,
                    event: #kr::AsAuditEvent<'_>,
                ) {
                    self.kdb_impl_audit_as_req(ctx, event)
                }
            }
        },
    );
    let refresh_config = inst(
        args,
        "refresh_config",
        || {
            quote! {
                fn refresh_config(&self, ctx: &#kr::KdbContext<'_>) {
                    <#dt as #kr::KdbModule>::refresh_config(&self.#f, ctx)
                }
            }
        },
        || {
            quote! {
                fn refresh_config(&self, ctx: &#kr::KdbContext<'_>) {
                    self.kdb_impl_refresh_config(ctx)
                }
            }
        },
    );
    quote! { #audit_as_req #refresh_config }
}

/// Generate S4U, PAC, and principal-data freeing methods:
/// `get_s4u_x509_principal`, `issue_pac`, `free_principal_e_data`.
fn gen_s4u_pac_methods(
    f: &Ident,
    dt: &Type,
    args: &KdbArgs,
    kr: &syn::Path,
) -> TokenStream2 {
    let get_s4u_x509_principal = inst(
        args,
        "get_s4u_x509_principal",
        || {
            quote! {
                fn get_s4u_x509_principal(
                    &self,
                    ctx: &#kr::KdbContext<'_>,
                    req: #kr::S4uX509Request<'_>,
                ) -> ::std::result::Result<
                    ::std::option::Option<#kr::PrincipalEntry>,
                    #kr::KdbError,
                > {
                    <#dt as #kr::KdbModule>::get_s4u_x509_principal(&self.#f, ctx, req)
                }
            }
        },
        || {
            quote! {
                fn get_s4u_x509_principal(
                    &self,
                    ctx: &#kr::KdbContext<'_>,
                    req: #kr::S4uX509Request<'_>,
                ) -> ::std::result::Result<
                    ::std::option::Option<#kr::PrincipalEntry>,
                    #kr::KdbError,
                > {
                    self.kdb_impl_get_s4u_x509_principal(ctx, req)
                }
            }
        },
    );
    let issue_pac = inst(
        args,
        "issue_pac",
        || {
            quote! {
                fn issue_pac(
                    &self,
                    ctx: &#kr::KdbContext<'_>,
                    req: #kr::PacIssuanceRequest<'_>,
                    output: &mut #kr::PacIssuanceOutput<'_>,
                ) -> ::std::result::Result<(), #kr::KdbError> {
                    <#dt as #kr::KdbModule>::issue_pac(&self.#f, ctx, req, output)
                }
            }
        },
        || {
            quote! {
                fn issue_pac(
                    &self,
                    ctx: &#kr::KdbContext<'_>,
                    req: #kr::PacIssuanceRequest<'_>,
                    output: &mut #kr::PacIssuanceOutput<'_>,
                ) -> ::std::result::Result<(), #kr::KdbError> {
                    self.kdb_impl_issue_pac(ctx, req, output)
                }
            }
        },
    );
    let free_principal_e_data = inst(
        args,
        "free_principal_e_data",
        || {
            quote! {
                fn free_principal_e_data(&self, e_data: *mut u8) {
                    <#dt as #kr::KdbModule>::free_principal_e_data(&self.#f, e_data)
                }
            }
        },
        || {
            quote! {
                fn free_principal_e_data(&self, e_data: *mut u8) {
                    self.kdb_impl_free_principal_e_data(e_data)
                }
            }
        },
    );
    quote! {
        #get_s4u_x509_principal
        #issue_pac
        #free_principal_e_data
    }
}

fn generate_symbol(name: &Ident, kr: &syn::Path) -> TokenStream2 {
    // SAFETY: same contract as kdb_plugin! — kdb_vftabl is a C struct of
    // function pointers produced by make_vftabl, placed in the .data section
    // with the fixed symbol name that libkdb5 dlsym's for.
    quote! {
        #[no_mangle]
        pub static kdb_function_table: #kr::sys::kdb_vftabl =
            #kr::glue::make_vftabl::<#name>();
    }
}

// ---------------------------------------------------------------------------
// #[kdb_method] — rename fn foo → fn kdb_impl_foo
// ---------------------------------------------------------------------------

/// Rename a method so that `#[derive(KdbModule)]` can dispatch to it.
///
/// Apply this to an inherent method whose name matches a `KdbModule` method;
/// the attribute renames it to `kdb_impl_<original_name>` so the generated
/// trait impl can call it without ambiguity.
///
/// ```rust,ignore
/// impl MyKdb {
///     #[kdb_method]
///     fn open(ctx: &KdbContext<'_>, ..) -> Result<Self, KdbError> { .. }
///     // becomes: fn kdb_impl_open(..) { .. }
/// }
/// ```
#[proc_macro_attribute]
pub fn kdb_method(_attr: TokenStream, item: TokenStream) -> TokenStream {
    let mut func = parse_macro_input!(item as syn::ItemFn);
    let original = func.sig.ident.clone();
    func.sig.ident = format_ident!("kdb_impl_{}", original);
    quote! { #func }.into()
}

// ---------------------------------------------------------------------------
// #[kdb_impl] — marker attribute on inherent impl blocks
// ---------------------------------------------------------------------------

/// Mark an inherent `impl` block as containing KDB override methods.
///
/// This attribute is a pass-through — it makes the intent explicit in code
/// and suppresses `unused_attributes` warnings for `#[kdb_method]` inside
/// the block.  All actual renaming is done by `#[kdb_method]` on individual
/// functions.
#[proc_macro_attribute]
pub fn kdb_impl(_attr: TokenStream, item: TokenStream) -> TokenStream {
    item
}
