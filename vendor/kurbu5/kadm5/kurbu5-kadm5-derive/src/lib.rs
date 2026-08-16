//! Proc-macro derives for `kurbu5-kadm5-rs` KADM5 plugin interfaces.
//!
//! Do not depend on this crate directly; use `kurbu5-kadm5-rs` with the
//! `derive` feature instead.
//!
//! Each derive macro generates a complete `impl XModule for Struct` that
//! delegates every non-overridden method to a nominated field.  If the
//! `name` attribute is set, it also emits the C `<name>_initvt` export.
//!
//! # Attribute syntax
//!
//! Place `#[plugin(...)]` on the struct alongside `#[derive(XModule)]`:
//!
//! | Option | Description |
//! |--------|-------------|
//! | `delegate = field` | **Required.** Field to forward non-overridden methods to. |
//! | `name = "symbol"` | Emit `<symbol>_initvt` C export (absorbs `initvt_plugin!`). |
//! | `overrides(m1, m2)` | Methods the struct implements directly (not delegated). |
//! | `crate = path` | Crate root path; defaults to `::kurbu5_kadm5_rs`. |

// The shared infrastructure is compiled when at least one interface feature is
// active.  This avoids dead-code and unused-import warnings when no feature is
// selected.
#[cfg(any(feature = "kadm5_auth", feature = "kadm5_hook",))]
mod shared {
    use proc_macro2::TokenStream as TokenStream2;
    use quote::{format_ident, quote};
    use syn::{
        Data, DeriveInput, Error, Fields, Ident, Meta, Token, Type,
        punctuated::Punctuated,
    };

    // -----------------------------------------------------------------------
    // Shared attribute parsing
    // -----------------------------------------------------------------------

    #[derive(Default)]
    pub(crate) struct PluginArgs {
        /// Field to delegate non-overridden methods to.
        pub(crate) delegate: Option<Ident>,
        /// If set, emits a `<name>_initvt` C symbol.
        pub(crate) name: Option<String>,
        /// Methods the user overrides directly (not delegated).
        pub(crate) overrides: Vec<Ident>,
        /// Override for the crate root path; defaults to `::kurbu5_kadm5_rs`.
        pub(crate) krate: Option<syn::Path>,
    }

    pub(crate) fn parse_plugin_args(
        attr: &syn::Attribute,
    ) -> Result<PluginArgs, Error> {
        let mut args = PluginArgs::default();

        let nested = attr.parse_args_with(
            Punctuated::<Meta, Token![,]>::parse_terminated,
        )?;

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
                Meta::NameValue(nv) if nv.path.is_ident("name") => {
                    if let syn::Expr::Lit(el) = &nv.value {
                        if let syn::Lit::Str(ls) = &el.lit {
                            args.name = Some(ls.value());
                        } else {
                            return Err(Error::new_spanned(
                                &el.lit,
                                "name value must be a string literal",
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
                        "unknown #[plugin(...)] option",
                    ));
                },
            }
        }

        Ok(args)
    }

    pub(crate) fn find_plugin_attr(
        input: &DeriveInput,
    ) -> Result<&syn::Attribute, Error> {
        input
            .attrs
            .iter()
            .find(|a| a.path().is_ident("plugin"))
            .ok_or_else(|| {
                Error::new_spanned(
                    &input.ident,
                    "#[derive(XModule)] requires a #[plugin(delegate = field, ...)] attribute",
                )
            })
    }

    pub(crate) fn find_field_type<'a>(
        input: &'a DeriveInput,
        field_name: &Ident,
    ) -> Result<&'a Type, Error> {
        let fields = match &input.data {
            Data::Struct(ds) => &ds.fields,
            _ => {
                return Err(Error::new_spanned(
                    &input.ident,
                    "#[derive(XModule)] only applies to structs",
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
                "#[derive(XModule)] requires named fields",
            )),
        }
    }

    fn has_override(args: &PluginArgs, name: &str) -> bool {
        args.overrides.iter().any(|id| id == name)
    }

    /// Emit a delegation or override body for a trait method.
    pub(crate) fn method_body(
        args: &PluginArgs,
        method_name: &str,
        delegate_expr: impl FnOnce() -> TokenStream2,
        override_expr: impl FnOnce() -> TokenStream2,
    ) -> TokenStream2 {
        if has_override(args, method_name) {
            override_expr()
        } else {
            delegate_expr()
        }
    }

    /// Generate the `<name>_initvt` C export if `args.name` is set.
    pub(crate) fn generate_initvt(
        args: &PluginArgs,
        struct_name: &Ident,
        krate: &syn::Path,
        major_ver: i32,
        make_vtable_fn: &TokenStream2,
    ) -> TokenStream2 {
        match &args.name {
            None => quote! {},
            Some(symbol_name) => {
                let initvt_ident = format_ident!("{}_initvt", symbol_name);
                quote! {
                    // SAFETY: This function is called by kadmind immediately after
                    // dlopen().  The invariants are:
                    //   - ctx is non-null and valid for the duration of the call.
                    //   - vtable is non-null and points to a zeroed vtable struct.
                    //   - maj_ver and min_ver are supplied by the kadmind loader.
                    #[no_mangle]
                    pub unsafe extern "C" fn #initvt_ident(
                        _ctx: *mut #krate::sys::_krb5_context,
                        maj_ver: ::libc::c_int,
                        _min_ver: ::libc::c_int,
                        vtable: *mut #krate::sys::krb5_plugin_vtable_st,
                    ) -> #krate::sys::krb5_error_code {
                        if maj_ver != #major_ver {
                            return #krate::sys::KRB5_PLUGIN_VER_NOTSUPP;
                        }
                        // SAFETY: vtable is non-null and points to a caller-allocated
                        // struct.  We cast to the concrete vtable type and fill fields.
                        let vt = vtable as *mut _;
                        // SAFETY: vt is non-null (derived from vtable which is non-null).
                        *vt = #make_vtable_fn::<#struct_name>();
                        0
                    }
                }
            },
        }
    }
}

// Bring the shared items into scope for each feature-gated section below.
#[cfg(any(feature = "kadm5_auth", feature = "kadm5_hook",))]
use shared::{
    PluginArgs, find_field_type, find_plugin_attr, generate_initvt,
    method_body, parse_plugin_args,
};

// ---------------------------------------------------------------------------
// #[derive(Kadm5AuthModule)]
// ---------------------------------------------------------------------------

/// Derive `Kadm5AuthModule` for a struct that delegates to a backing field.
///
/// Generates a complete `impl Kadm5AuthModule for Struct` block that forwards
/// every non-overridden method to the nominated delegate field.  When `name`
/// is set, it also emits the `<name>_initvt` C export, replacing an explicit
/// `initvt_plugin!` call.
///
/// # Attributes
///
/// Place `#[plugin(delegate = field, ...)]` on the struct.  See the [crate
/// docs](crate) for all attribute options.
///
/// # Delegated items
///
/// All trait methods are delegated:
/// - Lifecycle: `init_module`, `fini_module`, `end_operation`,
///   `free_restrictions`
/// - Check methods: `check_add_principal`, `check_modify_principal`,
///   `check_set_string`, `check_change_password`, `check_randomize_keys`,
///   `check_set_key`, `check_purge_keys`, `check_delete_principal`,
///   `check_rename_principal`, `check_get_principal`, `check_get_strings`,
///   `check_extract_keys`, `check_list_principals`, `check_add_policy`,
///   `check_modify_policy`, `check_delete_policy`, `check_get_policy`,
///   `check_list_policies`, `check_iprop`, `check_add_alias`
///
/// `NAME` is delegated from the backing type via
/// `<DelegateType as Kadm5AuthModule>::NAME`.
///
/// # Example
///
/// ```rust,ignore
/// use kurbu5_kadm5_rs::auth::Kadm5AuthModule;
/// use kurbu5_kadm5_rs::{Krb5Error, PluginContext};
///
/// struct Inner;
///
/// impl Kadm5AuthModule for Inner {
///     const NAME: &'static std::ffi::CStr = c"inner";
///     fn init_module(_ctx: &PluginContext<'_>, _acl: Option<&str>)
///         -> Result<Self, Krb5Error> { Ok(Inner) }
/// }
///
/// #[derive(Kadm5AuthModule)]
/// #[plugin(delegate = inner, name = "my_auth")]
/// struct Wrapper { inner: Inner }
/// // Exports C symbol: my_auth_initvt
/// // All Kadm5AuthModule methods delegate to self.inner.
/// ```
///
/// # Compile errors
///
/// Missing `#[plugin(...)]` attribute — the derive requires it:
///
/// ```compile_fail
/// use kurbu5_kadm5_rs::auth::Kadm5AuthModule;
/// use kurbu5_kadm5_rs::{Krb5Error, PluginContext};
/// struct Inner;
/// impl Kadm5AuthModule for Inner {
///     const NAME: &'static std::ffi::CStr = c"inner";
///     fn init_module(_ctx: &PluginContext<'_>, _acl: Option<&str>) -> Result<Self, Krb5Error> {
///         Ok(Inner)
///     }
/// }
/// #[derive(kurbu5_kadm5_rs::Kadm5AuthModule)]
/// struct Wrapper { inner: Inner }
/// ```
///
/// Delegate field name does not exist on the struct:
///
/// ```compile_fail
/// use kurbu5_kadm5_rs::auth::Kadm5AuthModule;
/// use kurbu5_kadm5_rs::{Krb5Error, PluginContext};
/// struct Inner;
/// impl Kadm5AuthModule for Inner {
///     const NAME: &'static std::ffi::CStr = c"inner";
///     fn init_module(_ctx: &PluginContext<'_>, _acl: Option<&str>) -> Result<Self, Krb5Error> {
///         Ok(Inner)
///     }
/// }
/// #[derive(kurbu5_kadm5_rs::Kadm5AuthModule)]
/// #[plugin(delegate = no_such_field)]
/// struct Wrapper { inner: Inner }
/// ```
///
/// Unknown key in `#[plugin(...)]`:
///
/// ```compile_fail
/// use kurbu5_kadm5_rs::auth::Kadm5AuthModule;
/// use kurbu5_kadm5_rs::{Krb5Error, PluginContext};
/// struct Inner;
/// impl Kadm5AuthModule for Inner {
///     const NAME: &'static std::ffi::CStr = c"inner";
///     fn init_module(_ctx: &PluginContext<'_>, _acl: Option<&str>) -> Result<Self, Krb5Error> {
///         Ok(Inner)
///     }
/// }
/// #[derive(kurbu5_kadm5_rs::Kadm5AuthModule)]
/// #[plugin(delegate = inner, bogus_key = "oops")]
/// struct Wrapper { inner: Inner }
/// ```
#[cfg(feature = "kadm5_auth")]
#[proc_macro_derive(Kadm5AuthModule, attributes(plugin))]
pub fn derive_kadm5_auth_module(
    input: proc_macro::TokenStream,
) -> proc_macro::TokenStream {
    use syn::parse_macro_input;
    let input = parse_macro_input!(input as syn::DeriveInput);
    derive_kadm5_auth_impl(&input)
        .unwrap_or_else(|e| e.to_compile_error())
        .into()
}

#[cfg(feature = "kadm5_auth")]
fn derive_kadm5_auth_impl(
    input: &syn::DeriveInput,
) -> Result<proc_macro2::TokenStream, syn::Error> {
    use quote::quote;
    let attr = find_plugin_attr(input)?;
    let args = parse_plugin_args(attr)?;
    let krate: syn::Path = args.krate.clone().unwrap_or_else(|| {
        syn::parse_str("::kurbu5_kadm5_rs").expect("valid path")
    });

    let delegate_name = args.delegate.as_ref().ok_or_else(|| {
        syn::Error::new_spanned(
            attr,
            "#[plugin(...)] requires `delegate = field_name`",
        )
    })?;
    let delegate_ty = find_field_type(input, delegate_name)?;
    let struct_name = &input.ident;
    let f = delegate_name;
    let dt = delegate_ty;

    let lifecycle = gen_auth_lifecycle(f, dt, &args, &krate);
    let add_modify = gen_auth_add_modify_checks(f, dt, &args, &krate);
    let key_checks = gen_auth_password_checks(f, dt, &args, &krate);
    let set_purge = gen_auth_set_purge_checks(f, dt, &args, &krate);
    let delete_get = gen_auth_delete_rename_checks(f, dt, &args, &krate);
    let get_list = gen_auth_get_checks(f, dt, &args, &krate);
    let extract_list = gen_auth_extract_list_checks(f, dt, &args, &krate);
    let policy_iprop = gen_auth_policy_write_checks(f, dt, &args, &krate);
    let policy_read = gen_auth_policy_read_checks(f, dt, &args, &krate);
    let iprop_alias = gen_auth_iprop_alias_checks(f, dt, &args, &krate);
    let initvt = generate_initvt(
        &args,
        struct_name,
        &krate,
        1i32,
        &quote! { #krate::auth::glue::make_kadm5_auth_vtable },
    );
    Ok(quote! {
        impl #krate::auth::Kadm5AuthModule for #struct_name {
            const NAME: &'static ::std::ffi::CStr =
                <#dt as #krate::auth::Kadm5AuthModule>::NAME;
            #lifecycle
            #add_modify
            #key_checks
            #set_purge
            #delete_get
            #get_list
            #extract_list
            #policy_iprop
            #policy_read
            #iprop_alias
        }
        #initvt
    })
}

/// Generate lifecycle methods for `Kadm5AuthModule`:
/// `init_module`, `fini_module`, `end_operation`, `free_restrictions`.
#[cfg(feature = "kadm5_auth")]
fn gen_auth_lifecycle(
    f: &syn::Ident,
    dt: &syn::Type,
    args: &PluginArgs,
    kr: &syn::Path,
) -> proc_macro2::TokenStream {
    use quote::quote;
    let init_module = method_body(
        args,
        "init_module",
        || {
            quote! {
                fn init_module(
                    ctx: &#kr::PluginContext<'_>,
                    acl_file: ::std::option::Option<&str>,
                ) -> ::std::result::Result<Self, #kr::Krb5Error> {
                    <#dt as #kr::auth::Kadm5AuthModule>::init_module(ctx, acl_file)
                        .map(|inner| Self { #f: inner })
                }
            }
        },
        || {
            quote! {
                fn init_module(
                    ctx: &#kr::PluginContext<'_>,
                    acl_file: ::std::option::Option<&str>,
                ) -> ::std::result::Result<Self, #kr::Krb5Error> {
                    Self::plugin_impl_init_module(ctx, acl_file)
                }
            }
        },
    );
    let fini_module = method_body(
        args,
        "fini_module",
        || {
            quote! {
                fn fini_module(self, ctx: &#kr::PluginContext<'_>) {
                    <#dt as #kr::auth::Kadm5AuthModule>::fini_module(self.#f, ctx)
                }
            }
        },
        || {
            quote! {
                fn fini_module(self, ctx: &#kr::PluginContext<'_>) {
                    self.plugin_impl_fini_module(ctx)
                }
            }
        },
    );
    let end_operation = method_body(
        args,
        "end_operation",
        || {
            quote! {
                fn end_operation(&self, ctx: &#kr::PluginContext<'_>) {
                    <#dt as #kr::auth::Kadm5AuthModule>::end_operation(&self.#f, ctx)
                }
            }
        },
        || {
            quote! {
                fn end_operation(&self, ctx: &#kr::PluginContext<'_>) {
                    self.plugin_impl_end_operation(ctx)
                }
            }
        },
    );
    let free_restrictions = method_body(
        args,
        "free_restrictions",
        || {
            quote! {
                fn free_restrictions(
                    &self,
                    ctx: &#kr::PluginContext<'_>,
                    rs: #kr::sys::kadm5_auth_restrictions,
                ) {
                    <#dt as #kr::auth::Kadm5AuthModule>::free_restrictions(&self.#f, ctx, rs)
                }
            }
        },
        || {
            quote! {
                fn free_restrictions(
                    &self,
                    ctx: &#kr::PluginContext<'_>,
                    rs: #kr::sys::kadm5_auth_restrictions,
                ) {
                    self.plugin_impl_free_restrictions(ctx, rs)
                }
            }
        },
    );
    quote! { #init_module #fini_module #end_operation #free_restrictions }
}

/// Generate add/modify/set-string principal check methods for `Kadm5AuthModule`:
/// `check_add_principal`, `check_modify_principal`, `check_set_string`.
#[cfg(feature = "kadm5_auth")]
fn gen_auth_add_modify_checks(
    f: &syn::Ident,
    dt: &syn::Type,
    args: &PluginArgs,
    kr: &syn::Path,
) -> proc_macro2::TokenStream {
    use quote::quote;
    let check_add_principal = method_body(
        args,
        "check_add_principal",
        || {
            quote! {
                fn check_add_principal<'a>(
                    &self,
                    ctx: &#kr::PluginContext<'_>,
                    req: &#kr::auth::AddPrincRequest<'a>,
                ) -> ::std::result::Result<
                    ::std::option::Option<#kr::sys::kadm5_auth_restrictions>,
                    #kr::Krb5Error,
                > {
                    <#dt as #kr::auth::Kadm5AuthModule>::check_add_principal(&self.#f, ctx, req)
                }
            }
        },
        || {
            quote! {
                fn check_add_principal<'a>(
                    &self,
                    ctx: &#kr::PluginContext<'_>,
                    req: &#kr::auth::AddPrincRequest<'a>,
                ) -> ::std::result::Result<
                    ::std::option::Option<#kr::sys::kadm5_auth_restrictions>,
                    #kr::Krb5Error,
                > {
                    self.plugin_impl_check_add_principal(ctx, req)
                }
            }
        },
    );
    let check_modify_principal = method_body(
        args,
        "check_modify_principal",
        || {
            quote! {
                fn check_modify_principal<'a>(
                    &self,
                    ctx: &#kr::PluginContext<'_>,
                    req: &#kr::auth::ModPrincRequest<'a>,
                ) -> ::std::result::Result<
                    ::std::option::Option<#kr::sys::kadm5_auth_restrictions>,
                    #kr::Krb5Error,
                > {
                    <#dt as #kr::auth::Kadm5AuthModule>::check_modify_principal(&self.#f, ctx, req)
                }
            }
        },
        || {
            quote! {
                fn check_modify_principal<'a>(
                    &self,
                    ctx: &#kr::PluginContext<'_>,
                    req: &#kr::auth::ModPrincRequest<'a>,
                ) -> ::std::result::Result<
                    ::std::option::Option<#kr::sys::kadm5_auth_restrictions>,
                    #kr::Krb5Error,
                > {
                    self.plugin_impl_check_modify_principal(ctx, req)
                }
            }
        },
    );
    let check_set_string = method_body(
        args,
        "check_set_string",
        || {
            quote! {
                fn check_set_string(
                    &self,
                    ctx: &#kr::PluginContext<'_>,
                    client: &#kr::sys::krb5_principal_data,
                    target: &#kr::sys::krb5_principal_data,
                    key: &str,
                    value: ::std::option::Option<&str>,
                ) -> ::std::result::Result<(), #kr::Krb5Error> {
                    <#dt as #kr::auth::Kadm5AuthModule>::check_set_string(
                        &self.#f, ctx, client, target, key, value,
                    )
                }
            }
        },
        || {
            quote! {
                fn check_set_string(
                    &self,
                    ctx: &#kr::PluginContext<'_>,
                    client: &#kr::sys::krb5_principal_data,
                    target: &#kr::sys::krb5_principal_data,
                    key: &str,
                    value: ::std::option::Option<&str>,
                ) -> ::std::result::Result<(), #kr::Krb5Error> {
                    self.plugin_impl_check_set_string(ctx, client, target, key, value)
                }
            }
        },
    );
    quote! { #check_add_principal #check_modify_principal #check_set_string }
}

/// Generate password and randomize-key check methods for `Kadm5AuthModule`:
/// `check_change_password`, `check_randomize_keys`.
#[cfg(feature = "kadm5_auth")]
fn gen_auth_password_checks(
    f: &syn::Ident,
    dt: &syn::Type,
    args: &PluginArgs,
    kr: &syn::Path,
) -> proc_macro2::TokenStream {
    use quote::quote;
    let check_change_password = method_body(
        args,
        "check_change_password",
        || {
            quote! {
                fn check_change_password(
                    &self,
                    ctx: &#kr::PluginContext<'_>,
                    client: &#kr::sys::krb5_principal_data,
                    target: &#kr::sys::krb5_principal_data,
                ) -> ::std::result::Result<(), #kr::Krb5Error> {
                    <#dt as #kr::auth::Kadm5AuthModule>::check_change_password(
                        &self.#f, ctx, client, target,
                    )
                }
            }
        },
        || {
            quote! {
                fn check_change_password(
                    &self,
                    ctx: &#kr::PluginContext<'_>,
                    client: &#kr::sys::krb5_principal_data,
                    target: &#kr::sys::krb5_principal_data,
                ) -> ::std::result::Result<(), #kr::Krb5Error> {
                    self.plugin_impl_check_change_password(ctx, client, target)
                }
            }
        },
    );
    let check_randomize_keys = method_body(
        args,
        "check_randomize_keys",
        || {
            quote! {
                fn check_randomize_keys(
                    &self,
                    ctx: &#kr::PluginContext<'_>,
                    client: &#kr::sys::krb5_principal_data,
                    target: &#kr::sys::krb5_principal_data,
                ) -> ::std::result::Result<(), #kr::Krb5Error> {
                    <#dt as #kr::auth::Kadm5AuthModule>::check_randomize_keys(
                        &self.#f, ctx, client, target,
                    )
                }
            }
        },
        || {
            quote! {
                fn check_randomize_keys(
                    &self,
                    ctx: &#kr::PluginContext<'_>,
                    client: &#kr::sys::krb5_principal_data,
                    target: &#kr::sys::krb5_principal_data,
                ) -> ::std::result::Result<(), #kr::Krb5Error> {
                    self.plugin_impl_check_randomize_keys(ctx, client, target)
                }
            }
        },
    );
    quote! { #check_change_password #check_randomize_keys }
}

/// Generate set-key and purge-key check methods for `Kadm5AuthModule`:
/// `check_set_key`, `check_purge_keys`.
#[cfg(feature = "kadm5_auth")]
fn gen_auth_set_purge_checks(
    f: &syn::Ident,
    dt: &syn::Type,
    args: &PluginArgs,
    kr: &syn::Path,
) -> proc_macro2::TokenStream {
    use quote::quote;
    let check_set_key = method_body(
        args,
        "check_set_key",
        || {
            quote! {
                fn check_set_key(
                    &self,
                    ctx: &#kr::PluginContext<'_>,
                    client: &#kr::sys::krb5_principal_data,
                    target: &#kr::sys::krb5_principal_data,
                ) -> ::std::result::Result<(), #kr::Krb5Error> {
                    <#dt as #kr::auth::Kadm5AuthModule>::check_set_key(
                        &self.#f, ctx, client, target,
                    )
                }
            }
        },
        || {
            quote! {
                fn check_set_key(
                    &self,
                    ctx: &#kr::PluginContext<'_>,
                    client: &#kr::sys::krb5_principal_data,
                    target: &#kr::sys::krb5_principal_data,
                ) -> ::std::result::Result<(), #kr::Krb5Error> {
                    self.plugin_impl_check_set_key(ctx, client, target)
                }
            }
        },
    );
    let check_purge_keys = method_body(
        args,
        "check_purge_keys",
        || {
            quote! {
                fn check_purge_keys(
                    &self,
                    ctx: &#kr::PluginContext<'_>,
                    client: &#kr::sys::krb5_principal_data,
                    target: &#kr::sys::krb5_principal_data,
                ) -> ::std::result::Result<(), #kr::Krb5Error> {
                    <#dt as #kr::auth::Kadm5AuthModule>::check_purge_keys(
                        &self.#f, ctx, client, target,
                    )
                }
            }
        },
        || {
            quote! {
                fn check_purge_keys(
                    &self,
                    ctx: &#kr::PluginContext<'_>,
                    client: &#kr::sys::krb5_principal_data,
                    target: &#kr::sys::krb5_principal_data,
                ) -> ::std::result::Result<(), #kr::Krb5Error> {
                    self.plugin_impl_check_purge_keys(ctx, client, target)
                }
            }
        },
    );
    quote! { #check_set_key #check_purge_keys }
}

/// Generate delete and rename principal check methods for `Kadm5AuthModule`:
/// `check_delete_principal`, `check_rename_principal`.
#[cfg(feature = "kadm5_auth")]
fn gen_auth_delete_rename_checks(
    f: &syn::Ident,
    dt: &syn::Type,
    args: &PluginArgs,
    kr: &syn::Path,
) -> proc_macro2::TokenStream {
    use quote::quote;
    let check_delete_principal = method_body(
        args,
        "check_delete_principal",
        || {
            quote! {
                fn check_delete_principal(
                    &self,
                    ctx: &#kr::PluginContext<'_>,
                    client: &#kr::sys::krb5_principal_data,
                    target: &#kr::sys::krb5_principal_data,
                ) -> ::std::result::Result<(), #kr::Krb5Error> {
                    <#dt as #kr::auth::Kadm5AuthModule>::check_delete_principal(
                        &self.#f, ctx, client, target,
                    )
                }
            }
        },
        || {
            quote! {
                fn check_delete_principal(
                    &self,
                    ctx: &#kr::PluginContext<'_>,
                    client: &#kr::sys::krb5_principal_data,
                    target: &#kr::sys::krb5_principal_data,
                ) -> ::std::result::Result<(), #kr::Krb5Error> {
                    self.plugin_impl_check_delete_principal(ctx, client, target)
                }
            }
        },
    );
    let check_rename_principal = method_body(
        args,
        "check_rename_principal",
        || {
            quote! {
                fn check_rename_principal(
                    &self,
                    ctx: &#kr::PluginContext<'_>,
                    client: &#kr::sys::krb5_principal_data,
                    src: &#kr::sys::krb5_principal_data,
                    dest: &#kr::sys::krb5_principal_data,
                ) -> ::std::result::Result<(), #kr::Krb5Error> {
                    <#dt as #kr::auth::Kadm5AuthModule>::check_rename_principal(
                        &self.#f, ctx, client, src, dest,
                    )
                }
            }
        },
        || {
            quote! {
                fn check_rename_principal(
                    &self,
                    ctx: &#kr::PluginContext<'_>,
                    client: &#kr::sys::krb5_principal_data,
                    src: &#kr::sys::krb5_principal_data,
                    dest: &#kr::sys::krb5_principal_data,
                ) -> ::std::result::Result<(), #kr::Krb5Error> {
                    self.plugin_impl_check_rename_principal(ctx, client, src, dest)
                }
            }
        },
    );
    quote! { #check_delete_principal #check_rename_principal }
}

/// Generate get and list principal check methods for `Kadm5AuthModule`:
/// `check_get_principal`, `check_get_strings`.
#[cfg(feature = "kadm5_auth")]
fn gen_auth_get_checks(
    f: &syn::Ident,
    dt: &syn::Type,
    args: &PluginArgs,
    kr: &syn::Path,
) -> proc_macro2::TokenStream {
    use quote::quote;
    let check_get_principal = method_body(
        args,
        "check_get_principal",
        || {
            quote! {
                fn check_get_principal(
                    &self,
                    ctx: &#kr::PluginContext<'_>,
                    client: &#kr::sys::krb5_principal_data,
                    target: &#kr::sys::krb5_principal_data,
                ) -> ::std::result::Result<(), #kr::Krb5Error> {
                    <#dt as #kr::auth::Kadm5AuthModule>::check_get_principal(
                        &self.#f, ctx, client, target,
                    )
                }
            }
        },
        || {
            quote! {
                fn check_get_principal(
                    &self,
                    ctx: &#kr::PluginContext<'_>,
                    client: &#kr::sys::krb5_principal_data,
                    target: &#kr::sys::krb5_principal_data,
                ) -> ::std::result::Result<(), #kr::Krb5Error> {
                    self.plugin_impl_check_get_principal(ctx, client, target)
                }
            }
        },
    );
    let check_get_strings = method_body(
        args,
        "check_get_strings",
        || {
            quote! {
                fn check_get_strings(
                    &self,
                    ctx: &#kr::PluginContext<'_>,
                    client: &#kr::sys::krb5_principal_data,
                    target: &#kr::sys::krb5_principal_data,
                ) -> ::std::result::Result<(), #kr::Krb5Error> {
                    <#dt as #kr::auth::Kadm5AuthModule>::check_get_strings(
                        &self.#f, ctx, client, target,
                    )
                }
            }
        },
        || {
            quote! {
                fn check_get_strings(
                    &self,
                    ctx: &#kr::PluginContext<'_>,
                    client: &#kr::sys::krb5_principal_data,
                    target: &#kr::sys::krb5_principal_data,
                ) -> ::std::result::Result<(), #kr::Krb5Error> {
                    self.plugin_impl_check_get_strings(ctx, client, target)
                }
            }
        },
    );
    quote! { #check_get_principal #check_get_strings }
}

/// `check_extract_keys`, `check_list_principals`.
#[cfg(feature = "kadm5_auth")]
fn gen_auth_extract_list_checks(
    f: &syn::Ident,
    dt: &syn::Type,
    args: &PluginArgs,
    kr: &syn::Path,
) -> proc_macro2::TokenStream {
    use quote::quote;
    let check_extract_keys = method_body(
        args,
        "check_extract_keys",
        || {
            quote! {
                fn check_extract_keys(
                    &self,
                    ctx: &#kr::PluginContext<'_>,
                    client: &#kr::sys::krb5_principal_data,
                    target: &#kr::sys::krb5_principal_data,
                ) -> ::std::result::Result<(), #kr::Krb5Error> {
                    <#dt as #kr::auth::Kadm5AuthModule>::check_extract_keys(
                        &self.#f, ctx, client, target,
                    )
                }
            }
        },
        || {
            quote! {
                fn check_extract_keys(
                    &self,
                    ctx: &#kr::PluginContext<'_>,
                    client: &#kr::sys::krb5_principal_data,
                    target: &#kr::sys::krb5_principal_data,
                ) -> ::std::result::Result<(), #kr::Krb5Error> {
                    self.plugin_impl_check_extract_keys(ctx, client, target)
                }
            }
        },
    );
    let check_list_principals = method_body(
        args,
        "check_list_principals",
        || {
            quote! {
                fn check_list_principals(
                    &self,
                    ctx: &#kr::PluginContext<'_>,
                    client: &#kr::sys::krb5_principal_data,
                ) -> ::std::result::Result<(), #kr::Krb5Error> {
                    <#dt as #kr::auth::Kadm5AuthModule>::check_list_principals(
                        &self.#f, ctx, client,
                    )
                }
            }
        },
        || {
            quote! {
                fn check_list_principals(
                    &self,
                    ctx: &#kr::PluginContext<'_>,
                    client: &#kr::sys::krb5_principal_data,
                ) -> ::std::result::Result<(), #kr::Krb5Error> {
                    self.plugin_impl_check_list_principals(ctx, client)
                }
            }
        },
    );
    quote! { #check_extract_keys #check_list_principals }
}

/// Generate write policy check methods for `Kadm5AuthModule`:
/// `check_add_policy`, `check_modify_policy`, `check_delete_policy`.
#[cfg(feature = "kadm5_auth")]
fn gen_auth_policy_write_checks(
    f: &syn::Ident,
    dt: &syn::Type,
    args: &PluginArgs,
    kr: &syn::Path,
) -> proc_macro2::TokenStream {
    use quote::quote;
    let check_add_policy = method_body(
        args,
        "check_add_policy",
        || {
            quote! {
                fn check_add_policy(
                    &self,
                    ctx: &#kr::PluginContext<'_>,
                    client: &#kr::sys::krb5_principal_data,
                    policy: &str,
                ) -> ::std::result::Result<(), #kr::Krb5Error> {
                    <#dt as #kr::auth::Kadm5AuthModule>::check_add_policy(
                        &self.#f, ctx, client, policy,
                    )
                }
            }
        },
        || {
            quote! {
                fn check_add_policy(
                    &self,
                    ctx: &#kr::PluginContext<'_>,
                    client: &#kr::sys::krb5_principal_data,
                    policy: &str,
                ) -> ::std::result::Result<(), #kr::Krb5Error> {
                    self.plugin_impl_check_add_policy(ctx, client, policy)
                }
            }
        },
    );
    let check_modify_policy = method_body(
        args,
        "check_modify_policy",
        || {
            quote! {
                fn check_modify_policy(
                    &self,
                    ctx: &#kr::PluginContext<'_>,
                    client: &#kr::sys::krb5_principal_data,
                    policy: &str,
                ) -> ::std::result::Result<(), #kr::Krb5Error> {
                    <#dt as #kr::auth::Kadm5AuthModule>::check_modify_policy(
                        &self.#f, ctx, client, policy,
                    )
                }
            }
        },
        || {
            quote! {
                fn check_modify_policy(
                    &self,
                    ctx: &#kr::PluginContext<'_>,
                    client: &#kr::sys::krb5_principal_data,
                    policy: &str,
                ) -> ::std::result::Result<(), #kr::Krb5Error> {
                    self.plugin_impl_check_modify_policy(ctx, client, policy)
                }
            }
        },
    );
    let check_delete_policy = method_body(
        args,
        "check_delete_policy",
        || {
            quote! {
                fn check_delete_policy(
                    &self,
                    ctx: &#kr::PluginContext<'_>,
                    client: &#kr::sys::krb5_principal_data,
                    policy: &str,
                ) -> ::std::result::Result<(), #kr::Krb5Error> {
                    <#dt as #kr::auth::Kadm5AuthModule>::check_delete_policy(
                        &self.#f, ctx, client, policy,
                    )
                }
            }
        },
        || {
            quote! {
                fn check_delete_policy(
                    &self,
                    ctx: &#kr::PluginContext<'_>,
                    client: &#kr::sys::krb5_principal_data,
                    policy: &str,
                ) -> ::std::result::Result<(), #kr::Krb5Error> {
                    self.plugin_impl_check_delete_policy(ctx, client, policy)
                }
            }
        },
    );
    quote! { #check_add_policy #check_modify_policy #check_delete_policy }
}

/// Generate read policy check methods for `Kadm5AuthModule`:
/// `check_get_policy`, `check_list_policies`.
#[cfg(feature = "kadm5_auth")]
fn gen_auth_policy_read_checks(
    f: &syn::Ident,
    dt: &syn::Type,
    args: &PluginArgs,
    kr: &syn::Path,
) -> proc_macro2::TokenStream {
    use quote::quote;
    let check_get_policy = method_body(
        args,
        "check_get_policy",
        || {
            quote! {
                fn check_get_policy(
                    &self,
                    ctx: &#kr::PluginContext<'_>,
                    client: &#kr::sys::krb5_principal_data,
                    policy: &str,
                    client_policy: ::std::option::Option<&str>,
                ) -> ::std::result::Result<(), #kr::Krb5Error> {
                    <#dt as #kr::auth::Kadm5AuthModule>::check_get_policy(
                        &self.#f, ctx, client, policy, client_policy,
                    )
                }
            }
        },
        || {
            quote! {
                fn check_get_policy(
                    &self,
                    ctx: &#kr::PluginContext<'_>,
                    client: &#kr::sys::krb5_principal_data,
                    policy: &str,
                    client_policy: ::std::option::Option<&str>,
                ) -> ::std::result::Result<(), #kr::Krb5Error> {
                    self.plugin_impl_check_get_policy(ctx, client, policy, client_policy)
                }
            }
        },
    );
    let check_list_policies = method_body(
        args,
        "check_list_policies",
        || {
            quote! {
                fn check_list_policies(
                    &self,
                    ctx: &#kr::PluginContext<'_>,
                    client: &#kr::sys::krb5_principal_data,
                ) -> ::std::result::Result<(), #kr::Krb5Error> {
                    <#dt as #kr::auth::Kadm5AuthModule>::check_list_policies(
                        &self.#f, ctx, client,
                    )
                }
            }
        },
        || {
            quote! {
                fn check_list_policies(
                    &self,
                    ctx: &#kr::PluginContext<'_>,
                    client: &#kr::sys::krb5_principal_data,
                ) -> ::std::result::Result<(), #kr::Krb5Error> {
                    self.plugin_impl_check_list_policies(ctx, client)
                }
            }
        },
    );
    quote! { #check_get_policy #check_list_policies }
}

/// Generate iprop and alias check methods for `Kadm5AuthModule`:
/// `check_iprop`, `check_add_alias`.
#[cfg(feature = "kadm5_auth")]
fn gen_auth_iprop_alias_checks(
    f: &syn::Ident,
    dt: &syn::Type,
    args: &PluginArgs,
    kr: &syn::Path,
) -> proc_macro2::TokenStream {
    use quote::quote;
    let check_iprop = method_body(
        args,
        "check_iprop",
        || {
            quote! {
                fn check_iprop(
                    &self,
                    ctx: &#kr::PluginContext<'_>,
                    client: &#kr::sys::krb5_principal_data,
                ) -> ::std::result::Result<(), #kr::Krb5Error> {
                    <#dt as #kr::auth::Kadm5AuthModule>::check_iprop(&self.#f, ctx, client)
                }
            }
        },
        || {
            quote! {
                fn check_iprop(
                    &self,
                    ctx: &#kr::PluginContext<'_>,
                    client: &#kr::sys::krb5_principal_data,
                ) -> ::std::result::Result<(), #kr::Krb5Error> {
                    self.plugin_impl_check_iprop(ctx, client)
                }
            }
        },
    );
    let check_add_alias = method_body(
        args,
        "check_add_alias",
        || {
            quote! {
                fn check_add_alias(
                    &self,
                    ctx: &#kr::PluginContext<'_>,
                    client: &#kr::sys::krb5_principal_data,
                    alias_princ: &#kr::sys::krb5_principal_data,
                    target_princ: &#kr::sys::krb5_principal_data,
                ) -> ::std::result::Result<(), #kr::Krb5Error> {
                    <#dt as #kr::auth::Kadm5AuthModule>::check_add_alias(
                        &self.#f, ctx, client, alias_princ, target_princ,
                    )
                }
            }
        },
        || {
            quote! {
                fn check_add_alias(
                    &self,
                    ctx: &#kr::PluginContext<'_>,
                    client: &#kr::sys::krb5_principal_data,
                    alias_princ: &#kr::sys::krb5_principal_data,
                    target_princ: &#kr::sys::krb5_principal_data,
                ) -> ::std::result::Result<(), #kr::Krb5Error> {
                    self.plugin_impl_check_add_alias(ctx, client, alias_princ, target_princ)
                }
            }
        },
    );
    quote! { #check_iprop #check_add_alias }
}

// ---------------------------------------------------------------------------
// #[derive(Kadm5HookModule)]
// ---------------------------------------------------------------------------

/// Derive `Kadm5HookModule` for a struct that delegates to a backing field.
///
/// Generates a complete `impl Kadm5HookModule for Struct` block that forwards
/// every non-overridden method to the nominated delegate field.  When `name`
/// is set, it also emits the `<name>_initvt` C export.
///
/// # Attributes
///
/// Place `#[plugin(delegate = field, ...)]` on the struct.  See the [crate
/// docs](crate) for all attribute options.
///
/// # Delegated items
///
/// All trait methods are delegated:
/// - Lifecycle: `init_module`, `fini_module`
/// - Hook methods: `chpass`, `create`, `modify`, `remove`, `rename`, `alias`
///
/// `NAME` is delegated from the backing type via
/// `<DelegateType as Kadm5HookModule>::NAME`.
///
/// # Example
///
/// ```rust,ignore
/// use kurbu5_kadm5_rs::hook::Kadm5HookModule;
/// use kurbu5_kadm5_rs::{Krb5Error, PluginContext};
///
/// struct Inner;
///
/// impl Kadm5HookModule for Inner {
///     const NAME: &'static std::ffi::CStr = c"inner";
///     fn init_module(_ctx: &PluginContext<'_>)
///         -> Result<Self, Krb5Error> { Ok(Inner) }
/// }
///
/// #[derive(Kadm5HookModule)]
/// #[plugin(delegate = inner, name = "my_hook")]
/// struct Wrapper { inner: Inner }
/// // Exports C symbol: my_hook_initvt
/// // All Kadm5HookModule methods delegate to self.inner.
/// ```
///
/// # Compile errors
///
/// Missing `#[plugin(...)]` attribute — the derive requires it:
///
/// ```compile_fail
/// use kurbu5_kadm5_rs::hook::Kadm5HookModule;
/// use kurbu5_kadm5_rs::{Krb5Error, PluginContext};
/// struct Inner;
/// impl Kadm5HookModule for Inner {
///     const NAME: &'static std::ffi::CStr = c"inner";
///     fn init_module(_ctx: &PluginContext<'_>) -> Result<Self, Krb5Error> {
///         Ok(Inner)
///     }
/// }
/// #[derive(kurbu5_kadm5_rs::Kadm5HookModule)]
/// struct Wrapper { inner: Inner }
/// ```
///
/// Delegate field name does not exist on the struct:
///
/// ```compile_fail
/// use kurbu5_kadm5_rs::hook::Kadm5HookModule;
/// use kurbu5_kadm5_rs::{Krb5Error, PluginContext};
/// struct Inner;
/// impl Kadm5HookModule for Inner {
///     const NAME: &'static std::ffi::CStr = c"inner";
///     fn init_module(_ctx: &PluginContext<'_>) -> Result<Self, Krb5Error> {
///         Ok(Inner)
///     }
/// }
/// #[derive(kurbu5_kadm5_rs::Kadm5HookModule)]
/// #[plugin(delegate = no_such_field)]
/// struct Wrapper { inner: Inner }
/// ```
///
/// Unknown key in `#[plugin(...)]`:
///
/// ```compile_fail
/// use kurbu5_kadm5_rs::hook::Kadm5HookModule;
/// use kurbu5_kadm5_rs::{Krb5Error, PluginContext};
/// struct Inner;
/// impl Kadm5HookModule for Inner {
///     const NAME: &'static std::ffi::CStr = c"inner";
///     fn init_module(_ctx: &PluginContext<'_>) -> Result<Self, Krb5Error> {
///         Ok(Inner)
///     }
/// }
/// #[derive(kurbu5_kadm5_rs::Kadm5HookModule)]
/// #[plugin(delegate = inner, bogus_key = "oops")]
/// struct Wrapper { inner: Inner }
/// ```
#[cfg(feature = "kadm5_hook")]
#[proc_macro_derive(Kadm5HookModule, attributes(plugin))]
pub fn derive_kadm5_hook_module(
    input: proc_macro::TokenStream,
) -> proc_macro::TokenStream {
    use syn::parse_macro_input;
    let input = parse_macro_input!(input as syn::DeriveInput);
    derive_kadm5_hook_impl(&input)
        .unwrap_or_else(|e| e.to_compile_error())
        .into()
}

#[cfg(feature = "kadm5_hook")]
fn derive_kadm5_hook_impl(
    input: &syn::DeriveInput,
) -> Result<proc_macro2::TokenStream, syn::Error> {
    use quote::quote;
    let attr = find_plugin_attr(input)?;
    let args = parse_plugin_args(attr)?;
    let krate: syn::Path = args.krate.clone().unwrap_or_else(|| {
        syn::parse_str("::kurbu5_kadm5_rs").expect("valid path")
    });

    let delegate_name = args.delegate.as_ref().ok_or_else(|| {
        syn::Error::new_spanned(
            attr,
            "#[plugin(...)] requires `delegate = field_name`",
        )
    })?;
    let delegate_ty = find_field_type(input, delegate_name)?;
    let struct_name = &input.ident;
    let f = delegate_name;
    let dt = delegate_ty;

    let lifecycle = gen_hook_lifecycle(f, dt, &args, &krate);
    let operations = gen_hook_chpass_create_modify(f, dt, &args, &krate);
    let removals = gen_hook_remove_rename_alias(f, dt, &args, &krate);
    let initvt = generate_initvt(
        &args,
        struct_name,
        &krate,
        1i32,
        &quote! { #krate::hook::glue::make_kadm5_hook_vtable },
    );
    Ok(quote! {
        impl #krate::hook::Kadm5HookModule for #struct_name {
            const NAME: &'static ::std::ffi::CStr =
                <#dt as #krate::hook::Kadm5HookModule>::NAME;
            #lifecycle
            #operations
            #removals
        }
        #initvt
    })
}

/// Generate lifecycle methods for `Kadm5HookModule`:
/// `init_module`, `fini_module`.
#[cfg(feature = "kadm5_hook")]
fn gen_hook_lifecycle(
    f: &syn::Ident,
    dt: &syn::Type,
    args: &PluginArgs,
    kr: &syn::Path,
) -> proc_macro2::TokenStream {
    use quote::quote;
    let init_module = method_body(
        args,
        "init_module",
        || {
            quote! {
                fn init_module(
                    ctx: &#kr::PluginContext<'_>,
                ) -> ::std::result::Result<Self, #kr::Krb5Error> {
                    <#dt as #kr::hook::Kadm5HookModule>::init_module(ctx)
                        .map(|inner| Self { #f: inner })
                }
            }
        },
        || {
            quote! {
                fn init_module(
                    ctx: &#kr::PluginContext<'_>,
                ) -> ::std::result::Result<Self, #kr::Krb5Error> {
                    Self::plugin_impl_init_module(ctx)
                }
            }
        },
    );
    let fini_module = method_body(
        args,
        "fini_module",
        || {
            quote! {
                fn fini_module(self, ctx: &#kr::PluginContext<'_>) {
                    <#dt as #kr::hook::Kadm5HookModule>::fini_module(self.#f, ctx)
                }
            }
        },
        || {
            quote! {
                fn fini_module(self, ctx: &#kr::PluginContext<'_>) {
                    self.plugin_impl_fini_module(ctx)
                }
            }
        },
    );
    quote! { #init_module #fini_module }
}

/// Generate password-change and principal create/modify methods for `Kadm5HookModule`:
/// `chpass`, `create`, `modify`.
#[cfg(feature = "kadm5_hook")]
fn gen_hook_chpass_create_modify(
    f: &syn::Ident,
    dt: &syn::Type,
    args: &PluginArgs,
    kr: &syn::Path,
) -> proc_macro2::TokenStream {
    use quote::quote;
    let chpass = method_body(
        args,
        "chpass",
        || {
            quote! {
                fn chpass(
                    &self,
                    ctx: &#kr::PluginContext<'_>,
                    stage: #kr::hook::HookStage,
                    req: &#kr::hook::ChpassRequest<'_>,
                ) -> ::std::result::Result<(), #kr::Krb5Error> {
                    <#dt as #kr::hook::Kadm5HookModule>::chpass(&self.#f, ctx, stage, req)
                }
            }
        },
        || {
            quote! {
                fn chpass(
                    &self,
                    ctx: &#kr::PluginContext<'_>,
                    stage: #kr::hook::HookStage,
                    req: &#kr::hook::ChpassRequest<'_>,
                ) -> ::std::result::Result<(), #kr::Krb5Error> {
                    self.plugin_impl_chpass(ctx, stage, req)
                }
            }
        },
    );
    let create = method_body(
        args,
        "create",
        || {
            quote! {
                fn create(
                    &self,
                    ctx: &#kr::PluginContext<'_>,
                    stage: #kr::hook::HookStage,
                    req: &#kr::hook::CreatePrincRequest<'_>,
                ) -> ::std::result::Result<(), #kr::Krb5Error> {
                    <#dt as #kr::hook::Kadm5HookModule>::create(&self.#f, ctx, stage, req)
                }
            }
        },
        || {
            quote! {
                fn create(
                    &self,
                    ctx: &#kr::PluginContext<'_>,
                    stage: #kr::hook::HookStage,
                    req: &#kr::hook::CreatePrincRequest<'_>,
                ) -> ::std::result::Result<(), #kr::Krb5Error> {
                    self.plugin_impl_create(ctx, stage, req)
                }
            }
        },
    );
    let modify = method_body(
        args,
        "modify",
        || {
            quote! {
                fn modify(
                    &self,
                    ctx: &#kr::PluginContext<'_>,
                    stage: #kr::hook::HookStage,
                    req: &#kr::hook::ModifyPrincRequest<'_>,
                ) -> ::std::result::Result<(), #kr::Krb5Error> {
                    <#dt as #kr::hook::Kadm5HookModule>::modify(&self.#f, ctx, stage, req)
                }
            }
        },
        || {
            quote! {
                fn modify(
                    &self,
                    ctx: &#kr::PluginContext<'_>,
                    stage: #kr::hook::HookStage,
                    req: &#kr::hook::ModifyPrincRequest<'_>,
                ) -> ::std::result::Result<(), #kr::Krb5Error> {
                    self.plugin_impl_modify(ctx, stage, req)
                }
            }
        },
    );
    quote! { #chpass #create #modify }
}

/// Generate remove, rename, and alias hook methods for `Kadm5HookModule`:
/// `remove`, `rename`, `alias`.
#[cfg(feature = "kadm5_hook")]
fn gen_hook_remove_rename_alias(
    f: &syn::Ident,
    dt: &syn::Type,
    args: &PluginArgs,
    kr: &syn::Path,
) -> proc_macro2::TokenStream {
    use quote::quote;
    let remove = method_body(
        args,
        "remove",
        || {
            quote! {
                fn remove(
                    &self,
                    ctx: &#kr::PluginContext<'_>,
                    stage: #kr::hook::HookStage,
                    principal: &#kr::sys::krb5_principal_data,
                ) -> ::std::result::Result<(), #kr::Krb5Error> {
                    <#dt as #kr::hook::Kadm5HookModule>::remove(&self.#f, ctx, stage, principal)
                }
            }
        },
        || {
            quote! {
                fn remove(
                    &self,
                    ctx: &#kr::PluginContext<'_>,
                    stage: #kr::hook::HookStage,
                    principal: &#kr::sys::krb5_principal_data,
                ) -> ::std::result::Result<(), #kr::Krb5Error> {
                    self.plugin_impl_remove(ctx, stage, principal)
                }
            }
        },
    );
    let rename = method_body(
        args,
        "rename",
        || {
            quote! {
                fn rename(
                    &self,
                    ctx: &#kr::PluginContext<'_>,
                    stage: #kr::hook::HookStage,
                    src: &#kr::sys::krb5_principal_data,
                    dest: &#kr::sys::krb5_principal_data,
                ) -> ::std::result::Result<(), #kr::Krb5Error> {
                    <#dt as #kr::hook::Kadm5HookModule>::rename(&self.#f, ctx, stage, src, dest)
                }
            }
        },
        || {
            quote! {
                fn rename(
                    &self,
                    ctx: &#kr::PluginContext<'_>,
                    stage: #kr::hook::HookStage,
                    src: &#kr::sys::krb5_principal_data,
                    dest: &#kr::sys::krb5_principal_data,
                ) -> ::std::result::Result<(), #kr::Krb5Error> {
                    self.plugin_impl_rename(ctx, stage, src, dest)
                }
            }
        },
    );
    let alias = method_body(
        args,
        "alias",
        || {
            quote! {
                fn alias(
                    &self,
                    ctx: &#kr::PluginContext<'_>,
                    stage: #kr::hook::HookStage,
                    alias: &#kr::sys::krb5_principal_data,
                    target: &#kr::sys::krb5_principal_data,
                ) -> ::std::result::Result<(), #kr::Krb5Error> {
                    <#dt as #kr::hook::Kadm5HookModule>::alias(&self.#f, ctx, stage, alias, target)
                }
            }
        },
        || {
            quote! {
                fn alias(
                    &self,
                    ctx: &#kr::PluginContext<'_>,
                    stage: #kr::hook::HookStage,
                    alias: &#kr::sys::krb5_principal_data,
                    target: &#kr::sys::krb5_principal_data,
                ) -> ::std::result::Result<(), #kr::Krb5Error> {
                    self.plugin_impl_alias(ctx, stage, alias, target)
                }
            }
        },
    );
    quote! { #remove #rename #alias }
}
