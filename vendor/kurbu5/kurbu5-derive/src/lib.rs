//! Proc-macro derives for `kurbu5-rs` non-KDB plugin interfaces.
//!
//! Do not depend on this crate directly; use `kurbu5-rs` with the `derive`
//! feature instead.
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
//! | `crate = path` | Crate root path; defaults to `::kurbu5_rs`. |

// The shared infrastructure (attribute parsing, helper functions) is only
// compiled when at least one interface feature is active.  This avoids dead-code
// and unused-import warnings when the crate is built with no features.
#[cfg(any(
    feature = "pwqual",
    feature = "hostrealm",
    feature = "localauth",
    feature = "ccselect",
    feature = "kdcpreauth",
    feature = "clpreauth",
    feature = "kdcpolicy",
    feature = "certauth",
    feature = "audit",
))]
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
        /// Override for the crate root path; defaults to `::kurbu5_rs`.
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
                    // SAFETY: This function is called by libkrb5 immediately after
                    // dlopen().  The invariants are:
                    //   - ctx is non-null and valid for the duration of the call.
                    //   - vtable is non-null and points to a zeroed vtable struct.
                    //   - maj_ver and min_ver are supplied by the libkrb5 loader.
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
#[cfg(any(
    feature = "pwqual",
    feature = "hostrealm",
    feature = "localauth",
    feature = "ccselect",
    feature = "kdcpreauth",
    feature = "clpreauth",
    feature = "kdcpolicy",
    feature = "certauth",
    feature = "audit",
))]
use shared::{
    PluginArgs, find_field_type, find_plugin_attr, generate_initvt,
    method_body, parse_plugin_args,
};

// ---------------------------------------------------------------------------
// #[derive(PwqualModule)]
// ---------------------------------------------------------------------------

/// Derive `PwqualModule` for a struct that delegates to a backing field.
///
/// # Attributes
///
/// Place `#[plugin(delegate = field, ...)]` on the struct.  See the [crate
/// docs](crate) for all attribute options.
///
/// # Delegated items
///
/// All three trait methods — `open`, `check`, `close` — and the required
/// `const NAME` are delegated.  `NAME` is set to
/// `<DelegateType as PwqualModule>::NAME` so the wrapper inherits the
/// backing type's plugin name.  If a different name is needed for the outer
/// type, provide an explicit `impl PwqualModule for Outer { const NAME = ...; }`
/// — but that is incompatible with using `#[derive(PwqualModule)]`.
///
/// `open` is a static method that calls
/// `<DelegateType as PwqualModule>::open(ctx, dict_file)`.  `check` and
/// `close` are instance methods that delegate to the field.
///
/// # Compile errors
///
/// Missing `#[plugin(...)]` attribute — the derive requires it:
///
/// ```compile_fail
/// use kurbu5_rs::pwqual::{CheckRequest, PwqualError, PwqualModule};
/// use kurbu5_rs::PluginContext;
/// struct Inner;
/// impl PwqualModule for Inner {
///     const NAME: &'static std::ffi::CStr = c"inner";
///     fn open(_: &PluginContext<'_>, _: Option<&str>) -> Result<Self, PwqualError> { Ok(Inner) }
///     fn check(&self, _: &PluginContext<'_>, _: &CheckRequest<'_>) -> Result<(), PwqualError> { Ok(()) }
/// }
/// #[derive(kurbu5_rs::PwqualModule)]
/// struct Wrapper { inner: Inner }
/// ```
///
/// Delegate field name does not exist on the struct:
///
/// ```compile_fail
/// use kurbu5_rs::pwqual::{CheckRequest, PwqualError, PwqualModule};
/// use kurbu5_rs::PluginContext;
/// struct Inner;
/// impl PwqualModule for Inner {
///     const NAME: &'static std::ffi::CStr = c"inner";
///     fn open(_: &PluginContext<'_>, _: Option<&str>) -> Result<Self, PwqualError> { Ok(Inner) }
///     fn check(&self, _: &PluginContext<'_>, _: &CheckRequest<'_>) -> Result<(), PwqualError> { Ok(()) }
/// }
/// #[derive(kurbu5_rs::PwqualModule)]
/// #[plugin(delegate = no_such_field)]
/// struct Wrapper { inner: Inner }
/// ```
///
/// Unknown key in `#[plugin(...)]`:
///
/// ```compile_fail
/// use kurbu5_rs::pwqual::{CheckRequest, PwqualError, PwqualModule};
/// use kurbu5_rs::PluginContext;
/// struct Inner;
/// impl PwqualModule for Inner {
///     const NAME: &'static std::ffi::CStr = c"inner";
///     fn open(_: &PluginContext<'_>, _: Option<&str>) -> Result<Self, PwqualError> { Ok(Inner) }
///     fn check(&self, _: &PluginContext<'_>, _: &CheckRequest<'_>) -> Result<(), PwqualError> { Ok(()) }
/// }
/// #[derive(kurbu5_rs::PwqualModule)]
/// #[plugin(delegate = inner, bogus_key = "oops")]
/// struct Wrapper { inner: Inner }
/// ```
#[cfg(feature = "pwqual")]
#[proc_macro_derive(PwqualModule, attributes(plugin))]
pub fn derive_pwqual_module(
    input: proc_macro::TokenStream,
) -> proc_macro::TokenStream {
    use syn::parse_macro_input;
    let input = parse_macro_input!(input as syn::DeriveInput);
    derive_pwqual_impl(&input)
        .unwrap_or_else(|e| e.to_compile_error())
        .into()
}

#[cfg(feature = "pwqual")]
fn derive_pwqual_impl(
    input: &syn::DeriveInput,
) -> Result<proc_macro2::TokenStream, syn::Error> {
    use quote::quote;
    let attr = find_plugin_attr(input)?;
    let args = parse_plugin_args(attr)?;
    let krate: syn::Path = args
        .krate
        .clone()
        .unwrap_or_else(|| syn::parse_str("::kurbu5_rs").expect("valid path"));
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
    let methods = gen_pwqual_methods(f, dt, &args, &krate);
    let initvt = generate_initvt(
        &args,
        struct_name,
        &krate,
        1i32,
        &quote! { #krate::pwqual::glue::make_pwqual_vtable },
    );
    Ok(quote! {
        impl #krate::pwqual::PwqualModule for #struct_name {
            const NAME: &'static ::std::ffi::CStr = <#dt as #krate::pwqual::PwqualModule>::NAME;
            #methods
        }
        #initvt
    })
}

/// Generate all `PwqualModule` methods: `open`, `check`, `close`.
#[cfg(feature = "pwqual")]
fn gen_pwqual_methods(
    f: &syn::Ident,
    dt: &syn::Type,
    args: &PluginArgs,
    kr: &syn::Path,
) -> proc_macro2::TokenStream {
    use quote::quote;
    let open = method_body(
        args,
        "open",
        || {
            quote! {
                fn open(
                    ctx: &#kr::PluginContext<'_>,
                    dict_file: ::std::option::Option<&str>,
                ) -> ::std::result::Result<Self, #kr::pwqual::PwqualError> {
                    <#dt as #kr::pwqual::PwqualModule>::open(ctx, dict_file)
                        .map(|inner| Self { #f: inner })
                }
            }
        },
        || {
            quote! {
                fn open(
                    ctx: &#kr::PluginContext<'_>,
                    dict_file: ::std::option::Option<&str>,
                ) -> ::std::result::Result<Self, #kr::pwqual::PwqualError> {
                    Self::plugin_impl_open(ctx, dict_file)
                }
            }
        },
    );
    let check = method_body(
        args,
        "check",
        || {
            quote! {
                fn check(
                    &self,
                    ctx: &#kr::PluginContext<'_>,
                    req: &#kr::pwqual::CheckRequest<'_>,
                ) -> ::std::result::Result<(), #kr::pwqual::PwqualError> {
                    <#dt as #kr::pwqual::PwqualModule>::check(&self.#f, ctx, req)
                }
            }
        },
        || {
            quote! {
                fn check(
                    &self,
                    ctx: &#kr::PluginContext<'_>,
                    req: &#kr::pwqual::CheckRequest<'_>,
                ) -> ::std::result::Result<(), #kr::pwqual::PwqualError> {
                    self.plugin_impl_check(ctx, req)
                }
            }
        },
    );
    let close = method_body(
        args,
        "close",
        || {
            quote! {
                fn close(self, ctx: &#kr::PluginContext<'_>) {
                    <#dt as #kr::pwqual::PwqualModule>::close(self.#f, ctx)
                }
            }
        },
        || {
            quote! {
                fn close(self, ctx: &#kr::PluginContext<'_>) {
                    self.plugin_impl_close(ctx)
                }
            }
        },
    );
    quote! { #open #check #close }
}

// ---------------------------------------------------------------------------
// #[derive(HostrealmModule)]
// ---------------------------------------------------------------------------

/// Derive `HostrealmModule` for a struct that delegates to a backing field.
///
/// Delegates `init_module`, `fini_module`, `host_realm`, `fallback_realm`,
/// and `default_realm`.
#[cfg(feature = "hostrealm")]
#[proc_macro_derive(HostrealmModule, attributes(plugin))]
pub fn derive_hostrealm_module(
    input: proc_macro::TokenStream,
) -> proc_macro::TokenStream {
    use syn::parse_macro_input;
    let input = parse_macro_input!(input as syn::DeriveInput);
    derive_hostrealm_impl(&input)
        .unwrap_or_else(|e| e.to_compile_error())
        .into()
}

#[cfg(feature = "hostrealm")]
fn derive_hostrealm_impl(
    input: &syn::DeriveInput,
) -> Result<proc_macro2::TokenStream, syn::Error> {
    use quote::quote;
    let attr = find_plugin_attr(input)?;
    let args = parse_plugin_args(attr)?;
    let krate: syn::Path = args
        .krate
        .clone()
        .unwrap_or_else(|| syn::parse_str("::kurbu5_rs").expect("valid path"));
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
    let lifecycle = gen_hostrealm_lifecycle(f, dt, &args, &krate);
    let queries = gen_hostrealm_query_methods(f, dt, &args, &krate);
    let initvt = generate_initvt(
        &args,
        struct_name,
        &krate,
        1i32,
        &quote! { #krate::hostrealm::glue::make_hostrealm_vtable },
    );
    Ok(quote! {
        impl #krate::hostrealm::HostrealmModule for #struct_name {
            const NAME: &'static ::std::ffi::CStr =
                <#dt as #krate::hostrealm::HostrealmModule>::NAME;
            #lifecycle
            #queries
        }
        #initvt
    })
}

/// Generate lifecycle methods for `HostrealmModule`: `init_module`, `fini_module`.
#[cfg(feature = "hostrealm")]
fn gen_hostrealm_lifecycle(
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
                    <#dt as #kr::hostrealm::HostrealmModule>::init_module(ctx)
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
                fn fini_module(self) {
                    <#dt as #kr::hostrealm::HostrealmModule>::fini_module(self.#f)
                }
            }
        },
        || {
            quote! {
                fn fini_module(self) {
                    self.plugin_impl_fini_module()
                }
            }
        },
    );
    quote! { #init_module #fini_module }
}

/// Generate realm query methods for `HostrealmModule`:
/// `host_realm`, `fallback_realm`, `default_realm`.
#[cfg(feature = "hostrealm")]
fn gen_hostrealm_query_methods(
    f: &syn::Ident,
    dt: &syn::Type,
    args: &PluginArgs,
    kr: &syn::Path,
) -> proc_macro2::TokenStream {
    use quote::quote;
    let host_realm = method_body(
        args,
        "host_realm",
        || {
            quote! {
                fn host_realm(
                    &self,
                    ctx: &#kr::PluginContext<'_>,
                    host: &str,
                ) -> ::std::result::Result<::std::vec::Vec<::std::string::String>, #kr::Krb5Error> {
                    <#dt as #kr::hostrealm::HostrealmModule>::host_realm(&self.#f, ctx, host)
                }
            }
        },
        || {
            quote! {
                fn host_realm(
                    &self,
                    ctx: &#kr::PluginContext<'_>,
                    host: &str,
                ) -> ::std::result::Result<::std::vec::Vec<::std::string::String>, #kr::Krb5Error> {
                    self.plugin_impl_host_realm(ctx, host)
                }
            }
        },
    );
    let fallback_realm = method_body(
        args,
        "fallback_realm",
        || {
            quote! {
                fn fallback_realm(
                    &self,
                    ctx: &#kr::PluginContext<'_>,
                    host: &str,
                ) -> ::std::result::Result<::std::vec::Vec<::std::string::String>, #kr::Krb5Error> {
                    <#dt as #kr::hostrealm::HostrealmModule>::fallback_realm(&self.#f, ctx, host)
                }
            }
        },
        || {
            quote! {
                fn fallback_realm(
                    &self,
                    ctx: &#kr::PluginContext<'_>,
                    host: &str,
                ) -> ::std::result::Result<::std::vec::Vec<::std::string::String>, #kr::Krb5Error> {
                    self.plugin_impl_fallback_realm(ctx, host)
                }
            }
        },
    );
    let default_realm = method_body(
        args,
        "default_realm",
        || {
            quote! {
                fn default_realm(
                    &self,
                    ctx: &#kr::PluginContext<'_>,
                ) -> ::std::result::Result<::std::vec::Vec<::std::string::String>, #kr::Krb5Error> {
                    <#dt as #kr::hostrealm::HostrealmModule>::default_realm(&self.#f, ctx)
                }
            }
        },
        || {
            quote! {
                fn default_realm(
                    &self,
                    ctx: &#kr::PluginContext<'_>,
                ) -> ::std::result::Result<::std::vec::Vec<::std::string::String>, #kr::Krb5Error> {
                    self.plugin_impl_default_realm(ctx)
                }
            }
        },
    );
    quote! { #host_realm #fallback_realm #default_realm }
}

// ---------------------------------------------------------------------------
// #[derive(LocalauthModule)]
// ---------------------------------------------------------------------------

/// Derive `LocalauthModule` for a struct that delegates to a backing field.
///
/// Delegates `NAME`, `init_module`, `fini_module`, `userok`, and `an2ln`.
/// `NAME` is inherited from the backing type via
/// `<DelegateType as LocalauthModule>::NAME`.
#[cfg(feature = "localauth")]
#[proc_macro_derive(LocalauthModule, attributes(plugin))]
pub fn derive_localauth_module(
    input: proc_macro::TokenStream,
) -> proc_macro::TokenStream {
    use syn::parse_macro_input;
    let input = parse_macro_input!(input as syn::DeriveInput);
    derive_localauth_impl(&input)
        .unwrap_or_else(|e| e.to_compile_error())
        .into()
}

#[cfg(feature = "localauth")]
fn derive_localauth_impl(
    input: &syn::DeriveInput,
) -> Result<proc_macro2::TokenStream, syn::Error> {
    use quote::quote;
    let attr = find_plugin_attr(input)?;
    let args = parse_plugin_args(attr)?;
    let krate: syn::Path = args
        .krate
        .clone()
        .unwrap_or_else(|| syn::parse_str("::kurbu5_rs").expect("valid path"));

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
    let lifecycle = gen_localauth_lifecycle(f, dt, &args, &krate);
    let operations = gen_localauth_operations(f, dt, &args, &krate);
    let initvt = generate_initvt(
        &args,
        struct_name,
        &krate,
        1i32,
        &quote! { #krate::localauth::glue::make_localauth_vtable },
    );
    Ok(quote! {
        impl #krate::localauth::LocalauthModule for #struct_name {
            const NAME: &'static ::std::ffi::CStr = <#dt as #krate::localauth::LocalauthModule>::NAME;
            #lifecycle
            #operations
        }
        #initvt
    })
}

/// Generate lifecycle methods for `LocalauthModule`: `init_module`, `fini_module`.
#[cfg(feature = "localauth")]
fn gen_localauth_lifecycle(
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
                    <#dt as #kr::localauth::LocalauthModule>::init_module(ctx)
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
                    <#dt as #kr::localauth::LocalauthModule>::fini_module(self.#f, ctx)
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

/// Generate operation methods for `LocalauthModule`: `userok`, `an2ln`.
#[cfg(feature = "localauth")]
fn gen_localauth_operations(
    f: &syn::Ident,
    dt: &syn::Type,
    args: &PluginArgs,
    kr: &syn::Path,
) -> proc_macro2::TokenStream {
    use quote::quote;
    let userok = method_body(
        args,
        "userok",
        || {
            quote! {
                fn userok(
                    &self,
                    ctx: &#kr::PluginContext<'_>,
                    aname: &kurbu5_sys::krb5_principal_data,
                    local_user: &str,
                ) -> ::std::result::Result<(), #kr::Krb5Error> {
                    <#dt as #kr::localauth::LocalauthModule>::userok(&self.#f, ctx, aname, local_user)
                }
            }
        },
        || {
            quote! {
                fn userok(
                    &self,
                    ctx: &#kr::PluginContext<'_>,
                    aname: &kurbu5_sys::krb5_principal_data,
                    local_user: &str,
                ) -> ::std::result::Result<(), #kr::Krb5Error> {
                    self.plugin_impl_userok(ctx, aname, local_user)
                }
            }
        },
    );
    let an2ln = method_body(
        args,
        "an2ln",
        || {
            quote! {
                fn an2ln(
                    &self,
                    ctx: &#kr::PluginContext<'_>,
                    type_: ::std::option::Option<&str>,
                    residual: ::std::option::Option<&str>,
                    aname: &kurbu5_sys::krb5_principal_data,
                ) -> ::std::result::Result<::std::string::String, #kr::Krb5Error> {
                    <#dt as #kr::localauth::LocalauthModule>::an2ln(&self.#f, ctx, type_, residual, aname)
                }
            }
        },
        || {
            quote! {
                fn an2ln(
                    &self,
                    ctx: &#kr::PluginContext<'_>,
                    type_: ::std::option::Option<&str>,
                    residual: ::std::option::Option<&str>,
                    aname: &kurbu5_sys::krb5_principal_data,
                ) -> ::std::result::Result<::std::string::String, #kr::Krb5Error> {
                    self.plugin_impl_an2ln(ctx, type_, residual, aname)
                }
            }
        },
    );
    quote! { #userok #an2ln }
}

// ---------------------------------------------------------------------------
// #[derive(CcselectModule)]
// ---------------------------------------------------------------------------

/// Derive `CcselectModule` for a struct that delegates to a backing field.
///
/// Delegates `NAME`, `init_module`, `priority`, `ccache`, and `fini_module`.
/// `NAME` is a `&'static CStr` inherited from the backing type via
/// `<DelegateType as CcselectModule>::NAME`.
#[cfg(feature = "ccselect")]
#[proc_macro_derive(CcselectModule, attributes(plugin))]
pub fn derive_ccselect_module(
    input: proc_macro::TokenStream,
) -> proc_macro::TokenStream {
    use syn::parse_macro_input;
    let input = parse_macro_input!(input as syn::DeriveInput);
    derive_ccselect_impl(&input)
        .unwrap_or_else(|e| e.to_compile_error())
        .into()
}

#[cfg(feature = "ccselect")]
#[allow(clippy::too_many_lines)]
fn derive_ccselect_impl(
    input: &syn::DeriveInput,
) -> Result<proc_macro2::TokenStream, syn::Error> {
    use quote::quote;
    let attr = find_plugin_attr(input)?;
    let args = parse_plugin_args(attr)?;
    let krate: syn::Path = args
        .krate
        .clone()
        .unwrap_or_else(|| syn::parse_str("::kurbu5_rs").expect("valid path"));

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

    let init_module = method_body(
        &args,
        "init_module",
        || {
            quote! {
                fn init_module() -> ::std::result::Result<Self, #krate::Krb5Error> {
                    <#dt as #krate::ccselect::CcselectModule>::init_module()
                        .map(|inner| Self { #f: inner })
                }
            }
        },
        || {
            quote! {
                fn init_module() -> ::std::result::Result<Self, #krate::Krb5Error> {
                    Self::plugin_impl_init_module()
                }
            }
        },
    );

    let priority = method_body(
        &args,
        "priority",
        || {
            quote! {
                fn priority(&self) -> i32 {
                    <#dt as #krate::ccselect::CcselectModule>::priority(&self.#f)
                }
            }
        },
        || {
            quote! {
                fn priority(&self) -> i32 {
                    self.plugin_impl_priority()
                }
            }
        },
    );

    let ccache = method_body(
        &args,
        "ccache",
        || {
            quote! {
                fn ccache(
                    &self,
                    ctx: &#krate::PluginContext<'_>,
                    server: &kurbu5_sys::krb5_principal_data,
                ) -> ::std::result::Result<#krate::CcacheHandle, #krate::Krb5Error> {
                    <#dt as #krate::ccselect::CcselectModule>::ccache(&self.#f, ctx, server)
                }
            }
        },
        || {
            quote! {
                fn ccache(
                    &self,
                    ctx: &#krate::PluginContext<'_>,
                    server: &kurbu5_sys::krb5_principal_data,
                ) -> ::std::result::Result<#krate::CcacheHandle, #krate::Krb5Error> {
                    self.plugin_impl_ccache(ctx, server)
                }
            }
        },
    );

    let fini_module = method_body(
        &args,
        "fini_module",
        || {
            quote! {
                fn fini_module(&mut self) {
                    <#dt as #krate::ccselect::CcselectModule>::fini_module(&mut self.#f)
                }
            }
        },
        || {
            quote! {
                fn fini_module(&mut self) {
                    self.plugin_impl_fini_module()
                }
            }
        },
    );

    let initvt = generate_initvt(
        &args,
        struct_name,
        &krate,
        1i32,
        &quote! { #krate::ccselect::glue::make_ccselect_vtable },
    );

    Ok(quote! {
        impl #krate::ccselect::CcselectModule for #struct_name {
            const NAME: &'static ::std::ffi::CStr =
                <#dt as #krate::ccselect::CcselectModule>::NAME;
            #init_module
            #priority
            #ccache
            #fini_module
        }
        #initvt
    })
}

// ---------------------------------------------------------------------------
// #[derive(KdcpolicyModule)]
// ---------------------------------------------------------------------------

/// Derive `KdcpolicyModule` for a struct that delegates to a backing field.
///
/// Delegates `init_module`, `fini_module`, `check_as`, and `check_tgs`.
#[cfg(feature = "kdcpolicy")]
#[proc_macro_derive(KdcpolicyModule, attributes(plugin))]
pub fn derive_kdcpolicy_module(
    input: proc_macro::TokenStream,
) -> proc_macro::TokenStream {
    use syn::parse_macro_input;
    let input = parse_macro_input!(input as syn::DeriveInput);
    derive_kdcpolicy_impl(&input)
        .unwrap_or_else(|e| e.to_compile_error())
        .into()
}

#[cfg(feature = "kdcpolicy")]
#[allow(clippy::too_many_lines)]
fn derive_kdcpolicy_impl(
    input: &syn::DeriveInput,
) -> Result<proc_macro2::TokenStream, syn::Error> {
    use quote::quote;
    let attr = find_plugin_attr(input)?;
    let args = parse_plugin_args(attr)?;
    let krate: syn::Path = args
        .krate
        .clone()
        .unwrap_or_else(|| syn::parse_str("::kurbu5_rs").expect("valid path"));

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

    let init_module = method_body(
        &args,
        "init_module",
        || {
            quote! {
                fn init_module(
                    ctx: &#krate::PluginContext<'_>,
                ) -> ::std::result::Result<Self, #krate::Krb5Error> {
                    <#dt as #krate::kdcpolicy::KdcpolicyModule>::init_module(ctx)
                        .map(|inner| Self { #f: inner })
                }
            }
        },
        || {
            quote! {
                fn init_module(
                    ctx: &#krate::PluginContext<'_>,
                ) -> ::std::result::Result<Self, #krate::Krb5Error> {
                    Self::plugin_impl_init_module(ctx)
                }
            }
        },
    );

    let fini_module = method_body(
        &args,
        "fini_module",
        || {
            quote! {
                fn fini_module(self, ctx: &#krate::PluginContext<'_>) -> ::std::result::Result<(), #krate::Krb5Error> {
                    <#dt as #krate::kdcpolicy::KdcpolicyModule>::fini_module(self.#f, ctx)
                }
            }
        },
        || {
            quote! {
                fn fini_module(self, ctx: &#krate::PluginContext<'_>) -> ::std::result::Result<(), #krate::Krb5Error> {
                    self.plugin_impl_fini_module(ctx)
                }
            }
        },
    );

    let check_as = method_body(
        &args,
        "check_as",
        || {
            quote! {
                fn check_as(
                    &self,
                    ctx: &#krate::PluginContext<'_>,
                    req: #krate::kdcpolicy::AsRequest<'_>,
                ) -> ::std::result::Result<(), #krate::kdcpolicy::PolicyError> {
                    <#dt as #krate::kdcpolicy::KdcpolicyModule>::check_as(&self.#f, ctx, req)
                }
            }
        },
        || {
            quote! {
                fn check_as(
                    &self,
                    ctx: &#krate::PluginContext<'_>,
                    req: #krate::kdcpolicy::AsRequest<'_>,
                ) -> ::std::result::Result<(), #krate::kdcpolicy::PolicyError> {
                    self.plugin_impl_check_as(ctx, req)
                }
            }
        },
    );

    let check_tgs = method_body(
        &args,
        "check_tgs",
        || {
            quote! {
                fn check_tgs(
                    &self,
                    ctx: &#krate::PluginContext<'_>,
                    req: #krate::kdcpolicy::TgsRequest<'_>,
                ) -> ::std::result::Result<(), #krate::kdcpolicy::PolicyError> {
                    <#dt as #krate::kdcpolicy::KdcpolicyModule>::check_tgs(&self.#f, ctx, req)
                }
            }
        },
        || {
            quote! {
                fn check_tgs(
                    &self,
                    ctx: &#krate::PluginContext<'_>,
                    req: #krate::kdcpolicy::TgsRequest<'_>,
                ) -> ::std::result::Result<(), #krate::kdcpolicy::PolicyError> {
                    self.plugin_impl_check_tgs(ctx, req)
                }
            }
        },
    );

    let initvt = generate_initvt(
        &args,
        struct_name,
        &krate,
        1i32,
        &quote! { #krate::kdcpolicy::glue::make_kdcpolicy_vtable },
    );

    Ok(quote! {
        impl #krate::kdcpolicy::KdcpolicyModule for #struct_name {
            const NAME: &'static ::std::ffi::CStr =
                <#dt as #krate::kdcpolicy::KdcpolicyModule>::NAME;
            #init_module
            #fini_module
            #check_as
            #check_tgs
        }
        #initvt
    })
}

// ---------------------------------------------------------------------------
// #[derive(CertauthModule)]
// ---------------------------------------------------------------------------

/// Derive `CertauthModule` for a struct that delegates to a backing field.
///
/// Delegates `init_module`, `init_module_ex`, `fini_module`, `authorize`,
/// `notify_pkinit_failure`, and `free_modreq`.
#[cfg(feature = "certauth")]
#[proc_macro_derive(CertauthModule, attributes(plugin))]
pub fn derive_certauth_module(
    input: proc_macro::TokenStream,
) -> proc_macro::TokenStream {
    use syn::parse_macro_input;
    let input = parse_macro_input!(input as syn::DeriveInput);
    derive_certauth_impl(&input)
        .unwrap_or_else(|e| e.to_compile_error())
        .into()
}

#[cfg(feature = "certauth")]
#[allow(clippy::too_many_lines)]
fn derive_certauth_impl(
    input: &syn::DeriveInput,
) -> Result<proc_macro2::TokenStream, syn::Error> {
    use quote::quote;
    let attr = find_plugin_attr(input)?;
    let args = parse_plugin_args(attr)?;
    let krate: syn::Path = args
        .krate
        .clone()
        .unwrap_or_else(|| syn::parse_str("::kurbu5_rs").expect("valid path"));

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

    let init_module = method_body(
        &args,
        "init_module",
        || {
            quote! {
                fn init_module(
                    ctx: &#krate::PluginContext<'_>,
                ) -> ::std::result::Result<Self, #krate::Krb5Error> {
                    <#dt as #krate::certauth::CertauthModule>::init_module(ctx)
                        .map(|inner| Self { #f: inner })
                }
            }
        },
        || {
            quote! {
                fn init_module(
                    ctx: &#krate::PluginContext<'_>,
                ) -> ::std::result::Result<Self, #krate::Krb5Error> {
                    Self::plugin_impl_init_module(ctx)
                }
            }
        },
    );

    let init_module_ex = method_body(
        &args,
        "init_module_ex",
        || {
            quote! {
                fn init_module_ex(
                    ctx: &#krate::PluginContext<'_>,
                    realms: &[&str],
                ) -> ::std::result::Result<Self, #krate::Krb5Error> {
                    <#dt as #krate::certauth::CertauthModule>::init_module_ex(ctx, realms)
                        .map(|inner| Self { #f: inner })
                }
            }
        },
        || {
            quote! {
                fn init_module_ex(
                    ctx: &#krate::PluginContext<'_>,
                    realms: &[&str],
                ) -> ::std::result::Result<Self, #krate::Krb5Error> {
                    Self::plugin_impl_init_module_ex(ctx, realms)
                }
            }
        },
    );

    let fini_module = method_body(
        &args,
        "fini_module",
        || {
            quote! {
                fn fini_module(self) {
                    <#dt as #krate::certauth::CertauthModule>::fini_module(self.#f)
                }
            }
        },
        || {
            quote! {
                fn fini_module(self) {
                    self.plugin_impl_fini_module()
                }
            }
        },
    );

    let authorize = method_body(
        &args,
        "authorize",
        || {
            quote! {
                fn authorize(
                    &self,
                    ctx: &#krate::PluginContext<'_>,
                    cert: #krate::certauth::CertRef<'_>,
                    princ: &kurbu5_sys::krb5_principal_data,
                ) -> ::std::result::Result<#krate::certauth::CertauthDecision, #krate::Krb5Error> {
                    <#dt as #krate::certauth::CertauthModule>::authorize(&self.#f, ctx, cert, princ)
                }
            }
        },
        || {
            quote! {
                fn authorize(
                    &self,
                    ctx: &#krate::PluginContext<'_>,
                    cert: #krate::certauth::CertRef<'_>,
                    princ: &kurbu5_sys::krb5_principal_data,
                ) -> ::std::result::Result<#krate::certauth::CertauthDecision, #krate::Krb5Error> {
                    self.plugin_impl_authorize(ctx, cert, princ)
                }
            }
        },
    );

    let notify_pkinit_failure = method_body(
        &args,
        "notify_pkinit_failure",
        || {
            quote! {
                fn notify_pkinit_failure(
                    &self,
                    ctx: &#krate::PluginContext<'_>,
                    princ: &kurbu5_sys::krb5_principal_data,
                ) {
                    <#dt as #krate::certauth::CertauthModule>::notify_pkinit_failure(
                        &self.#f,
                        ctx,
                        princ,
                    )
                }
            }
        },
        || {
            quote! {
                fn notify_pkinit_failure(
                    &self,
                    ctx: &#krate::PluginContext<'_>,
                    princ: &kurbu5_sys::krb5_principal_data,
                ) {
                    self.plugin_impl_notify_pkinit_failure(ctx, princ)
                }
            }
        },
    );

    let free_modreq = method_body(
        &args,
        "free_modreq",
        || {
            quote! {
                fn free_modreq(&self) {
                    <#dt as #krate::certauth::CertauthModule>::free_modreq(&self.#f)
                }
            }
        },
        || {
            quote! {
                fn free_modreq(&self) {
                    self.plugin_impl_free_modreq()
                }
            }
        },
    );

    let initvt = generate_initvt(
        &args,
        struct_name,
        &krate,
        1i32,
        &quote! { #krate::certauth::glue::make_certauth_vtable },
    );

    Ok(quote! {
        impl #krate::certauth::CertauthModule for #struct_name {
            const NAME: &'static ::std::ffi::CStr =
                <#dt as #krate::certauth::CertauthModule>::NAME;
            #init_module
            #init_module_ex
            #fini_module
            #authorize
            #notify_pkinit_failure
            #free_modreq
        }
        #initvt
    })
}

// ---------------------------------------------------------------------------
// #[derive(KdcpreauthModule)]
// ---------------------------------------------------------------------------

/// Derive `KdcpreauthModule` for a struct that delegates to a backing field.
///
/// Delegates `NAME`, `pa_type_list`, `flags_for_type`, `init_module`,
/// `fini_module`, `get_edata`, `verify`, and `return_padata`.
/// `NAME` is inherited from the backing type via
/// `<DelegateType as KdcpreauthModule>::NAME`.
#[cfg(feature = "kdcpreauth")]
#[proc_macro_derive(KdcpreauthModule, attributes(plugin))]
pub fn derive_kdcpreauth_module(
    input: proc_macro::TokenStream,
) -> proc_macro::TokenStream {
    use syn::parse_macro_input;
    let input = parse_macro_input!(input as syn::DeriveInput);
    derive_kdcpreauth_impl(&input)
        .unwrap_or_else(|e| e.to_compile_error())
        .into()
}

#[cfg(feature = "kdcpreauth")]
#[allow(clippy::too_many_lines)]
fn derive_kdcpreauth_impl(
    input: &syn::DeriveInput,
) -> Result<proc_macro2::TokenStream, syn::Error> {
    use quote::quote;
    let attr = find_plugin_attr(input)?;
    let args = parse_plugin_args(attr)?;
    let krate: syn::Path = args
        .krate
        .clone()
        .unwrap_or_else(|| syn::parse_str("::kurbu5_rs").expect("valid path"));

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

    let pa_type_list = method_body(
        &args,
        "pa_type_list",
        || {
            quote! {
                fn pa_type_list() -> &'static [i32] {
                    <#dt as #krate::kdcpreauth::KdcpreauthModule>::pa_type_list()
                }
            }
        },
        || {
            quote! {
                fn pa_type_list() -> &'static [i32] {
                    Self::plugin_impl_pa_type_list()
                }
            }
        },
    );

    let init_module = method_body(
        &args,
        "init_module",
        || {
            quote! {
                fn init_module(
                    ctx: &#krate::PluginContext<'_>,
                    realmnames: &[&str],
                ) -> ::std::result::Result<Self, #krate::Krb5Error> {
                    <#dt as #krate::kdcpreauth::KdcpreauthModule>::init_module(ctx, realmnames)
                        .map(|inner| Self { #f: inner })
                }
            }
        },
        || {
            quote! {
                fn init_module(
                    ctx: &#krate::PluginContext<'_>,
                    realmnames: &[&str],
                ) -> ::std::result::Result<Self, #krate::Krb5Error> {
                    Self::plugin_impl_init_module(ctx, realmnames)
                }
            }
        },
    );

    let fini_module = method_body(
        &args,
        "fini_module",
        || {
            quote! {
                fn fini_module(self) {
                    <#dt as #krate::kdcpreauth::KdcpreauthModule>::fini_module(self.#f)
                }
            }
        },
        || {
            quote! {
                fn fini_module(self) {
                    self.plugin_impl_fini_module()
                }
            }
        },
    );

    let flags_for_type = method_body(
        &args,
        "flags_for_type",
        || {
            quote! {
                fn flags_for_type(ctx: &#krate::PluginContext<'_>, pa_type: i32) -> i32 {
                    <#dt as #krate::kdcpreauth::KdcpreauthModule>::flags_for_type(ctx, pa_type)
                }
            }
        },
        || {
            quote! {
                fn flags_for_type(ctx: &#krate::PluginContext<'_>, pa_type: i32) -> i32 {
                    Self::plugin_impl_flags_for_type(ctx, pa_type)
                }
            }
        },
    );

    let get_edata = method_body(
        &args,
        "get_edata",
        || {
            quote! {
                fn get_edata(
                    &self,
                    ctx: &#krate::PluginContext<'_>,
                    pa_type: i32,
                    callbacks: &#krate::kdcpreauth::KdcpreauthCallbacks<'_>,
                    respond: ::std::boxed::Box<dyn ::std::ops::FnOnce(::std::result::Result<::std::option::Option<#krate::kdcpreauth::PaData>, #krate::Krb5Error>)>,
                ) {
                    <#dt as #krate::kdcpreauth::KdcpreauthModule>::get_edata(
                        &self.#f,
                        ctx,
                        pa_type,
                        callbacks,
                        respond,
                    )
                }
            }
        },
        || {
            quote! {
                fn get_edata(
                    &self,
                    ctx: &#krate::PluginContext<'_>,
                    pa_type: i32,
                    callbacks: &#krate::kdcpreauth::KdcpreauthCallbacks<'_>,
                    respond: ::std::boxed::Box<dyn ::std::ops::FnOnce(::std::result::Result<::std::option::Option<#krate::kdcpreauth::PaData>, #krate::Krb5Error>)>,
                ) {
                    self.plugin_impl_get_edata(ctx, pa_type, callbacks, respond)
                }
            }
        },
    );

    let verify = method_body(
        &args,
        "verify",
        || {
            quote! {
                fn verify(
                    &self,
                    ctx: &#krate::PluginContext<'_>,
                    pa_data: &#krate::kdcpreauth::PaData,
                    callbacks: &#krate::kdcpreauth::KdcpreauthCallbacks<'_>,
                    respond: ::std::boxed::Box<dyn ::std::ops::FnOnce(#krate::kdcpreauth::VerifyResponse)>,
                ) {
                    <#dt as #krate::kdcpreauth::KdcpreauthModule>::verify(
                        &self.#f,
                        ctx,
                        pa_data,
                        callbacks,
                        respond,
                    )
                }
            }
        },
        || {
            quote! {
                fn verify(
                    &self,
                    ctx: &#krate::PluginContext<'_>,
                    pa_data: &#krate::kdcpreauth::PaData,
                    callbacks: &#krate::kdcpreauth::KdcpreauthCallbacks<'_>,
                    respond: ::std::boxed::Box<dyn ::std::ops::FnOnce(#krate::kdcpreauth::VerifyResponse)>,
                ) {
                    self.plugin_impl_verify(ctx, pa_data, callbacks, respond)
                }
            }
        },
    );

    let return_padata = method_body(
        &args,
        "return_padata",
        || {
            quote! {
                fn return_padata(
                    &self,
                    ctx: &#krate::PluginContext<'_>,
                    req: #krate::kdcpreauth::ReturnPadataRequest<'_>,
                    callbacks: &#krate::kdcpreauth::KdcpreauthCallbacks<'_>,
                ) -> ::std::result::Result<::std::option::Option<#krate::kdcpreauth::PaData>, #krate::Krb5Error> {
                    <#dt as #krate::kdcpreauth::KdcpreauthModule>::return_padata(
                        &self.#f,
                        ctx,
                        req,
                        callbacks,
                    )
                }
            }
        },
        || {
            quote! {
                fn return_padata(
                    &self,
                    ctx: &#krate::PluginContext<'_>,
                    req: #krate::kdcpreauth::ReturnPadataRequest<'_>,
                    callbacks: &#krate::kdcpreauth::KdcpreauthCallbacks<'_>,
                ) -> ::std::result::Result<::std::option::Option<#krate::kdcpreauth::PaData>, #krate::Krb5Error> {
                    self.plugin_impl_return_padata(ctx, req, callbacks)
                }
            }
        },
    );

    let initvt = generate_initvt(
        &args,
        struct_name,
        &krate,
        1i32,
        &quote! { #krate::kdcpreauth::glue::make_kdcpreauth_vtable },
    );

    Ok(quote! {
        impl #krate::kdcpreauth::KdcpreauthModule for #struct_name {
            const NAME: &'static ::std::ffi::CStr =
                <#dt as #krate::kdcpreauth::KdcpreauthModule>::NAME;
            #pa_type_list
            #init_module
            #fini_module
            #flags_for_type
            #get_edata
            #verify
            #return_padata
        }
        #initvt
    })
}

// ---------------------------------------------------------------------------
// #[derive(ClpreauthModule)]
// ---------------------------------------------------------------------------

/// Derive `ClpreauthModule` for a struct that delegates to a backing field.
///
/// Delegates `NAME`, `pa_type_list`, `flags`, `init_module`, `fini_module`,
/// `init_etype_info`, `process`, `tryagain`, `enctype_list`, and `free_modreq`.
/// `NAME` is inherited from the backing type via
/// `<DelegateType as ClpreauthModule>::NAME`.
#[cfg(feature = "clpreauth")]
#[proc_macro_derive(ClpreauthModule, attributes(plugin))]
pub fn derive_clpreauth_module(
    input: proc_macro::TokenStream,
) -> proc_macro::TokenStream {
    use syn::parse_macro_input;
    let input = parse_macro_input!(input as syn::DeriveInput);
    derive_clpreauth_impl(&input)
        .unwrap_or_else(|e| e.to_compile_error())
        .into()
}

#[cfg(feature = "clpreauth")]
#[allow(clippy::too_many_lines)]
fn derive_clpreauth_impl(
    input: &syn::DeriveInput,
) -> Result<proc_macro2::TokenStream, syn::Error> {
    use quote::quote;
    let attr = find_plugin_attr(input)?;
    let args = parse_plugin_args(attr)?;
    let krate: syn::Path = args
        .krate
        .clone()
        .unwrap_or_else(|| syn::parse_str("::kurbu5_rs").expect("valid path"));

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

    let pa_type_list = method_body(
        &args,
        "pa_type_list",
        || {
            quote! {
                fn pa_type_list() -> &'static [i32] {
                    <#dt as #krate::clpreauth::ClpreauthModule>::pa_type_list()
                }
            }
        },
        || {
            quote! {
                fn pa_type_list() -> &'static [i32] {
                    Self::plugin_impl_pa_type_list()
                }
            }
        },
    );

    let init_module = method_body(
        &args,
        "init_module",
        || {
            quote! {
                fn init_module(
                    ctx: &#krate::PluginContext<'_>,
                ) -> ::std::result::Result<Self, #krate::Krb5Error> {
                    <#dt as #krate::clpreauth::ClpreauthModule>::init_module(ctx)
                        .map(|inner| Self { #f: inner })
                }
            }
        },
        || {
            quote! {
                fn init_module(
                    ctx: &#krate::PluginContext<'_>,
                ) -> ::std::result::Result<Self, #krate::Krb5Error> {
                    Self::plugin_impl_init_module(ctx)
                }
            }
        },
    );

    let fini_module = method_body(
        &args,
        "fini_module",
        || {
            quote! {
                fn fini_module(self) {
                    <#dt as #krate::clpreauth::ClpreauthModule>::fini_module(self.#f)
                }
            }
        },
        || {
            quote! {
                fn fini_module(self) {
                    self.plugin_impl_fini_module()
                }
            }
        },
    );

    let flags = method_body(
        &args,
        "flags",
        || {
            quote! {
                fn flags(ctx: &#krate::PluginContext<'_>, pa_type: i32) -> i32 {
                    <#dt as #krate::clpreauth::ClpreauthModule>::flags(ctx, pa_type)
                }
            }
        },
        || {
            quote! {
                fn flags(ctx: &#krate::PluginContext<'_>, pa_type: i32) -> i32 {
                    Self::plugin_impl_flags(ctx, pa_type)
                }
            }
        },
    );

    let init_etype_info = method_body(
        &args,
        "init_etype_info",
        || {
            quote! {
                fn init_etype_info(
                    &mut self,
                    ctx: &#krate::PluginContext<'_>,
                    callbacks: &mut #krate::clpreauth::ClpreauthCallbacks<'_>,
                    req: &#krate::clpreauth::EtypeInfoRequest<'_>,
                ) -> ::std::result::Result<(), #krate::Krb5Error> {
                    <#dt as #krate::clpreauth::ClpreauthModule>::init_etype_info(
                        &mut self.#f,
                        ctx,
                        callbacks,
                        req,
                    )
                }
            }
        },
        || {
            quote! {
                fn init_etype_info(
                    &mut self,
                    ctx: &#krate::PluginContext<'_>,
                    callbacks: &mut #krate::clpreauth::ClpreauthCallbacks<'_>,
                    req: &#krate::clpreauth::EtypeInfoRequest<'_>,
                ) -> ::std::result::Result<(), #krate::Krb5Error> {
                    self.plugin_impl_init_etype_info(ctx, callbacks, req)
                }
            }
        },
    );

    let process = method_body(
        &args,
        "process",
        || {
            quote! {
                fn process(
                    &mut self,
                    ctx: &#krate::PluginContext<'_>,
                    callbacks: &mut #krate::clpreauth::ClpreauthCallbacks<'_>,
                    req: &#krate::clpreauth::ProcessRequest<'_>,
                ) -> ::std::result::Result<::std::vec::Vec<#krate::clpreauth::PaData>, #krate::Krb5Error> {
                    <#dt as #krate::clpreauth::ClpreauthModule>::process(
                        &mut self.#f,
                        ctx,
                        callbacks,
                        req,
                    )
                }
            }
        },
        || {
            quote! {
                fn process(
                    &mut self,
                    ctx: &#krate::PluginContext<'_>,
                    callbacks: &mut #krate::clpreauth::ClpreauthCallbacks<'_>,
                    req: &#krate::clpreauth::ProcessRequest<'_>,
                ) -> ::std::result::Result<::std::vec::Vec<#krate::clpreauth::PaData>, #krate::Krb5Error> {
                    self.plugin_impl_process(ctx, callbacks, req)
                }
            }
        },
    );

    let tryagain = method_body(
        &args,
        "tryagain",
        || {
            quote! {
                fn tryagain(
                    &mut self,
                    ctx: &#krate::PluginContext<'_>,
                    callbacks: &mut #krate::clpreauth::ClpreauthCallbacks<'_>,
                    req: &#krate::clpreauth::TryagainRequest<'_>,
                ) -> ::std::result::Result<::std::vec::Vec<#krate::clpreauth::PaData>, #krate::Krb5Error> {
                    <#dt as #krate::clpreauth::ClpreauthModule>::tryagain(
                        &mut self.#f,
                        ctx,
                        callbacks,
                        req,
                    )
                }
            }
        },
        || {
            quote! {
                fn tryagain(
                    &mut self,
                    ctx: &#krate::PluginContext<'_>,
                    callbacks: &mut #krate::clpreauth::ClpreauthCallbacks<'_>,
                    req: &#krate::clpreauth::TryagainRequest<'_>,
                ) -> ::std::result::Result<::std::vec::Vec<#krate::clpreauth::PaData>, #krate::Krb5Error> {
                    self.plugin_impl_tryagain(ctx, callbacks, req)
                }
            }
        },
    );

    let enctype_list = method_body(
        &args,
        "enctype_list",
        || {
            quote! {
                fn enctype_list() -> ::std::option::Option<&'static [i32]> {
                    <#dt as #krate::clpreauth::ClpreauthModule>::enctype_list()
                }
            }
        },
        || {
            quote! {
                fn enctype_list() -> ::std::option::Option<&'static [i32]> {
                    Self::plugin_impl_enctype_list()
                }
            }
        },
    );

    let free_modreq = method_body(
        &args,
        "free_modreq",
        || {
            quote! {
                fn free_modreq(&mut self) {
                    <#dt as #krate::clpreauth::ClpreauthModule>::free_modreq(&mut self.#f)
                }
            }
        },
        || {
            quote! {
                fn free_modreq(&mut self) {
                    self.plugin_impl_free_modreq()
                }
            }
        },
    );

    let initvt = generate_initvt(
        &args,
        struct_name,
        &krate,
        1i32,
        &quote! { #krate::clpreauth::glue::make_clpreauth_vtable },
    );

    Ok(quote! {
        impl #krate::clpreauth::ClpreauthModule for #struct_name {
            const NAME: &'static ::std::ffi::CStr =
                <#dt as #krate::clpreauth::ClpreauthModule>::NAME;
            #pa_type_list
            #init_module
            #fini_module
            #flags
            #init_etype_info
            #process
            #tryagain
            #enctype_list
            #free_modreq
        }
        #initvt
    })
}

// ---------------------------------------------------------------------------
// #[derive(AuditModule)]
// ---------------------------------------------------------------------------

/// Derive `AuditModule` for a struct that delegates to a backing field.
///
/// Delegates `NAME`, `open`, `close`, `kdc_start`, `kdc_stop`, `as_req`,
/// `tgs_req`, `tgs_s4u2self`, `tgs_s4u2proxy`, and `tgs_u2u`.  `NAME` is
/// inherited from the backing type via `<DelegateType as AuditModule>::NAME`.
///
/// Unlike other interfaces, `open` does not receive a `krb5_context`.  The
/// generated delegation calls `<DelegateType as AuditModule>::open()` with no
/// arguments and wraps the result in the outer struct.
///
/// # Compile errors
///
/// Missing `#[plugin(...)]` attribute — the derive requires it:
///
/// ```compile_fail
/// use kurbu5_rs::audit::AuditModule;
/// use kurbu5_rs::Krb5Error;
/// struct Inner;
/// impl AuditModule for Inner {
///     const NAME: &'static std::ffi::CStr = c"inner";
///     fn open() -> Result<Self, Krb5Error> { Ok(Inner) }
/// }
/// #[derive(kurbu5_rs::AuditModule)]
/// struct Wrapper { inner: Inner }
/// ```
///
/// Delegate field name does not exist on the struct:
///
/// ```compile_fail
/// use kurbu5_rs::audit::AuditModule;
/// use kurbu5_rs::Krb5Error;
/// struct Inner;
/// impl AuditModule for Inner {
///     const NAME: &'static std::ffi::CStr = c"inner";
///     fn open() -> Result<Self, Krb5Error> { Ok(Inner) }
/// }
/// #[derive(kurbu5_rs::AuditModule)]
/// #[plugin(delegate = no_such_field)]
/// struct Wrapper { inner: Inner }
/// ```
#[cfg(feature = "audit")]
#[proc_macro_derive(AuditModule, attributes(plugin))]
pub fn derive_audit_module(
    input: proc_macro::TokenStream,
) -> proc_macro::TokenStream {
    use syn::parse_macro_input;
    let input = parse_macro_input!(input as syn::DeriveInput);
    derive_audit_impl(&input)
        .unwrap_or_else(|e| e.to_compile_error())
        .into()
}

#[cfg(feature = "audit")]
#[allow(clippy::too_many_lines)]
fn derive_audit_impl(
    input: &syn::DeriveInput,
) -> Result<proc_macro2::TokenStream, syn::Error> {
    use quote::quote;
    let attr = find_plugin_attr(input)?;
    let args = parse_plugin_args(attr)?;
    let krate: syn::Path = args
        .krate
        .clone()
        .unwrap_or_else(|| syn::parse_str("::kurbu5_rs").expect("valid path"));

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

    let open = method_body(
        &args,
        "open",
        || {
            quote! {
                fn open() -> ::std::result::Result<Self, #krate::Krb5Error> {
                    <#dt as #krate::audit::AuditModule>::open()
                        .map(|inner| Self { #f: inner })
                }
            }
        },
        || {
            quote! {
                fn open() -> ::std::result::Result<Self, #krate::Krb5Error> {
                    Self::plugin_impl_open()
                }
            }
        },
    );

    let close = method_body(
        &args,
        "close",
        || {
            quote! {
                fn close(self) -> ::std::result::Result<(), #krate::Krb5Error> {
                    <#dt as #krate::audit::AuditModule>::close(self.#f)
                }
            }
        },
        || {
            quote! {
                fn close(self) -> ::std::result::Result<(), #krate::Krb5Error> {
                    self.plugin_impl_close()
                }
            }
        },
    );

    let kdc_start = method_body(
        &args,
        "kdc_start",
        || {
            quote! {
                fn kdc_start(&self, success: bool) -> ::std::result::Result<(), #krate::Krb5Error> {
                    <#dt as #krate::audit::AuditModule>::kdc_start(&self.#f, success)
                }
            }
        },
        || {
            quote! {
                fn kdc_start(&self, success: bool) -> ::std::result::Result<(), #krate::Krb5Error> {
                    self.plugin_impl_kdc_start(success)
                }
            }
        },
    );

    let kdc_stop = method_body(
        &args,
        "kdc_stop",
        || {
            quote! {
                fn kdc_stop(&self, success: bool) -> ::std::result::Result<(), #krate::Krb5Error> {
                    <#dt as #krate::audit::AuditModule>::kdc_stop(&self.#f, success)
                }
            }
        },
        || {
            quote! {
                fn kdc_stop(&self, success: bool) -> ::std::result::Result<(), #krate::Krb5Error> {
                    self.plugin_impl_kdc_stop(success)
                }
            }
        },
    );

    let as_req = method_body(
        &args,
        "as_req",
        || {
            quote! {
                fn as_req(
                    &self,
                    success: bool,
                    state: #krate::audit::AuditStateRef<'_>,
                ) -> ::std::result::Result<(), #krate::Krb5Error> {
                    <#dt as #krate::audit::AuditModule>::as_req(&self.#f, success, state)
                }
            }
        },
        || {
            quote! {
                fn as_req(
                    &self,
                    success: bool,
                    state: #krate::audit::AuditStateRef<'_>,
                ) -> ::std::result::Result<(), #krate::Krb5Error> {
                    self.plugin_impl_as_req(success, state)
                }
            }
        },
    );

    let tgs_req = method_body(
        &args,
        "tgs_req",
        || {
            quote! {
                fn tgs_req(
                    &self,
                    success: bool,
                    state: #krate::audit::AuditStateRef<'_>,
                ) -> ::std::result::Result<(), #krate::Krb5Error> {
                    <#dt as #krate::audit::AuditModule>::tgs_req(&self.#f, success, state)
                }
            }
        },
        || {
            quote! {
                fn tgs_req(
                    &self,
                    success: bool,
                    state: #krate::audit::AuditStateRef<'_>,
                ) -> ::std::result::Result<(), #krate::Krb5Error> {
                    self.plugin_impl_tgs_req(success, state)
                }
            }
        },
    );

    let tgs_s4u2self = method_body(
        &args,
        "tgs_s4u2self",
        || {
            quote! {
                fn tgs_s4u2self(
                    &self,
                    success: bool,
                    state: #krate::audit::AuditStateRef<'_>,
                ) -> ::std::result::Result<(), #krate::Krb5Error> {
                    <#dt as #krate::audit::AuditModule>::tgs_s4u2self(&self.#f, success, state)
                }
            }
        },
        || {
            quote! {
                fn tgs_s4u2self(
                    &self,
                    success: bool,
                    state: #krate::audit::AuditStateRef<'_>,
                ) -> ::std::result::Result<(), #krate::Krb5Error> {
                    self.plugin_impl_tgs_s4u2self(success, state)
                }
            }
        },
    );

    let tgs_s4u2proxy = method_body(
        &args,
        "tgs_s4u2proxy",
        || {
            quote! {
                fn tgs_s4u2proxy(
                    &self,
                    success: bool,
                    state: #krate::audit::AuditStateRef<'_>,
                ) -> ::std::result::Result<(), #krate::Krb5Error> {
                    <#dt as #krate::audit::AuditModule>::tgs_s4u2proxy(&self.#f, success, state)
                }
            }
        },
        || {
            quote! {
                fn tgs_s4u2proxy(
                    &self,
                    success: bool,
                    state: #krate::audit::AuditStateRef<'_>,
                ) -> ::std::result::Result<(), #krate::Krb5Error> {
                    self.plugin_impl_tgs_s4u2proxy(success, state)
                }
            }
        },
    );

    let tgs_u2u = method_body(
        &args,
        "tgs_u2u",
        || {
            quote! {
                fn tgs_u2u(
                    &self,
                    success: bool,
                    state: #krate::audit::AuditStateRef<'_>,
                ) -> ::std::result::Result<(), #krate::Krb5Error> {
                    <#dt as #krate::audit::AuditModule>::tgs_u2u(&self.#f, success, state)
                }
            }
        },
        || {
            quote! {
                fn tgs_u2u(
                    &self,
                    success: bool,
                    state: #krate::audit::AuditStateRef<'_>,
                ) -> ::std::result::Result<(), #krate::Krb5Error> {
                    self.plugin_impl_tgs_u2u(success, state)
                }
            }
        },
    );

    let initvt = generate_initvt(
        &args,
        struct_name,
        &krate,
        1i32,
        &quote! { #krate::audit::glue::make_audit_vtable },
    );

    Ok(quote! {
        impl #krate::audit::AuditModule for #struct_name {
            const NAME: &'static ::std::ffi::CStr =
                <#dt as #krate::audit::AuditModule>::NAME;
            #open
            #close
            #kdc_start
            #kdc_stop
            #as_req
            #tgs_req
            #tgs_s4u2self
            #tgs_s4u2proxy
            #tgs_u2u
        }
        #initvt
    })
}
