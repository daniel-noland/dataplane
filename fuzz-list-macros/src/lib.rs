// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

//! Proc macros for fuzz test registration.
//!
//! See [`fuzz_list`] crate documentation for usage.

use proc_macro::TokenStream;
use quote::quote;
use syn::parse::{Parse, ParseStream};
use syn::{Ident, ItemFn, LitInt, Token, parse_macro_input};

/// Known sanitizer names.
const KNOWN_SANITIZERS: &[&str] = &["address", "thread"];

// -- sanitizer parsing -------------------------------------------------------

struct SanitizerList {
    names: Vec<Ident>,
}

impl Parse for SanitizerList {
    fn parse(input: ParseStream) -> syn::Result<Self> {
        let mut names = Vec::new();
        names.push(input.parse::<Ident>()?);
        // Consume comma-separated idents, stopping at EOF or a non-ident after comma
        // (which would be the start of the next key like `jobs`).
        while input.peek(Token![,]) && input.peek2(Ident) {
            // Peek ahead: if the ident after the comma is a known key, stop.
            let fork = input.fork();
            fork.parse::<Token![,]>()?;
            let next_ident: Ident = fork.parse()?;
            if is_known_key(&next_ident.to_string()) {
                break;
            }
            // It's a sanitizer name -- consume the comma and ident for real.
            input.parse::<Token![,]>()?;
            names.push(input.parse::<Ident>()?);
        }
        for name in &names {
            if !KNOWN_SANITIZERS.contains(&name.to_string().as_str()) {
                return Err(syn::Error::new(
                    name.span(),
                    format!(
                        "unknown sanitizer `{name}`, expected one of: {}",
                        KNOWN_SANITIZERS.join(", ")
                    ),
                ));
            }
        }
        Ok(SanitizerList { names })
    }
}

enum SanitizerOp {
    Add(SanitizerList),
    Remove(SanitizerList),
    Exact(SanitizerList),
}

fn parse_sanitizer_op(input: ParseStream) -> syn::Result<SanitizerOp> {
    if input.peek(Token![+=]) {
        input.parse::<Token![+=]>()?;
        Ok(SanitizerOp::Add(input.parse()?))
    } else if input.peek(Token![-=]) {
        input.parse::<Token![-=]>()?;
        Ok(SanitizerOp::Remove(input.parse()?))
    } else if input.peek(Token![=]) {
        input.parse::<Token![=]>()?;
        Ok(SanitizerOp::Exact(input.parse()?))
    } else {
        Err(input.error("expected `+=`, `-=`, or `=` after `sanitizers`"))
    }
}

// -- top-level argument parsing ----------------------------------------------

/// All known top-level keys in `#[fuzz(...)]`.
fn is_known_key(s: &str) -> bool {
    matches!(s, "sanitizers" | "jobs" | "timeout")
}

struct FuzzArgs {
    sanitizers: Option<SanitizerOp>,
    jobs: Option<LitInt>,
    timeout: Option<LitInt>,
}

impl Parse for FuzzArgs {
    fn parse(input: ParseStream) -> syn::Result<Self> {
        let mut args = FuzzArgs {
            sanitizers: None,
            jobs: None,
            timeout: None,
        };

        if input.is_empty() {
            return Ok(args);
        }

        loop {
            let key: Ident = input.parse()?;
            match key.to_string().as_str() {
                "sanitizers" => {
                    if args.sanitizers.is_some() {
                        return Err(syn::Error::new(key.span(), "duplicate `sanitizers` key"));
                    }
                    args.sanitizers = Some(parse_sanitizer_op(input)?);
                }
                "jobs" => {
                    if args.jobs.is_some() {
                        return Err(syn::Error::new(key.span(), "duplicate `jobs` key"));
                    }
                    input.parse::<Token![=]>()?;
                    args.jobs = Some(input.parse()?);
                }
                "timeout" => {
                    if args.timeout.is_some() {
                        return Err(syn::Error::new(key.span(), "duplicate `timeout` key"));
                    }
                    input.parse::<Token![=]>()?;
                    args.timeout = Some(input.parse()?);
                }
                other => {
                    return Err(syn::Error::new(
                        key.span(),
                        format!(
                            "unknown key `{other}`, expected one of: sanitizers, jobs, timeout"
                        ),
                    ));
                }
            }

            // Consume separator comma if present
            if input.peek(Token![,]) {
                input.parse::<Token![,]>()?;
                if input.is_empty() {
                    break; // trailing comma
                }
            } else {
                break;
            }
        }

        Ok(args)
    }
}

// -- code generation ---------------------------------------------------------

fn sanitize_expr(op: &Option<SanitizerOp>) -> proc_macro2::TokenStream {
    match op {
        None => quote! { ::fuzz_list::Sanitize::defaults() },
        Some(op) => {
            let base = match op {
                SanitizerOp::Exact(_) => quote! { ::fuzz_list::Sanitize::none() },
                SanitizerOp::Add(_) | SanitizerOp::Remove(_) => {
                    quote! { ::fuzz_list::Sanitize::defaults() }
                }
            };

            let modifiers: Vec<_> = match op {
                SanitizerOp::Add(list) | SanitizerOp::Exact(list) => list
                    .names
                    .iter()
                    .map(|name| {
                        let method = quote::format_ident!("with_{name}");
                        quote! { .#method(true) }
                    })
                    .collect(),
                SanitizerOp::Remove(list) => list
                    .names
                    .iter()
                    .map(|name| {
                        let method = quote::format_ident!("with_{name}");
                        quote! { .#method(false) }
                    })
                    .collect(),
            };

            quote! { #base #(#modifiers)* }
        }
    }
}

/// Register a function as a bolero fuzz test.
///
/// This attribute does two things:
///
/// 1. Emits a [`linkme::distributed_slice`] registration at module scope (in an anonymous const
///    block) so the test is discoverable by the fuzz harness even in non-test builds (e.g.,
///    integration test binaries with `harness = false`).
///
/// 2. Preserves the original function with all its attributes (including `#[test]`).
///
/// # Usage
///
/// ```ignore
/// use fuzz_list::fuzz;
///
/// // All defaults:
/// #[fuzz]
/// #[test]
/// fn simple_test() { /* ... */ }
///
/// // Sanitizer control:
/// #[fuzz(sanitizers += thread)]
/// #[fuzz(sanitizers -= address)]
/// #[fuzz(sanitizers = thread)]
///
/// // Resource hints for the CI supervisor:
/// #[fuzz(jobs = 4)]                    // request 4 parallel fuzzer jobs
/// #[fuzz(timeout = 60)]                // request 60 seconds (default: 5)
///
/// // Combined:
/// #[fuzz(sanitizers += thread, jobs = 8, timeout = 300)]
/// #[test]
/// fn complex_test() { /* ... */ }
/// ```
#[proc_macro_attribute]
pub fn fuzz(attr: TokenStream, item: TokenStream) -> TokenStream {
    let args = parse_macro_input!(attr as FuzzArgs);
    let func = parse_macro_input!(item as ItemFn);

    let func_name_str = func.sig.ident.to_string();
    let sanitize = sanitize_expr(&args.sanitizers);

    let jobs = args
        .jobs
        .as_ref()
        .map_or(quote! { 1 }, |lit| quote! { #lit });
    let timeout = args
        .timeout
        .as_ref()
        .map_or(quote! { 5 }, |lit| quote! { #lit });

    let output = quote! {
        const _: () = {
            #[::fuzz_list::distributed_slice(::fuzz_list::TESTS)]
            static __FUZZ_ENTRY: ::fuzz_list::Test = ::fuzz_list::Test::new(
                concat!(module_path!(), "::", #func_name_str),
                #sanitize,
                #jobs,
                #timeout,
            );
        };

        #func
    };

    output.into()
}
