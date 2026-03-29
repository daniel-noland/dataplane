// SPDX-License-Identifier: Apache-2.0
// Copyright Open Network Fabric Authors

#![warn(missing_docs)]

//! Proc macro crate for the `n-vm` test infrastructure.
//!
//! This crate provides the [`in_vm`] attribute macro, which rewrites a test
//! function so that it transparently runs inside an ephemeral virtual machine.
//!
//! # Architecture
//!
//! The `#[in_vm]` macro implements a three-tier dispatch based on environment
//! variables (defined in `n_vm_protocol` and re-exported from `n_vm`):
//!
//! 1. **Host** (no env vars set) -- the default when `cargo test` is invoked.
//!    Delegates to [`n_vm::dispatch::run_host_tier`] which launches a Docker
//!    container with the required devices and capabilities, then re-executes
//!    the same test binary inside it.
//!
//! 2. **Container** (`IN_TEST_CONTAINER=YES`) -- inside the Docker container.
//!    Delegates to [`n_vm::dispatch::run_container_tier`] which boots a
//!    cloud-hypervisor VM, shares the test binary into the guest via
//!    virtiofs, and re-executes the test inside the VM.
//!
//! 3. **VM guest** (`IN_VM=YES`) -- inside the virtual machine, running under
//!    the `n-it` init system.  The original test body executes directly.
//!
//! All runtime policy (tokio runtime construction, tracing configuration,
//! error formatting, exit-code interpretation) lives in the
//! [`n_vm::dispatch`] module rather than in `quote!` output, so that
//! changes do not require proc-macro recompilation and the logic is
//! testable and debuggable as normal Rust code.
//!
//! # Usage
//!
//! ```ignore
//! use n_vm::in_vm;
//!
//! #[test]
//! #[in_vm]
//! fn my_test() {
//!     // This body runs inside an ephemeral VM.
//!     assert!(std::path::Path::new("/proc").exists());
//! }
//! ```
//!
//! The decorated function must be a synchronous `fn()` with no parameters and
//! no return value.

extern crate proc_macro;

use proc_macro::TokenStream;
use quote::quote;
use syn::{ReturnType, parse_macro_input};

/// Attribute macro that rewrites a test function to run inside an ephemeral VM.
///
/// See the [crate-level documentation](crate) for a full description of the
/// three-tier dispatch mechanism and usage examples.
///
/// # Compile-time validation
///
/// The macro rejects functions that are:
/// - **`async`** -- the generated code creates its own tokio runtime at the
///   container tier, so the decorated function must be synchronous.
/// - **Parameterised** -- the function is re-invoked by name as `fn()` inside
///   the VM guest, so it cannot accept arguments.
/// - **Non-unit return type** -- the generated dispatch branches use bare
///   `return;` statements, so the function must return `()`.
///
/// # Panics
///
/// The generated code panics if:
/// - The Docker container exits with a non-zero code (host tier).
/// - The VM test output indicates failure (container tier).
/// - The tokio runtime cannot be created.
#[proc_macro_attribute]
pub fn in_vm(attr: TokenStream, input: TokenStream) -> TokenStream {
    if !attr.is_empty() {
        return syn::Error::new(
            proc_macro2::Span::call_site(),
            "#[in_vm] does not accept any arguments",
        )
        .to_compile_error()
        .into();
    }

    let func = parse_macro_input!(input as syn::ItemFn);

    // ── Validate function signature ──────────────────────────────────

    if func.sig.asyncness.is_some() {
        return syn::Error::new_spanned(
            func.sig.asyncness,
            "#[in_vm] cannot be applied to async functions; \
             the generated code creates its own tokio runtime at the container tier",
        )
        .to_compile_error()
        .into();
    }

    if !func.sig.inputs.is_empty() {
        return syn::Error::new_spanned(
            &func.sig.inputs,
            "#[in_vm] functions must take no parameters; \
             the function is re-invoked by name as `fn()` inside the VM guest",
        )
        .to_compile_error()
        .into();
    }

    if !matches!(func.sig.output, ReturnType::Default) {
        return syn::Error::new_spanned(
            &func.sig.output,
            "#[in_vm] functions must return `()`; \
             the generated dispatch branches use bare `return;` statements",
        )
        .to_compile_error()
        .into();
    }

    // ── Code generation ──────────────────────────────────────────────

    let block = &func.block;
    let vis = &func.vis;
    let sig = &func.sig;
    let attrs = &func.attrs;
    let ident = &func.sig.ident;

    // The three tiers are dispatched as a flat if / else-if / else chain.
    // Each tier is identified by an environment variable set by the
    // enclosing layer before re-executing the test binary.
    //
    // Only Tier 3 (the VM guest) runs the original test body and must
    // therefore be generated inline.  Tiers 1 and 2 delegate to helper
    // functions in `n_vm::dispatch` so that all runtime policy lives in
    // normal, testable Rust code rather than in macro output.
    quote! {
        #(#attrs)*
        #vis #sig {
            // ── Tier 3: VM guest ─────────────────────────────────────
            if ::n_vm::is_in_vm() {
                { #block }
                return;
            }

            // ── Tier 2: Docker container -> VM ───────────────────────
            if ::n_vm::is_in_test_container() {
                ::n_vm::run_container_tier(#ident);
                return;
            }

            // ── Tier 1: Host -> Docker container ─────────────────────
            ::n_vm::run_host_tier(#ident);
        }
    }
    .into()
}